//! Simulated world, abstract operations and the `proptest` generator. Operations are selectors
//! resolved against the current state, so traces stay realistic (claims on real slices, acks on the
//! live attempt) while still including adversarial ones (stale attempts, wrong lender, duplicates,
//! concurrent versions, receipt bursts).

use std::sync::Arc;

use gpu_domain::*;
use gpu_ledger::{LedgerLimits, LedgerService};
use more_identity::{
    assume_account, lease_message, mandate_message, ready_message, receipt_message, relay_message,
    restore_message, Assignment, IdentityAuthority, JobTerms, KeyDirectory, Restoration,
    ServiceRole, UserKey,
};

use crate::invariants::{check_state, check_step, Violation};

mod adversarial;
mod composite;
mod identity;
mod operations;
mod resolve;
mod setup;

pub use identity::{
    assignment_of, restoration_of, state_commitment, SimIdentity, SEGMENTS, UNSET_CONFIG,
    UNSET_STATE, UNSIGNED,
};
pub use operations::{op_strategy, Op};
use operations::{pick, wt_of};
pub use setup::*;

/// Simulation: coordinator state, history, violations found.
pub struct Sim {
    pub coord: Coordinator,
    pub ids: Arc<SimIdentity>,
    pub history: Vec<Command>,
    pub violations: Vec<Violation>,
    pub applied: usize,
    pub refused: usize,
    /// Contributions claimed by the right lender on an output bound to the slice's attempt
    /// (TEST-P23): (slice, lender, contribution).
    pub structural_claims: Vec<(SliceId, AccountId, ContributionId)>,
    /// Rejections per error type (coverage).
    pub refusal_counts: std::collections::BTreeMap<String, u64>,
    /// Where the time goes: copying the state for the checker, running the command, checking.
    pub time: [std::time::Duration; 3],
}

impl Default for Sim {
    fn default() -> Self {
        Self::new(sim_config())
    }
}

impl Sim {
    pub fn new(cfg: Config) -> Self {
        let (ids, orchestrator) = SimIdentity::new();
        let coord = Coordinator::new(cfg, ids.verifier_ledger(), orchestrator, ids.verifier())
            .expect("valid simulation config");
        let mut sim = Sim {
            coord,
            ids: Arc::new(ids),
            history: Vec::new(),
            violations: Vec::new(),
            applied: 0,
            refused: 0,
            structural_claims: Vec::new(),
            refusal_counts: Default::default(),
            time: Default::default(),
        };
        for c in setup_commands() {
            sim.exec(c).expect("setup must succeed");
        }
        sim
    }

    /// A scratch copy of `coord` with the same identities, for look-ahead.
    fn scratch(&self, coord: Coordinator) -> Sim {
        Sim {
            coord,
            ids: Arc::clone(&self.ids),
            history: Vec::new(),
            violations: Vec::new(),
            applied: 0,
            refused: 0,
            structural_claims: Vec::new(),
            refusal_counts: Default::default(),
            time: Default::default(),
        }
    }

    /// Runs a command on a copy, as its honest sender, without checks.
    pub fn try_on_copy(&self, cmd: &Command) -> Result<Outcome, DomainError> {
        let mut c = self.coord.clone();
        let ctx = self.actor(cmd);
        c.execute(&ctx, &self.signed(&ctx, cmd.clone()))
    }

    fn quiet(&mut self, cmd: &Command) {
        let ctx = self.actor(cmd);
        let cmd = self.signed(&ctx, cmd.clone());
        let _ = self.coord.execute(&ctx, &cmd);
    }

    /// Registers the key of an account that is not in the default set.
    pub fn register(&self, a: AccountId) {
        let _ = self.ids.keys.register(a.0, user_key(a).public());
    }

    /// Full read access to the ledger (Auditor credential).
    pub fn ledger(&self) -> &Ledger {
        self.coord
            .audit_ledger(&self.ids.auditor)
            .expect("the auditor reads the ledger")
    }

    pub fn balance(&self, a: Account) -> i128 {
        self.ledger().balance(a)
    }

    /// Applies a concrete command, sent by its honest sender, and checks every property.
    pub fn exec(&mut self, cmd: Command) -> Result<Outcome, DomainError> {
        let ctx = self.actor(&cmd);
        self.exec_as(&ctx, cmd)
    }

    /// JOB-R38: every lender of `attempt` accepts, loads and reports ready, each as itself, then
    /// each stage's recipient corroborates the restoration (JOB-R18): a healthy cluster. Every
    /// property is checked. Returns the first refusal, or the outcome of the last readiness.
    pub fn start_cluster(
        &mut self,
        job: JobId,
        attempt: u32,
        restored: PerType<u32>,
    ) -> Result<Outcome, DomainError> {
        let lenders = self
            .coord
            .job(job)?
            .attempts
            .get(&attempt)
            .map(|a| a.lenders.clone())
            .ok_or(DomainError::StaleAttempt)?;
        let mut last = Outcome::AlreadyApplied;
        for cmd in bring_up(job, attempt, &lenders, restored) {
            last = self.exec(cmd)?;
        }
        for cmd in corroborate(job, attempt, &lenders) {
            self.exec(cmd)?;
        }
        Ok(last)
    }

    /// Applies a command sent by `ctx` and checks every property, including TEST-P29.
    pub fn exec_as(&mut self, ctx: &AuthContext, cmd: Command) -> Result<Outcome, DomainError> {
        let cmd = self.signed(ctx, cmd);
        let t0 = std::time::Instant::now();
        let before = self.coord.clone();
        let t1 = std::time::Instant::now();
        let res = self.coord.execute(ctx, &cmd);
        let t2 = std::time::Instant::now();
        if let (
            Ok(Outcome::Applied),
            Command::Claim {
                slice,
                lender,
                items,
            },
        ) = (&res, &cmd)
        {
            self.record_claims(&before, *slice, *lender, items);
        }
        let auditor = &self.ids.auditor;
        let mut vs = check_step(&before, ctx, &cmd, &res, &self.coord, auditor);
        vs.extend(check_state(&self.coord, auditor));
        for v in vs {
            if !self.violations.contains(&v) {
                self.violations.push(v);
            }
        }
        self.time[0] += t1 - t0;
        self.time[1] += t2 - t1;
        self.time[2] += t2.elapsed();
        match &res {
            Ok(_) => self.applied += 1,
            Err(e) => {
                self.refused += 1;
                let k = format!("{e:?}");
                let k = k.split(['(', ' ', '{']).next().unwrap_or("").to_string();
                *self.refusal_counts.entry(k).or_default() += 1;
            }
        }
        self.history.push(cmd);
        res
    }

    fn record_claims(
        &mut self,
        c: &Coordinator,
        slice: SliceId,
        lender: AccountId,
        items: &[ClaimItem],
    ) {
        let a = &c.jobs()[&slice.job].attempts[&slice.attempt];
        for it in items {
            if let ClaimItem::Contribution { output, stage, .. } = it {
                let st = *stage as usize;
                if a.lenders.get(st) != Some(&lender)
                    || c.delivery().outputs().get(output) != Some(&slice.attempt)
                {
                    continue;
                }
                let Some((ls, le)) = a.layer_range(st) else {
                    continue;
                };
                self.structural_claims.push((
                    slice,
                    lender,
                    ContributionId {
                        output: *output,
                        charge: c.delivery().charges()[output].gen,
                        layer_start: ls,
                        layer_end: le,
                        role: ContributionRole::Executor,
                    },
                ));
            }
        }
    }

    fn job(&self, sel: u8) -> JobId {
        pick(&JOBS, sel)
    }

    fn slice_of(&self, job: JobId, sel: u8) -> Option<SliceId> {
        let ids: Vec<SliceId> = self
            .coord
            .slices()
            .keys()
            .filter(|s| s.job == job)
            .copied()
            .collect();
        if ids.is_empty() {
            None
        } else {
            Some(ids[sel as usize % ids.len()])
        }
    }

    pub fn run_op(&mut self, op: &Op) {
        if let Op::Impersonate { job, sel, sender } = *op {
            if let Some(cmd) = self.impersonated(job, sel) {
                let ctx = self.principal(sender);
                let _ = self.exec_as(&ctx, cmd);
            }
            return;
        }
        for cmd in self.resolve(op) {
            let _ = self.exec(cmd);
        }
    }

    /// Liveness (TEST-P06, TEST-P13): stop all activity, let deadlines pass and reconcile. Every
    /// job must end closed with zero escrow, without human action.
    pub fn drain(&mut self) {
        let jobs: Vec<JobId> = self.coord.jobs().keys().copied().collect();
        for id in &jobs {
            let exec = self.coord.jobs()[id].exec;
            if !exec.is_terminal() && exec != ExecStatus::Settling {
                let _ = self.exec(Command::Cancel {
                    job: *id,
                    expected_version: None,
                });
            }
        }
        for _ in 0..12 {
            let _ = self.exec(Command::Tick { dt: 3 * 24 * 3600 });
            let _ = self.exec(Command::Reconcile);
        }
        for j in self.coord.jobs().values() {
            if !j.exec.is_terminal() || j.settle != SettleStatus::Closed {
                self.violations.push(Violation {
                    property: "TEST-P06",
                    detail: format!("{:?} stuck: exec {:?}, settle {:?}", j.id, j.exec, j.settle),
                });
            }
        }
        for s in self.coord.slices().values() {
            if s.status != SliceStatus::Final {
                self.violations.push(Violation {
                    property: "TEST-P06",
                    detail: format!("slice {:?} stuck in {:?}", s.id, s.status),
                });
            }
            // JOB-R22: every held reward ends released or contested.
            for (l, line) in &s.lines {
                if line.held != 0 {
                    self.violations.push(Violation {
                        property: "TEST-P06",
                        detail: format!("{:?}/{l:?}: reward still held after drain", s.id),
                    });
                }
            }
        }
        // JOB-R29: no delivery stays provisional.
        for (o, ch) in self.coord.delivery().charges() {
            if !ch.definitive {
                self.violations.push(Violation {
                    property: "TEST-P06",
                    detail: format!("{o:?} still provisional after drain"),
                });
            }
        }
        let fairness = crate::invariants::check_fairness(&self.coord, &self.structural_claims);
        self.violations.extend(fairness);
    }
}
