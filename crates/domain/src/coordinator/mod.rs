//! Coordinator (Job Orchestrator trust domain): applies commands as atomic transitions.
//! `execute` authorizes a command, runs it on a full copy of the state and keeps the copy only if
//! the whole transition succeeds, the in-memory equivalent of JOB-R01's single transaction.
//!
//! The ledger is reached only through typed operations and the orchestrator's own credential
//! (`ledger_op`); delivery state and the pool registry live in their own books, with private
//! fields.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gpu_ledger::link::{LedgerInfo, RemoteLedger, TxId, TxState};
use gpu_ledger::{
    Account, Amount, Assignment, EscrowBucket, IssueTo, ItemId, JobTerms, Ledger, LedgerApiError,
    LedgerError, LedgerOp, LedgerOutcome, LedgerService, LineRef, OutputRef,
};
use more_identity::{AuthContext, CredentialVerifier, ServiceCredential, ServiceRole};

use crate::authorization::authorize;
use crate::command::{Command, IssueTarget, Outcome};
use crate::config::{Config, MAX_TIME};
use crate::delivery_book::DeliveryBook;
use crate::error::DomainError;
use crate::ids::*;
use crate::model::*;
use crate::registry::{PoolMode, Registry};
use link::{Committed, LedgerLink};

mod audit;
mod claims;
mod contests;
mod delivery;
mod dispatch;
mod evaluation;
mod leases;
mod lifecycle;
mod link;
mod placement;
mod receipts;
mod reconciliation;
mod rewards;

pub use audit::AuditEvent;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinator {
    cfg: Config,
    now: Time,
    /// The ledger, in this process or in its own. Private: reached only through typed
    /// operations, with the orchestrator's own credential (`ledger_op`).
    ledger: LedgerLink,
    /// The orchestrator's credential towards the ledger (role `Orchestrator`).
    cred: ServiceCredential,
    /// Checks the credentials of calling services (tag and revocation), like the ledger does.
    verifier: CredentialVerifier,
    /// Model Registry: pools, members, catalog.
    registry: Registry,
    /// Delivery state: charges, contests, witness commitments.
    delivery: DeliveryBook,
    jobs: BTreeMap<JobId, Job>,
    slices: BTreeMap<SliceId, Slice>,
    /// Reserved or paid contribution to its slice (JOB-R21).
    contributions: BTreeMap<ContributionId, SliceId>,
    /// Reserved or paid recovery work to its slice (JOB-R18).
    recovery_items: BTreeMap<RecoveryWorkId, SliceId>,
    /// Payments admitted on uncommitted receipts, per account: (time, amount). Gross amounts; a
    /// refund does not restore quota (JOB-R19).
    uncommitted_paid: BTreeMap<AccountId, Vec<(Time, Amount)>>,
    /// Receipt commitment history: (covered up to, time, seq) (JOB-R15).
    commit_log: CommitLog,
    /// Receipts co-signed by the recipient and presented by the producer: highest position
    /// covered, per (job, attempt, producer, type) (JOB-R12, LEDGER-016).
    presented: BTreeMap<(JobId, u32, AccountId, WorkType), u32>,
    /// Logical sequence number: total order of applied commands (CE-03).
    seq: u64,
    audit: Vec<AuditEvent>,
    /// Why the coordinator accepts nothing for now (ledger in another process only).
    halted: Option<Halt>,
}

/// A coordinator stops when it no longer knows what its ledger holds.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Halt {
    /// The answer to the commit of transaction `tx` was lost. `pending` is the state the
    /// coordinator takes if the ledger did commit; otherwise it keeps the one it has.
    CommitUnknown { tx: TxId, pending: Box<Coordinator> },
    /// The ledger restarted and lost its state.
    LedgerLost,
}

type R<T = ()> = Result<T, DomainError>;

/// (job, attempt, producer, type) to [(covered up to, time, seq)].
pub type CommitLog = BTreeMap<(JobId, u32, AccountId, WorkType), Vec<(u32, Time, u64)>>;

fn job_acct(j: JobId) -> u32 {
    j.0
}

fn line_ref(s: SliceId, lender: AccountId) -> LineRef {
    LineRef {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

fn output_ref(o: OutputId) -> OutputRef {
    OutputRef {
        wt: o.wt.idx() as u8,
        pos: o.pos,
    }
}

fn add(a: Amount, b: Amount, what: &'static str) -> R<Amount> {
    a.checked_add(b).ok_or(DomainError::Overflow(what))
}

/// Subtraction on internal counters: going below zero is a model bug, never an input error.
fn sub(a: Amount, b: Amount, what: &'static str) -> R<Amount> {
    a.checked_sub(b)
        .ok_or_else(|| DomainError::Internal(format!("{what}: {a} - {b}")))
}

impl Coordinator {
    /// `ledger` is the Ledger service; `cred` must be an Orchestrator credential it accepts;
    /// `verifier` checks the credentials of the services that send commands.
    ///
    /// # Errors
    /// `InvalidInput` for a config outside the arithmetic bounds or a credential that is not a
    /// valid Orchestrator one.
    pub fn new(
        cfg: Config,
        ledger: LedgerService,
        cred: ServiceCredential,
        verifier: CredentialVerifier,
    ) -> R<Self> {
        Self::start(cfg, LedgerLink::Local(ledger), cred, verifier)
    }

    /// A coordinator whose ledger runs in another process. `port` is the orchestrator's own
    /// authenticated connection to it and `info` what the ledger answered to `Info` on that
    /// connection. The same checks apply as for a ledger in this process.
    ///
    /// The coordinator then sends the ledger its own operations only. Issuance, the ledger's
    /// clock and the registration of pool admins belong to other services, which hold their own
    /// keys and talk to the ledger themselves.
    ///
    /// `node` names this coordinator instance in its transactions. An instance started later
    /// with the same credential must take a higher number: the ledger then refuses the earlier
    /// one, and refuses a number that is not higher.
    pub fn with_remote_ledger(
        cfg: Config,
        port: Arc<Mutex<dyn RemoteLedger>>,
        info: LedgerInfo,
        node: u64,
        cred: ServiceCredential,
        verifier: CredentialVerifier,
    ) -> R<Self> {
        Self::start(cfg, LedgerLink::remote(port, info, node), cred, verifier)
    }

    /// The transaction whose commit got no answer, if the coordinator is stopped on one.
    pub fn unknown_commit(&self) -> Option<TxId> {
        match &self.halted {
            Some(Halt::CommitUnknown { tx, .. }) => Some(*tx),
            _ => None,
        }
    }

    /// Replaces a failed connection to the ledger. The connection must have authenticated this
    /// deployment's ledger, as `LedgerClient::connect` checks. The failed one is dropped, which
    /// tells the ledger to roll back what was still open on it. If the ledger at the other end
    /// has another incarnation, it restarted and lost its state: the coordinator stops for good.
    pub fn reconnect_ledger(&mut self, port: Arc<Mutex<dyn RemoteLedger>>) -> R {
        let Some(known) = self.ledger.incarnation() else {
            return Err(DomainError::Precondition("the ledger is in this process"));
        };
        if self.halted == Some(Halt::LedgerLost) {
            return Err(DomainError::LedgerStateLost);
        }
        let incarnation = self.ledger.reconnect(port.clone())?;
        if let Some(Halt::CommitUnknown { pending, .. }) = &mut self.halted {
            pending.ledger.replace(port);
        }
        if incarnation != known {
            self.halted = Some(Halt::LedgerLost);
            return Err(DomainError::LedgerStateLost);
        }
        Ok(())
    }

    /// Asks the ledger what became of the transaction whose commit got no answer, and acts on
    /// the answer. Committed: the coordinator takes the state that goes with it. Rolled back:
    /// it keeps the state it had, and the command can be sent again by its sender. Still open
    /// or unknown: it stays stopped. Nothing is ever sent again on its own.
    pub fn resolve_commit(&mut self) -> R<TxState> {
        let Some(Halt::CommitUnknown { tx, .. }) = &self.halted else {
            return Err(match self.halted {
                Some(Halt::LedgerLost) => DomainError::LedgerStateLost,
                _ => DomainError::Precondition("no commit to resolve"),
            });
        };
        // A connection ends with the process at its other end: the ledger that answers here is
        // the incarnation `reconnect_ledger` checked.
        let (state, _) = self.ledger.status(*tx)?;
        match state {
            TxState::Committed { .. } => {
                if let Some(Halt::CommitUnknown { pending, .. }) = self.halted.take() {
                    // The connection in use now is the one to keep.
                    let link = self.ledger.clone();
                    *self = *pending;
                    self.ledger = link;
                    self.halted = None;
                }
            }
            TxState::RolledBack(_) => self.halted = None,
            // Open: its deadline will settle it. Unknown: the ledger no longer remembers, an
            // operator has to compare both sides.
            TxState::Open | TxState::Unknown => {}
        }
        Ok(state)
    }

    fn start(
        cfg: Config,
        ledger: LedgerLink,
        cred: ServiceCredential,
        verifier: CredentialVerifier,
    ) -> R<Self> {
        cfg.validate().map_err(DomainError::InvalidInput)?;
        if verifier.verify(&cred) != Ok(ServiceRole::Orchestrator) {
            return Err(DomainError::InvalidInput(
                "orchestrator credential expected",
            ));
        }
        // JOB-R22: the coordinator never releases a reward before the ledger would let it.
        if cfg.reward_window < ledger.limits().reward_hold {
            return Err(DomainError::InvalidInput(
                "reward window shorter than the ledger's hold",
            ));
        }
        // LEDGER-018: with a contest limit below the hold, a payment could be stuck.
        ledger
            .limits()
            .validate()
            .map_err(DomainError::InvalidInput)?;
        if verifier.domain() != ledger.domain() {
            return Err(DomainError::InvalidInput(
                "ledger and coordinator of different deployments",
            ));
        }
        Ok(Coordinator {
            cfg,
            now: 0,
            ledger,
            cred,
            verifier,
            registry: Registry::default(),
            delivery: DeliveryBook::default(),
            jobs: BTreeMap::new(),
            slices: BTreeMap::new(),
            contributions: BTreeMap::new(),
            recovery_items: BTreeMap::new(),
            uncommitted_paid: BTreeMap::new(),
            commit_log: BTreeMap::new(),
            presented: BTreeMap::new(),
            seq: 0,
            audit: Vec::new(),
            halted: None,
        })
    }

    /// Authorizes then applies a command atomically. An unauthorized command is refused before
    /// anything is touched (SEC-001).
    pub fn execute(&mut self, ctx: &AuthContext, cmd: &Command) -> R<Outcome> {
        // A service credential is checked on every command: a revoked one stops working here as
        // it does at the ledger.
        if let Some(c) = ctx.credential() {
            self.verifier
                .verify(c)
                .map_err(|_| DomainError::Unauthorized("invalid or revoked service credential"))?;
        }
        match self.halted {
            Some(Halt::CommitUnknown { .. }) => return Err(DomainError::LedgerOutcomeUnknown),
            Some(Halt::LedgerLost) => return Err(DomainError::LedgerStateLost),
            None => {}
        }
        authorize(self, ctx, cmd)?;
        // With the ledger in another process, its part of the transition is a transaction there:
        // committed with the coordinator's copy, or rolled back with it.
        self.ledger.begin()?;
        let mut next = self.clone();
        match next.step(ctx, cmd) {
            Ok(Outcome::Applied) => match next.ledger.commit() {
                Committed::Yes => {
                    *self = next;
                    Ok(Outcome::Applied)
                }
                Committed::No(e) => {
                    // Nothing of the command is kept, but the transaction is closed on the
                    // link all the same.
                    self.ledger = next.ledger;
                    Err(e.into())
                }
                // The commit was sent and no answer came. Sending the command again could apply
                // it twice, and dropping it could forget something the ledger holds: the
                // coordinator stops until the ledger has been asked (`resolve_commit`).
                Committed::Unknown(tx) => {
                    self.ledger = next.ledger.clone();
                    self.halted = Some(Halt::CommitUnknown {
                        tx,
                        pending: Box::new(next),
                    });
                    Err(DomainError::LedgerOutcomeUnknown)
                }
            },
            // An already applied command changes nothing, not even the sequence (JOB-R04).
            Ok(out) => {
                self.ledger.abort()?;
                Ok(out)
            }
            Err(e) => {
                // The command's own error is the one to report. If the abort does not get
                // through, the ledger rolls back when the connection ends or times out.
                let _undone_there_anyway = self.ledger.abort();
                Err(e)
            }
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Coordinator clock (JOB-R09).
    pub fn now(&self) -> Time {
        self.now
    }

    /// The deployment this coordinator serves: the one its credential verifier belongs to.
    pub fn domain(&self) -> more_identity::Domain {
        self.verifier.domain()
    }

    /// Position of the last applied command in the log (CE-03).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn audit_log(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn delivery(&self) -> &DeliveryBook {
        &self.delivery
    }

    pub fn jobs(&self) -> &BTreeMap<JobId, Job> {
        &self.jobs
    }

    pub fn slices(&self) -> &BTreeMap<SliceId, Slice> {
        &self.slices
    }

    pub fn contributions(&self) -> &BTreeMap<ContributionId, SliceId> {
        &self.contributions
    }

    pub fn recovery_items(&self) -> &BTreeMap<RecoveryWorkId, SliceId> {
        &self.recovery_items
    }

    pub fn uncommitted_paid(&self) -> &BTreeMap<AccountId, Vec<(Time, Amount)>> {
        &self.uncommitted_paid
    }

    pub fn commit_log(&self) -> &CommitLog {
        &self.commit_log
    }

    pub fn presented_receipts(&self) -> &BTreeMap<(JobId, u32, AccountId, WorkType), u32> {
        &self.presented
    }

    /// Full read access to the ledger, for the Auditor role only.
    pub fn audit_ledger(&self, auditor: &ServiceCredential) -> R<&Ledger> {
        match self.ledger.local() {
            Some(ledger) => Ok(ledger.audit_view(auditor)?),
            None => Err(DomainError::Precondition(
                "the ledger runs in its own process: audit it there",
            )),
        }
    }

    /// The ledger service itself, read-only, for audits of escrows and denials. `None` when the
    /// ledger runs in its own process: it is then audited there, by the auditor's own connection.
    pub fn ledger_service(&self) -> Option<&LedgerService> {
        self.ledger.local()
    }

    /// Test only: the ledger's journal fails after `after` more entries (`None` clears it).
    #[cfg(feature = "fault-injection")]
    pub fn inject_ledger_fault(&mut self, after: Option<u64>) {
        if let Some(ledger) = self.ledger.local_mut() {
            ledger.inject_fault(after);
        }
    }

    fn ledger_op(&mut self, op: LedgerOp) -> R<LedgerOutcome> {
        Ok(self.ledger.execute(&self.cred, op)?)
    }

    /// The ledger's name for a line item.
    fn item_id(&self, slice: SliceId, kind: ItemKind) -> R<ItemId> {
        Ok(match kind {
            ItemKind::Contribution(cid) => {
                let a = self
                    .job(slice.job)?
                    .attempts
                    .get(&slice.attempt)
                    .ok_or_else(|| DomainError::Internal("attempt".into()))?;
                let stage = (0..a.layout.len())
                    .find(|s| a.layer_range(*s) == Some((cid.layer_start, cid.layer_end)))
                    .ok_or_else(|| DomainError::Internal("contribution stage".into()))?;
                ItemId::Contribution {
                    output: output_ref(cid.output),
                    gen: cid.charge,
                    stage: stage as u32,
                }
            }
            ItemKind::Recovery(rid) => ItemId::Recovery {
                attempt: rid.attempt,
                segment: rid.segment,
            },
        })
    }

    fn escrow_work(&self, job: JobId) -> R<Amount> {
        Ok(self
            .ledger
            .job_balance(&self.cred, Account::EscrowWork(job_acct(job)))?)
    }

    pub fn job(&self, id: JobId) -> R<&Job> {
        self.jobs.get(&id).ok_or(DomainError::UnknownJob(id))
    }

    fn job_mut(&mut self, id: JobId) -> R<&mut Job> {
        self.jobs.get_mut(&id).ok_or(DomainError::UnknownJob(id))
    }

    fn slice_mut(&mut self, id: SliceId) -> R<&mut Slice> {
        self.slices
            .get_mut(&id)
            .ok_or(DomainError::UnknownSlice(id))
    }

    fn attempt_mut(&mut self, job: JobId, attempt: u32) -> R<&mut Attempt> {
        self.job_mut(job)?
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal(format!("missing attempt {attempt}")))
    }

    fn line_mut(&mut self, slice: SliceId, lender: AccountId) -> R<&mut Line> {
        self.slice_mut(slice)?
            .lines
            .get_mut(&lender)
            .ok_or_else(|| DomainError::Internal(format!("missing line {lender:?}")))
    }

    fn is_credits(&self, job: JobId) -> R<bool> {
        let pool = self.job(job)?.pool;
        Ok(self.registry.pool(pool)?.is_credits())
    }

    fn check_version(&self, job: JobId, expected: Option<u64>) -> R {
        if let Some(e) = expected {
            let actual = self.job(job)?.version;
            if e != actual {
                return Err(DomainError::VersionConflict {
                    expected: e,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn set_exec(&mut self, job: JobId, to: ExecStatus, rule: &'static str) -> R {
        let now = self.now;
        let j = self.job_mut(job)?;
        let from = j.exec;
        if !ExecStatus::allowed(from, to) {
            return Err(DomainError::InvalidTransition { from, rule });
        }
        j.exec = to;
        j.exec_since = now;
        j.version += 1;
        self.audit.push(AuditEvent::Exec {
            job,
            from: Some(from),
            to,
            rule,
        });
        Ok(())
    }

    fn set_settle(&mut self, job: JobId, to: SettleStatus, rule: &'static str) -> R {
        let j = self.job_mut(job)?;
        let from = j.settle;
        let ok = matches!(
            (from, to),
            (SettleStatus::None, SettleStatus::Active)
                | (SettleStatus::Active, SettleStatus::Finalizing)
                | (SettleStatus::Finalizing, SettleStatus::Closed)
                | (SettleStatus::None, SettleStatus::Closed)
        );
        if !ok {
            return Err(DomainError::Internal(format!("settle {from:?} -> {to:?}")));
        }
        j.settle = to;
        j.version += 1;
        self.audit.push(AuditEvent::Settle {
            job,
            from,
            to,
            rule,
        });
        Ok(())
    }

    fn set_slice(&mut self, id: SliceId, to: SliceStatus, rule: &'static str) -> R {
        let now = self.now;
        let s = self.slice_mut(id)?;
        let from = s.status;
        if !SliceStatus::allowed(from, to) {
            return Err(DomainError::InvalidSliceTransition { from, rule });
        }
        s.status = to;
        let seq = self.seq;
        let s = self.slice_mut(id)?;
        match to {
            SliceStatus::Closed => {
                s.closed_at = Some(now);
                s.closed_seq = Some(seq);
            }
            SliceStatus::Final => s.final_at = Some(now),
            _ => {}
        }
        self.audit.push(AuditEvent::SliceState {
            slice: id,
            from: Some(from),
            to,
            rule,
        });
        Ok(())
    }

    fn open_slice(&mut self, job: JobId, attempt: u32) -> R {
        let now = self.now;
        let a = self
            .job_mut(job)?
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?;
        a.next_slice += 1;
        let id = SliceId {
            job,
            attempt,
            slice: a.next_slice,
        };
        self.slices.insert(
            id,
            Slice {
                id,
                status: SliceStatus::Open,
                opened_at: now,
                receipt_deadline: None,
                closed_at: None,
                closed_seq: None,
                final_at: None,
                staged: Vec::new(),
                lines: BTreeMap::new(),
                rejected_items: 0,
            },
        );
        self.audit.push(AuditEvent::SliceState {
            slice: id,
            from: None,
            to: SliceStatus::Open,
            rule: "JOB-S01",
        });
        Ok(())
    }

    fn slices_of(&self, job: JobId, attempt: Option<u32>) -> Vec<SliceId> {
        self.slices
            .keys()
            .filter(|s| s.job == job && attempt.is_none_or(|a| s.attempt == a))
            .copied()
            .collect()
    }

    /// Revokes the current attempt (JOB-R11); its open slices start draining (JOB-S02).
    fn revoke_current(&mut self, job: JobId) -> R {
        let now = self.now;
        let seq = self.seq;
        let drain = self.cfg.drain_window;
        let j = self.job(job)?;
        let attempt = j.attempt;
        if j.attempts
            .get(&attempt)
            .is_none_or(|a| a.revoked_at.is_some())
        {
            return Ok(());
        }
        // CE-03: the ledger closes the attempt's set of proofs at the same point of the log.
        self.ledger_op(LedgerOp::RevokeAttempt {
            job: job_acct(job),
            attempt,
        })?;
        let a = self.attempt_mut(job, attempt)?;
        a.revoked_at = Some(now);
        a.revoked_seq = Some(seq);
        let nodes = a.expired_nodes(now);
        if !nodes.is_empty() {
            self.audit.push(AuditEvent::LeasesExpired {
                job,
                attempt,
                nodes,
            });
        }
        for id in self.slices_of(job, Some(attempt)) {
            if self.slices[&id].status == SliceStatus::Open {
                self.set_slice(id, SliceStatus::Draining, "JOB-S02")?;
                self.slice_mut(id)?.receipt_deadline = Some(now + drain);
            }
        }
        self.maybe_return_earmark(job, attempt)
    }

    /// Returns an attempt's unused recovery share to the budget once it is revoked and all its
    /// slices are final (JOB-R18).
    fn maybe_return_earmark(&mut self, job: JobId, attempt: u32) -> R {
        let all_final = self
            .slices_of(job, Some(attempt))
            .iter()
            .all(|s| self.slices[s].status == SliceStatus::Final);
        let j = self.job_mut(job)?;
        let Some(a) = j.attempts.get_mut(&attempt) else {
            return Ok(());
        };
        if a.revoked_at.is_none() || a.earmark_returned || !all_final {
            return Ok(());
        }
        let unused = a
            .recovery_earmark
            .checked_sub(a.recovery_reserved)
            .ok_or_else(|| DomainError::Internal("recovery reserved > earmark".into()))?;
        a.earmark_returned = true;
        j.recovery_unearmarked = add(j.recovery_unearmarked, unused, "recovery budget")?;
        // The ledger computes the same amount from its own records; a difference is a bug.
        let LedgerOutcome::Moved(back) = self.ledger_op(LedgerOp::ReturnEarmark {
            job: job_acct(job),
            attempt,
        })?
        else {
            return Err(DomainError::Internal("earmark outcome".into()));
        };
        if back != unused {
            return Err(DomainError::Internal(format!(
                "earmark returned: ledger {back}, coordinator {unused}"
            )));
        }
        Ok(())
    }

    fn require_exec(&self, job: JobId, want: ExecStatus, rule: &'static str) -> R {
        let from = self.job(job)?.exec;
        if from != want {
            return Err(DomainError::InvalidTransition { from, rule });
        }
        Ok(())
    }
}

/// FNV-1a over 64-bit words (symbolic digests in the model).
fn fnv(words: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in words {
        for b in w.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}
