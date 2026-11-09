//! Simulated world, abstract operations and the `proptest` generator. Operations are selectors
//! resolved against the current state, so traces stay realistic (claims on real slices, acks on the
//! live attempt) while still including adversarial ones (stale attempts, wrong lender, duplicates,
//! concurrent versions, receipt bursts).

use proptest::prelude::*;

use gpu_domain::*;

use crate::invariants::{check_state, check_step, Violation};

pub const CREDIT_POOL: PoolId = PoolId(1);
pub const FREE_POOL: PoolId = PoolId(2);
pub const BORROWERS: [AccountId; 2] = [AccountId(1), AccountId(2)];
pub const LENDERS: [AccountId; 4] = [AccountId(10), AccountId(11), AccountId(12), AccountId(13)];
pub const JOBS: [JobId; 3] = [JobId(1), JobId(2), JobId(3)];
/// Delivery witness (relay), independent of lenders and borrowers (JOB-R26).
pub const WITNESS: AccountId = AccountId(90);

/// Setup commands: pools, issuance, job submissions.
pub fn setup_commands() -> Vec<Command> {
    vec![
        Command::CreatePool {
            pool: CREDIT_POOL,
            mode: PoolMode::Credits,
        },
        Command::CreatePool {
            pool: FREE_POOL,
            mode: PoolMode::FreeShare {
                quota_per_borrower: 1,
            },
        },
        Command::Issue {
            id: 1,
            to: IssueTarget::User(BORROWERS[0]),
            amount: 2_000,
        },
        Command::Issue {
            id: 2,
            to: IssueTarget::User(BORROWERS[1]),
            amount: 2_000,
        },
        Command::Issue {
            id: 3,
            to: IssueTarget::Pool(CREDIT_POOL),
            amount: 300,
        },
        // Job 1: 3 stages (3, 2, 1 layers), divisible prices.
        Command::Submit {
            job: JOBS[0],
            borrower: BORROWERS[0],
            pool: CREDIT_POOL,
            layout: vec![3, 2, 1],
            price: [6, 12, 3],
            max_outputs: [4, 12, 3],
        },
        // Job 2: 2 stages, price with rounding (7 / 2).
        Command::Submit {
            job: JOBS[1],
            borrower: BORROWERS[1],
            pool: CREDIT_POOL,
            layout: vec![2, 2],
            price: [4, 7, 2],
            max_outputs: [2, 8, 2],
        },
        // Job 3: free pool.
        Command::Submit {
            job: JOBS[2],
            borrower: BORROWERS[0],
            pool: FREE_POOL,
            layout: vec![1, 1],
            price: [5, 5, 5],
            max_outputs: [1, 6, 1],
        },
    ]
}

/// Abstract operation. The `u8` fields are selectors taken modulo what exists.
#[derive(Clone, Debug)]
pub enum Op {
    Tick(u8),
    Reserve(u8),
    Place {
        job: u8,
        rot: u8,
        est: u8,
    },
    PlacementFailed(u8),
    Ready {
        job: u8,
        correct: bool,
    },
    Produce {
        job: u8,
        wt: u8,
        n: u8,
    },
    Ack {
        job: u8,
        wt: u8,
        n: u8,
    },
    Commit {
        job: u8,
        stage: u8,
        wt: u8,
        partial: bool,
    },
    Claim {
        job: u8,
        slice: u8,
        stage: u8,
        wt: u8,
        pos: u8,
        ev: u8,
        honest: bool,
    },
    ClaimRecovery {
        job: u8,
        slice: u8,
        stage: u8,
        amount: u8,
        ev: u8,
    },
    StaleProduce {
        job: u8,
    },
    Close {
        job: u8,
        slice: u8,
    },
    Evaluate {
        job: u8,
        slice: u8,
    },
    Arbitrate {
        job: u8,
        slice: u8,
        lender: u8,
        pay: bool,
    },
    NodeLost(u8),
    Pause(u8),
    Resume {
        job: u8,
        topup: u8,
    },
    RecoveryTimeout(u8),
    Fund {
        job: u8,
        amount: u8,
    },
    Finish(u8),
    CompleteSettling(u8),
    Cancel(u8),
    Fail(u8),
    Settle(u8),
    Release {
        job: u8,
        slice: u8,
        lender: u8,
    },
    Contest {
        job: u8,
        slice: u8,
        lender: u8,
    },
    Reconcile,
    Duplicate(u16),
    Concurrent {
        job: u8,
        pair: u8,
    },
    /// Moves the job one sensible step along its normal path, so traces reach deep states.
    Drive {
        job: u8,
        sel: u8,
    },
    /// The right lender, on the right range, claims outputs of ANOTHER attempt.
    CrossAttemptClaim {
        job: u8,
        slice: u8,
        stage: u8,
        pos: u8,
    },
    /// Lease renewal (JOB-R31).
    Heartbeat(u8),
    /// Delivery attestation; `forged` means signed by a lender (JOB-R26).
    Deliver {
        job: u8,
        wt: u8,
        n: u8,
        forged: bool,
    },
    /// Client statement on resume or after the end: honest, "nothing after validated", or more than
    /// delivered (a lie).
    Confirm {
        job: u8,
        wt: u8,
        sel: u8,
    },
    /// The witness loses its replay buffer (current or previous attempt).
    WitnessLost {
        job: u8,
        prev: bool,
    },
    /// Simultaneous faults: silent client AND expired lease, or node AND witness lost in the same
    /// second.
    DoubleFault {
        job: u8,
        kind: u8,
    },
    /// The witness attests everything produced, lenders commit and claim, and the slice is closed
    /// and evaluated before the client answers.
    DeliverAndSettle {
        job: u8,
        sel: u8,
    },
    /// Burst of uncommitted receipts (cap, disputes, arbitration).
    UncommittedBurst {
        job: u8,
        sel: u8,
    },
    /// An arbiter rules on an existing disputed line (JOB-S06).
    ArbitrateDisputed {
        job: u8,
        sel: u8,
    },
    /// Attested tail, buffer and node lost, resume started without waiting for the client, then the
    /// client reports nothing received (JOB-F32).
    ContestUnderLiveResume {
        job: u8,
    },
    /// Full attestation arriving while draining (JOB-R32), with or without a commitment before
    /// revocation.
    LateDeliver {
        job: u8,
        commit_first: bool,
    },
    /// Client keepalive, covers no position (JOB-R33).
    ClientHeartbeat(u8),
    /// The client reports the attested tail of a revoked attempt as not received (buffer intact):
    /// contest and replay (JOB-R33).
    ContestReplay {
        job: u8,
        sel: u8,
    },
    /// The witness tries to purge its buffer (JOB-R28).
    PurgeBuffer {
        job: u8,
        prev: bool,
    },
    /// Supplementary proof before the deadline (JOB-R35); `honest` means only if a prior commitment
    /// really exists.
    Supplement {
        job: u8,
        sel: u8,
        honest: bool,
    },
    /// Contest one minute before the 24 h window ends, then the witness tries to purge right after
    /// (JOB-R28, JOB-F39).
    ContestAtWindowEnd {
        job: u8,
    },
    /// Uncommitted receipts just before midnight, reward contested, new receipts just after
    /// (JOB-R19, JOB-F40).
    BoundaryBurst {
        job: u8,
        sel: u8,
    },
}

pub fn op_strategy() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        3 => b().prop_map(Op::Tick),
        3 => b().prop_map(Op::Reserve),
        4 => (b(), b(), b()).prop_map(|(job, rot, est)| Op::Place { job, rot, est }),
        1 => b().prop_map(Op::PlacementFailed),
        4 => (b(), prop::bool::weighted(0.85)).prop_map(|(job, correct)| Op::Ready { job, correct }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        4 => (b(), b(), b(), any::<bool>()).prop_map(|(job, stage, wt, partial)| Op::Commit { job, stage, wt, partial }),
        8 => (b(), b(), b(), b(), b(), b(), prop::bool::weighted(0.7))
            .prop_map(|(job, slice, stage, wt, pos, ev, honest)| Op::Claim { job, slice, stage, wt, pos, ev, honest }),
        2 => (b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, amount, ev)| Op::ClaimRecovery { job, slice, stage, amount, ev }),
        1 => b().prop_map(|job| Op::StaleProduce { job }),
        4 => (b(), b()).prop_map(|(job, slice)| Op::Close { job, slice }),
        4 => (b(), b()).prop_map(|(job, slice)| Op::Evaluate { job, slice }),
        2 => (b(), b(), b(), any::<bool>()).prop_map(|(job, slice, lender, pay)| Op::Arbitrate { job, slice, lender, pay }),
        2 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(Op::Pause),
        2 => (b(), b()).prop_map(|(job, topup)| Op::Resume { job, topup }),
        1 => b().prop_map(Op::RecoveryTimeout),
        1 => (b(), b()).prop_map(|(job, amount)| Op::Fund { job, amount }),
        2 => b().prop_map(Op::Finish),
        2 => b().prop_map(Op::CompleteSettling),
        1 => b().prop_map(Op::Cancel),
        1 => b().prop_map(Op::Fail),
        2 => b().prop_map(Op::Settle),
        2 => (b(), b(), b()).prop_map(|(job, slice, lender)| Op::Release { job, slice, lender }),
        1 => (b(), b(), b()).prop_map(|(job, slice, lender)| Op::Contest { job, slice, lender }),
        3 => Just(Op::Reconcile),
        3 => any::<u16>().prop_map(Op::Duplicate),
        2 => (b(), b()).prop_map(|(job, pair)| Op::Concurrent { job, pair }),
        20 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        2 => (b(), b(), b(), b()).prop_map(|(job, slice, stage, pos)| Op::CrossAttemptClaim { job, slice, stage, pos }),
        3 => b().prop_map(Op::Heartbeat),
        4 => (b(), b(), b(), prop::bool::weighted(0.2)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        2 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::WitnessLost { job, prev }),
        1 => (b(), b()).prop_map(|(job, kind)| Op::DoubleFault { job, kind }),
                2 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        1 => b().prop_map(Op::ClientHeartbeat),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
        1 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
    ]
}

fn pick<T: Copy>(xs: &[T], sel: u8) -> T {
    xs[sel as usize % xs.len()]
}

fn wt_of(sel: u8) -> WorkType {
    pick(&WorkType::ALL, sel)
}

/// Simulation: coordinator state, history, violations found.
pub struct Sim {
    pub coord: Coordinator,
    pub history: Vec<Command>,
    pub violations: Vec<Violation>,
    pub applied: usize,
    pub refused: usize,
    /// Contributions claimed by the right lender on an output bound to the slice's attempt
    /// (TEST-P23): (slice, lender, contribution).
    pub structural_claims: Vec<(SliceId, AccountId, ContributionId)>,
    /// Rejections per error type (coverage).
    pub refusal_counts: std::collections::BTreeMap<String, u64>,
}

/// Simulation config: spec values, except the anti-collusion cap, lowered to 4 credits per sliding
/// 24 h so simulated prices reach it and disputes get exercised.
pub fn sim_config() -> Config {
    Config {
        uncommitted_cap: 4,
        ..Config::default()
    }
}

impl Default for Sim {
    fn default() -> Self {
        Self::new(sim_config())
    }
}

impl Sim {
    pub fn new(cfg: Config) -> Self {
        let mut sim = Sim {
            coord: Coordinator::new(cfg),
            history: Vec::new(),
            violations: Vec::new(),
            applied: 0,
            refused: 0,
            structural_claims: Vec::new(),
            refusal_counts: Default::default(),
        };
        for c in setup_commands() {
            sim.exec(c).expect("setup must succeed");
        }
        sim
    }

    /// Applies a concrete command and checks every property.
    pub fn exec(&mut self, cmd: Command) -> Result<Outcome, DomainError> {
        let before = self.coord.clone();
        let res = self.coord.apply(&cmd);
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
        let mut vs = check_step(&before, &cmd, &res, &self.coord);
        vs.extend(check_state(&self.coord));
        for v in vs {
            if !self.violations.contains(&v) {
                self.violations.push(v);
            }
        }
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
        let j = &c.jobs[&slice.job];
        let a = &j.attempts[&slice.attempt];
        for it in items {
            if let ClaimItem::Contribution { output, stage, .. } = it {
                let st = *stage as usize;
                if a.lenders.get(st) != Some(&lender)
                    || c.outputs.get(output) != Some(&slice.attempt)
                {
                    continue;
                }
                let (ls, le) = j.layer_range(st).unwrap();
                self.structural_claims.push((
                    slice,
                    lender,
                    ContributionId {
                        output: *output,
                        charge: c.charges[output].gen,
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
            .slices
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

    pub fn resolve(&self, op: &Op) -> Vec<Command> {
        let c = &self.coord;
        match *op {
            Op::Tick(s) => {
                // Mostly small steps, sometimes a jump past the deadlines.
                let dt = match s % 8 {
                    0 => 3 * 24 * 3600,
                    1 => 700,
                    2 => 130,
                    _ => u64::from(s % 40) + 1,
                };
                vec![Command::Tick { dt }]
            }
            Op::Reserve(j) => vec![Command::Reserve { job: self.job(j) }],
            Op::Place { job, rot, est } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let lenders = (0..j.layout.len())
                    .map(|k| LENDERS[(k + rot as usize) % LENDERS.len()])
                    .collect();
                let recovery_estimate = if j.intent == Intent::Resume {
                    u64::from(est % 12)
                } else {
                    0
                };
                // Sometimes a non-independent witness (a lender), which must be rejected.
                let witness = if est % 9 == 0 {
                    LENDERS[rot as usize % LENDERS.len()]
                } else {
                    WITNESS
                };
                vec![Command::Place {
                    job: id,
                    lenders,
                    recovery_estimate,
                    witness,
                    expected_version: None,
                }]
            }
            Op::PlacementFailed(j) => vec![Command::PlacementFailed { job: self.job(j) }],
            Op::Ready { job, correct } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let mut restored = j.delivered;
                if !correct {
                    restored[1] = restored[1].saturating_add(1);
                }
                vec![Command::AttemptReady {
                    job: id,
                    attempt: j.attempt,
                    restored,
                }]
            }
            Op::Produce { job, wt, n } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = wt_of(wt);
                let Some(a) = j.current() else { return vec![] };
                let upto = a.produced[wt.idx()] + 1 + u32::from(n % 5);
                vec![Command::Produce {
                    job: id,
                    attempt: j.attempt,
                    wt,
                    upto,
                }]
            }
            Op::Ack { job, wt, n } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = wt_of(wt);
                let Some(a) = j.current() else { return vec![] };
                let lo = j.validated[wt.idx()];
                let hi = a.produced[wt.idx()];
                let upto = if hi > lo {
                    lo + 1 + u32::from(n) % (hi - lo)
                } else {
                    lo + u32::from(n % 2)
                };
                vec![Command::Ack {
                    job: id,
                    attempt: j.attempt,
                    wt,
                    upto,
                }]
            }
            Op::Commit {
                job,
                stage,
                wt,
                partial,
            } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                // Commitment on the current or previous attempt (late commitment).
                let attempt = if partial && j.attempt > 1 {
                    j.attempt - 1
                } else {
                    j.attempt
                };
                let Some(a) = j.attempts.get(&attempt) else {
                    return vec![];
                };
                let lender = pick(&a.lenders, stage);
                let wt = wt_of(wt);
                vec![Command::CommitReceipts {
                    job: id,
                    attempt,
                    lender,
                    wt,
                    upto: a.produced[wt.idx()],
                }]
            }
            Op::Claim {
                job,
                slice,
                stage,
                wt,
                pos,
                ev,
                honest,
            } => {
                let id = self.job(job);
                let Some(sid) = self.slice_of(id, slice) else {
                    return vec![];
                };
                let Ok(j) = c.job(id) else { return vec![] };
                let a = &j.attempts[&sid.attempt];
                let wt = wt_of(wt);
                let st = stage as usize % a.lenders.len();
                // Honest lender claims its own range; otherwise a random one.
                let lender = if honest {
                    a.lenders[st]
                } else {
                    pick(&LENDERS, stage.wrapping_add(pos))
                };
                let evidence = match ev % 4 {
                    0 | 1 => Evidence::Committed,
                    2 => Evidence::Uncommitted,
                    _ => Evidence::None,
                };
                // Honest: outputs actually validated on this attempt. Otherwise any position.
                let positions: Vec<u32> = if honest {
                    let mine: Vec<u32> = c
                        .outputs
                        .iter()
                        .filter(|(o, at)| o.job == id && o.wt == wt && **at == sid.attempt)
                        .map(|(o, _)| o.pos)
                        .collect();
                    if mine.is_empty() {
                        return vec![];
                    }
                    (0..1 + usize::from(pos % 3))
                        .map(|k| mine[(usize::from(pos) + k) % mine.len()])
                        .collect()
                } else {
                    let max = j.max_outputs[wt.idx()].max(1);
                    (0..1 + u32::from(pos % 3))
                        .map(|k| (u32::from(pos) + k) % max)
                        .collect()
                };
                let items = positions
                    .into_iter()
                    .map(|p| ClaimItem::Contribution {
                        output: OutputId {
                            job: id,
                            wt,
                            pos: p,
                        },
                        stage: st as u32,
                        evidence,
                    })
                    .collect();
                vec![Command::Claim {
                    slice: sid,
                    lender,
                    items,
                }]
            }
            Op::ClaimRecovery {
                job,
                slice,
                stage,
                amount,
                ev,
            } => {
                let id = self.job(job);
                let Some(sid) = self.slice_of(id, slice) else {
                    return vec![];
                };
                let a = &c.jobs[&id].attempts[&sid.attempt];
                let lender = pick(&a.lenders, stage);
                let evidence = if ev % 3 == 0 {
                    Evidence::Uncommitted
                } else {
                    Evidence::Committed
                };
                vec![Command::Claim {
                    slice: sid,
                    lender,
                    items: vec![ClaimItem::Recovery {
                        segment: u32::from(stage % 3),
                        amount: u64::from(amount % 9),
                        evidence,
                    }],
                }]
            }
            Op::StaleProduce { job } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                if j.attempt < 2 {
                    return vec![];
                }
                let old = j.attempt - 1;
                let p = j.attempts[&old].produced[1];
                vec![
                    Command::Produce {
                        job: id,
                        attempt: old,
                        wt: WorkType::Generate,
                        upto: p + 1,
                    },
                    Command::Ack {
                        job: id,
                        attempt: old,
                        wt: WorkType::Generate,
                        upto: p + 1,
                    },
                ]
            }
            Op::Close { job, slice } => self
                .slice_of(self.job(job), slice)
                .map(|s| vec![Command::CloseSlice { slice: s }])
                .unwrap_or_default(),
            Op::Evaluate { job, slice } => self
                .slice_of(self.job(job), slice)
                .map(|s| vec![Command::Evaluate { slice: s }])
                .unwrap_or_default(),
            Op::Arbitrate {
                job,
                slice,
                lender,
                pay,
            } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::Arbitrate {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                        pay,
                    }]
                })
                .unwrap_or_default(),
            Op::NodeLost(j) => vec![Command::NodeLost {
                job: self.job(j),
                expected_version: None,
            }],
            Op::Pause(j) => vec![Command::Pause {
                job: self.job(j),
                reason: PauseReason::Requested,
                expected_version: None,
            }],
            Op::Resume { job, topup } => {
                let id = self.job(job);
                let topup = if c.job(id).is_ok_and(|j| j.pool == CREDIT_POOL) {
                    u64::from(topup % 60)
                } else {
                    0
                };
                vec![Command::Resume { job: id, topup }]
            }
            Op::RecoveryTimeout(j) => vec![Command::RecoveryTimeout { job: self.job(j) }],
            Op::Fund { job, amount } => vec![Command::FundRecovery {
                job: self.job(job),
                amount: u64::from(amount % 20) + 1,
            }],
            Op::Finish(j) => vec![Command::Finish {
                job: self.job(j),
                expected_version: None,
            }],
            Op::CompleteSettling(j) => vec![Command::CompleteSettling { job: self.job(j) }],
            Op::Cancel(j) => vec![Command::Cancel {
                job: self.job(j),
                expected_version: None,
            }],
            Op::Fail(j) => vec![Command::Fail { job: self.job(j) }],
            Op::Settle(j) => vec![Command::Settle { job: self.job(j) }],
            Op::Release { job, slice, lender } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::ReleaseReward {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                    }]
                })
                .unwrap_or_default(),
            Op::Contest { job, slice, lender } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::ContestReward {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                    }]
                })
                .unwrap_or_default(),
            Op::Reconcile => vec![Command::Reconcile],
            Op::Duplicate(i) => {
                // Duplicate delivery of a past command (retry, replayed outbox).
                let n = self.history.len();
                if n == 0 {
                    vec![]
                } else {
                    vec![self.history[i as usize % n].clone()]
                }
            }
            Op::Concurrent { job, pair } => {
                // Two commands computed from the same job version (JOB-R03).
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let ver = Some(j.version);
                let cancel = Command::Cancel {
                    job: id,
                    expected_version: ver,
                };
                let finish = Command::Finish {
                    job: id,
                    expected_version: ver,
                };
                let lost = Command::NodeLost {
                    job: id,
                    expected_version: ver,
                };
                let pause = Command::Pause {
                    job: id,
                    reason: PauseReason::Requested,
                    expected_version: ver,
                };
                match pair % 4 {
                    0 => vec![cancel, finish],
                    1 => vec![finish, cancel],
                    2 => vec![lost, pause],
                    _ => vec![cancel, lost],
                }
            }
            Op::Drive { job, sel } => self.drive(self.job(job), sel),
            Op::Heartbeat(j) => {
                let id = self.job(j);
                let Ok(job) = c.job(id) else { return vec![] };
                vec![Command::Heartbeat {
                    job: id,
                    attempt: job.attempt,
                }]
            }
            Op::Deliver { job, wt, n, forged } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                let wt = wt_of(wt);
                let t = wt.idx();
                // Sometimes beyond what was produced (rejected), mostly within the window.
                let upto = j.delivered[t] + 1 + u32::from(n % 4);
                let witness = if forged {
                    pick(&a.lenders, n)
                } else {
                    a.witness
                };
                // Substituted frame, or a valid frame from another session (JOB-R34).
                let digest = match n % 7 {
                    0 => c.frame_digest(id, wt, upto) ^ 1,
                    1 => c.frame_digest(pick(&JOBS, n.wrapping_add(1)), wt, upto),
                    _ => c.frame_digest(id, wt, upto),
                };
                vec![Command::Deliver {
                    job: id,
                    attempt: j.attempt,
                    witness,
                    wt,
                    upto,
                    digest,
                }]
            }
            Op::Confirm { job, wt, sel } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = WorkType::ALL
                    .into_iter()
                    .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
                    .unwrap_or_else(|| wt_of(wt));
                let t = wt.idx();
                let (v, d) = (j.validated[t], j.delivered[t]);
                let confirmed = match sel % 4 {
                    0 => d,
                    1 => v,
                    2 => v + (d - v) / 2,
                    // Lie: the client claims more than was delivered.
                    _ => d + 1,
                };
                // Sometimes a statement signed in another session (JOB-R34).
                let digest = if (sel / 4) % 5 == 0 {
                    c.frame_digest(pick(&JOBS, sel.wrapping_add(1)), wt, confirmed)
                } else {
                    c.frame_digest(id, wt, confirmed)
                };
                vec![Command::ConfirmDelivery {
                    job: id,
                    wt,
                    confirmed,
                    digest,
                }]
            }
            Op::WitnessLost { job, prev } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let attempt = if prev && j.attempt > 1 {
                    j.attempt - 1
                } else {
                    j.attempt
                };
                if attempt == 0 {
                    return vec![];
                }
                vec![Command::WitnessLost { job: id, attempt }]
            }
            Op::DeliverAndSettle { job, sel } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                if j.exec != ExecStatus::Running || a.revoked_at.is_some() {
                    return vec![];
                }
                let wt = WorkType::ALL
                    .into_iter()
                    .find(|w| a.produced[w.idx()] > j.delivered[w.idx()])
                    .unwrap_or(WorkType::Generate);
                let t = wt.idx();
                let Some(open) = c
                    .slices
                    .values()
                    .find(|s| {
                        s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open
                    })
                    .map(|s| s.id)
                else {
                    return vec![];
                };
                let mut v = vec![
                    Command::Heartbeat {
                        job: id,
                        attempt: j.attempt,
                    },
                    Command::Deliver {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                        digest: c.frame_digest(id, wt, a.produced[t]),
                    },
                ];
                for l in &a.lenders {
                    v.push(Command::CommitReceipts {
                        job: id,
                        attempt: j.attempt,
                        lender: *l,
                        wt,
                        upto: a.produced[t],
                    });
                }
                // Claims are computed on the current state, so target every bound output ahead of
                // the attestation.
                let mut tmp = Sim {
                    coord: c.clone(),
                    history: Vec::new(),
                    violations: Vec::new(),
                    applied: 0,
                    refused: 0,
                    structural_claims: Vec::new(),
                    refusal_counts: Default::default(),
                };
                for cmd in &v {
                    let _ = tmp.coord.apply(cmd);
                }
                for k in 0..a.lenders.len() as u8 {
                    if let Some(cl) =
                        tmp.honest_claim_with(open, sel.wrapping_add(k), Evidence::Committed)
                    {
                        let _ = tmp.coord.apply(&cl);
                        v.push(cl);
                    }
                }
                v.push(Command::CloseSlice { slice: open });
                v.push(Command::Evaluate { slice: open });
                v
            }
            Op::UncommittedBurst { job, sel } => {
                let id = self.job(job);
                let live: Vec<SliceId> = c
                    .slices
                    .values()
                    .filter(|s| {
                        s.id.job == id
                            && matches!(s.status, SliceStatus::Open | SliceStatus::Draining)
                    })
                    .map(|s| s.id)
                    .collect();
                if live.is_empty() {
                    return vec![];
                }
                let sid = live[usize::from(sel) % live.len()];
                let st = c.slices[&sid].status;
                let mut v: Vec<Command> = self
                    .honest_claim_with(sid, sel, Evidence::Uncommitted)
                    .into_iter()
                    .collect();
                if st == SliceStatus::Open {
                    v.push(Command::CloseSlice { slice: sid });
                    v.push(Command::Evaluate { slice: sid });
                }
                v
            }
            Op::ContestUnderLiveResume { job } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                if j.exec != ExecStatus::Running || a.revoked_at.is_some() {
                    return vec![];
                }
                let Some(wt) = WorkType::ALL
                    .into_iter()
                    .find(|w| a.produced[w.idx()] > j.validated[w.idx()])
                else {
                    return vec![];
                };
                let t = wt.idx();
                let mut delivered = j.delivered;
                delivered[t] = a.produced[t];
                let lenders: Vec<AccountId> = a.lenders.iter().rev().copied().collect();
                vec![
                    Command::Deliver {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                        digest: c.frame_digest(id, wt, a.produced[t]),
                    },
                    Command::WitnessLost {
                        job: id,
                        attempt: j.attempt,
                    },
                    Command::NodeLost {
                        job: id,
                        expected_version: None,
                    },
                    Command::Place {
                        job: id,
                        lenders,
                        recovery_estimate: 0,
                        witness: WITNESS,
                        expected_version: None,
                    },
                    Command::AttemptReady {
                        job: id,
                        attempt: j.attempt + 1,
                        restored: delivered,
                    },
                    Command::ConfirmDelivery {
                        job: id,
                        wt,
                        confirmed: j.validated[t],
                        digest: c.frame_digest(id, wt, j.validated[t]),
                    },
                ]
            }
            Op::LateDeliver { job, commit_first } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                let Some(wt) = WorkType::ALL
                    .into_iter()
                    .find(|w| a.produced[w.idx()] > j.delivered[w.idx()])
                else {
                    return vec![];
                };
                let upto = a.produced[wt.idx()];
                let deliver = Command::Deliver {
                    job: id,
                    attempt: j.attempt,
                    witness: a.witness,
                    wt,
                    upto,
                    digest: c.frame_digest(id, wt, upto),
                };
                if a.revoked_at.is_some() {
                    // After revocation, any commitment comes too late and proves nothing.
                    let mut v = Vec::new();
                    if commit_first {
                        v.push(Command::WitnessCommit {
                            job: id,
                            attempt: j.attempt,
                            witness: a.witness,
                            wt,
                            upto,
                        });
                    }
                    v.push(deliver);
                    return v;
                }
                if j.exec != ExecStatus::Running {
                    return vec![];
                }
                // Commitment (or not) before the fault, full attestation while draining.
                let mut v = vec![Command::Heartbeat {
                    job: id,
                    attempt: j.attempt,
                }];
                if commit_first {
                    v.push(Command::WitnessCommit {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto,
                    });
                }
                v.push(Command::NodeLost {
                    job: id,
                    expected_version: None,
                });
                v.push(deliver);
                v
            }
            Op::ClientHeartbeat(j) => vec![Command::ClientHeartbeat { job: self.job(j) }],
            Op::ContestAtWindowEnd { job } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let w = c.cfg.delivery_window;
                // An uncontested provisional output of a revoked attempt, window still open.
                let target = c.charges.iter().find_map(|(o, ch)| {
                    let r = j.attempts.get(&ch.attempt)?.revoked_at?;
                    (o.job == id && !ch.definitive && ch.contest.is_none() && c.now + 60 < r + w)
                        .then_some((o.wt, ch.attempt, r))
                });
                let Some((wt, attempt, r)) = target else {
                    return vec![];
                };
                let t = wt.idx();
                vec![
                    Command::Tick {
                        dt: r + w - 60 - c.now,
                    },
                    Command::ConfirmDelivery {
                        job: id,
                        wt,
                        confirmed: j.validated[t],
                        digest: c.frame_digest(id, wt, j.validated[t]),
                    },
                    Command::Tick { dt: 120 },
                    Command::PurgeBuffer { job: id, attempt },
                ]
            }
            Op::BoundaryBurst { job, sel } => self.boundary_burst(self.job(job), sel),
            Op::ContestReplay { job, sel } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(wt) = WorkType::ALL
                    .into_iter()
                    .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
                else {
                    return vec![];
                };
                let t = wt.idx();
                let (v, d) = (j.validated[t], j.delivered[t]);
                let confirmed = v + u32::from(sel) % (d - v);
                vec![Command::ConfirmDelivery {
                    job: id,
                    wt,
                    confirmed,
                    digest: c.frame_digest(id, wt, confirmed),
                }]
            }
            Op::PurgeBuffer { job, prev } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let attempt = if prev && j.attempt > 1 {
                    j.attempt - 1
                } else {
                    j.attempt
                };
                if attempt == 0 {
                    return vec![];
                }
                vec![Command::PurgeBuffer { job: id, attempt }]
            }
            Op::Supplement { job, sel, honest } => {
                let id = self.job(job);
                let mut cands = Vec::new();
                for s in c.slices.values().filter(|s| s.id.job == id) {
                    for (l, line) in &s.lines {
                        for it in &line.items {
                            if let ItemKind::Contribution(cid) = it.kind {
                                let undecided = it.status == ItemStatus::PendingEvaluation
                                    || it.awaiting_delivery;
                                if undecided && it.evidence != Evidence::Committed {
                                    let proven =
                                        c.committed_before(s.id, *l, cid.output.wt, cid.output.pos);
                                    if proven || !honest {
                                        cands.push((s.id, *l, cid.output));
                                    }
                                }
                            }
                        }
                    }
                }
                if cands.is_empty() {
                    // No candidate: the lender claims without proof (it hasn't come back yet), the
                    // slice closes, then it supplements (JOB-R35).
                    return self.late_proof(id, sel, honest);
                }
                let (slice, lender, output) = cands[usize::from(sel) % cands.len()];
                vec![Command::SupplementEvidence {
                    slice,
                    lender,
                    output,
                    evidence: Evidence::Committed,
                }]
            }
            Op::ArbitrateDisputed { job, sel } => {
                let id = self.job(job);
                let cands: Vec<(SliceId, AccountId)> = c
                    .slices
                    .values()
                    .filter(|s| {
                        s.id.job == id
                            && matches!(s.status, SliceStatus::Disputed | SliceStatus::Closed)
                    })
                    .flat_map(|s| {
                        s.lines
                            .iter()
                            .filter(|(_, l)| {
                                l.items.iter().any(|i| {
                                    i.status == ItemStatus::Disputed && !i.awaiting_delivery
                                })
                            })
                            .map(move |(l, _)| (s.id, *l))
                    })
                    .collect();
                if cands.is_empty() {
                    return vec![];
                }
                let (slice, lender) = cands[usize::from(sel) % cands.len()];
                let mut v = Vec::new();
                // The arbiter waits for the end of evaluation (JOB-R35 deadline).
                if c.slices[&slice].status == SliceStatus::Closed {
                    v.push(Command::Tick {
                        dt: c.cfg.evaluation_deadline,
                    });
                    v.push(Command::Reconcile);
                }
                v.push(Command::Arbitrate {
                    slice,
                    lender,
                    pay: sel.is_multiple_of(2),
                });
                v
            }
            Op::DoubleFault { job, kind } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                if kind.is_multiple_of(2) {
                    // Silent client and expired lease at the same deadline.
                    vec![
                        Command::Tick {
                            dt: c.cfg.client_silence.max(c.cfg.lease_ttl),
                        },
                        Command::Reconcile,
                    ]
                } else {
                    vec![
                        Command::WitnessLost {
                            job: id,
                            attempt: j.attempt.max(1),
                        },
                        Command::NodeLost {
                            job: id,
                            expected_version: None,
                        },
                    ]
                }
            }
            Op::CrossAttemptClaim {
                job,
                slice,
                stage,
                pos,
            } => {
                let id = self.job(job);
                let Some(sid) = self.slice_of(id, slice) else {
                    return vec![];
                };
                let a = &c.jobs[&id].attempts[&sid.attempt];
                let st = usize::from(stage) % a.lenders.len();
                let foreign: Vec<OutputId> = c
                    .outputs
                    .iter()
                    .filter(|(o, at)| o.job == id && **at != sid.attempt)
                    .map(|(o, _)| *o)
                    .collect();
                if foreign.is_empty() {
                    return vec![];
                }
                let o = foreign[usize::from(pos) % foreign.len()];
                vec![Command::Claim {
                    slice: sid,
                    lender: a.lenders[st],
                    items: vec![ClaimItem::Contribution {
                        output: o,
                        stage: st as u32,
                        evidence: Evidence::Committed,
                    }],
                }]
            }
        }
    }

    /// Next normal step for a job, given its state.
    fn drive(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        // Advance slices first, whatever the job state.
        let mut slice_work = Vec::new();
        for s in c.slices.values().filter(|s| s.id.job == id) {
            match s.status {
                SliceStatus::Closed => slice_work.push(Command::Evaluate { slice: s.id }),
                SliceStatus::Disputed => {
                    let arbitrable = s.lines.iter().find(|(_, l)| {
                        l.items
                            .iter()
                            .any(|i| i.status == ItemStatus::Disputed && !i.awaiting_delivery)
                    });
                    if let Some((l, _)) = arbitrable {
                        // A human arbiter rules before the deadline (JOB-S06).
                        return vec![Command::Arbitrate {
                            slice: s.id,
                            lender: *l,
                            pay: sel.is_multiple_of(2),
                        }];
                    }
                }
                SliceStatus::Final => {
                    if let Some((l, _)) = s.lines.iter().find(|(_, l)| l.held > 0) {
                        let open = s.final_at.is_some_and(|f| c.now < f + c.cfg.reward_window);
                        if !open {
                            slice_work.push(Command::ReleaseReward {
                                slice: s.id,
                                lender: *l,
                            });
                        } else if sel.is_multiple_of(4) {
                            // Fraud found during the window (JOB-R22).
                            slice_work.push(Command::ContestReward {
                                slice: s.id,
                                lender: *l,
                            });
                        }
                    }
                }
                SliceStatus::Draining => {
                    // The lender still online presents its receipts (JOB-F16).
                    if let Some(cmd) = self.honest_claim(s.id, sel) {
                        slice_work.push(cmd);
                    }
                    if c.now >= s.receipt_deadline.unwrap_or(0) {
                        slice_work.push(Command::CloseSlice { slice: s.id });
                    }
                }
                SliceStatus::Open => {}
            }
        }
        if !slice_work.is_empty() && sel.is_multiple_of(3) {
            return vec![slice_work[usize::from(sel) % slice_work.len()].clone()];
        }
        match j.exec {
            ExecStatus::Queued => vec![Command::Reserve { job: id }],
            ExecStatus::Reserved | ExecStatus::Recovering => {
                let lenders = (0..j.layout.len())
                    .map(|k| LENDERS[(k + usize::from(sel)) % LENDERS.len()])
                    .collect();
                let est = if j.intent == Intent::Resume {
                    u64::from(sel % 6)
                } else {
                    0
                };
                let mut v = self.client_confirm(id, sel);
                v.push(Command::Place {
                    job: id,
                    lenders,
                    recovery_estimate: est,
                    witness: WITNESS,
                    expected_version: None,
                });
                v
            }
            ExecStatus::Placing => vec![
                Command::Heartbeat {
                    job: id,
                    attempt: j.attempt,
                },
                Command::AttemptReady {
                    job: id,
                    attempt: j.attempt,
                    restored: j.delivered,
                },
            ],
            ExecStatus::Paused => {
                let mut v = self.client_confirm(id, sel);
                v.push(Command::Resume {
                    job: id,
                    topup: if j.pool == CREDIT_POOL { 30 } else { 0 },
                });
                v
            }
            ExecStatus::Settling => {
                let mut v = self.client_confirm(id, sel);
                v.extend([
                    Command::Tick {
                        dt: c.cfg.drain_window + 1,
                    },
                    Command::Reconcile,
                ]);
                v
            }
            ExecStatus::Running => {
                let a = j.current().expect("running has an attempt");
                let wt = pick(&WorkType::ALL, sel / 7);
                let t = wt.idx();
                let open = c
                    .slices
                    .values()
                    .find(|s| {
                        s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open
                    })
                    .map(|s| s.id);
                // Healthy cluster: renews its lease at every step.
                let hb = Command::Heartbeat {
                    job: id,
                    attempt: j.attempt,
                };
                let step: Vec<Command> = match sel % 10 {
                    0 | 1 => vec![Command::Produce {
                        job: id,
                        attempt: j.attempt,
                        wt,
                        upto: (a.produced[t] + 1 + u32::from(sel % 3)).min(j.max_outputs[t]),
                    }],
                    2 => vec![Command::Ack {
                        job: id,
                        attempt: j.attempt,
                        wt,
                        upto: a.produced[t],
                    }],
                    // The witness attests; the client does not ack right away.
                    3 => vec![Command::Deliver {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                        digest: c.frame_digest(id, wt, a.produced[t]),
                    }],
                    // The witness only sends its short commitment (JOB-R32).
                    9 => vec![Command::WitnessCommit {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                    }],
                    4 => a
                        .lenders
                        .iter()
                        .map(|l| Command::CommitReceipts {
                            job: id,
                            attempt: j.attempt,
                            lender: *l,
                            wt,
                            upto: a.produced[t],
                        })
                        .collect(),
                    5 | 6 => open
                        .and_then(|s| self.honest_claim(s, sel))
                        .into_iter()
                        .collect(),
                    7 => {
                        let mut v: Vec<Command> = open
                            .map(|s| Command::CloseSlice { slice: s })
                            .into_iter()
                            .collect();
                        if j.delivered == a.produced && sel.is_multiple_of(2) {
                            v.push(Command::Finish {
                                job: id,
                                expected_version: None,
                            });
                        }
                        v
                    }
                    _ => {
                        // Recovery claimed by the replacement (JOB-R18).
                        if a.recovery_earmark > a.recovery_reserved {
                            open.map(|s| Command::Claim {
                                slice: s,
                                lender: a.lenders[0],
                                items: vec![ClaimItem::Recovery {
                                    segment: u32::from(sel % 4),
                                    amount: (a.recovery_earmark - a.recovery_reserved).min(3),
                                    evidence: Evidence::Committed,
                                }],
                            })
                            .into_iter()
                            .collect()
                        } else {
                            vec![Command::Ack {
                                job: id,
                                attempt: j.attempt,
                                wt,
                                upto: a.produced[t],
                            }]
                        }
                    }
                };
                let mut v = vec![hb];
                v.extend(step);
                v
            }
            _ => {
                let mut v = self.client_confirm(id, sel);
                v.extend(slice_work.into_iter().take(1));
                v
            }
        }
    }

    /// Claim without proof, close, evaluate (deferred), then supplement: committed if it exists
    /// (honest), wrongly claimed otherwise.
    fn late_proof(&self, id: JobId, sel: u8, honest: bool) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        if j.exec != ExecStatus::Running {
            return vec![];
        }
        let Some(open) = c
            .slices
            .values()
            .find(|s| s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open)
            .map(|s| s.id)
        else {
            return vec![];
        };
        let Some(Command::Claim {
            slice,
            lender,
            items,
        }) = self.honest_claim_with(open, sel, Evidence::None)
        else {
            return vec![];
        };
        let mut out = vec![
            Command::Claim {
                slice,
                lender,
                items: items.clone(),
            },
            Command::CloseSlice { slice },
            Command::Evaluate { slice },
        ];
        for it in items {
            if let ClaimItem::Contribution { output, .. } = it {
                if !honest || c.committed_before(slice, lender, output.wt, output.pos) {
                    out.push(Command::SupplementEvidence {
                        slice,
                        lender,
                        output,
                        evidence: Evidence::Committed,
                    });
                }
            }
        }
        out
    }

    /// Two bursts of uncommitted receipts around a multiple of 24 h, with the first reward
    /// contested in between (JOB-R19).
    fn boundary_burst(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        if j.exec != ExecStatus::Running {
            return vec![];
        }
        let mut tmp = Sim {
            coord: c.clone(),
            history: Vec::new(),
            violations: Vec::new(),
            applied: 0,
            refused: 0,
            structural_claims: Vec::new(),
            refusal_counts: Default::default(),
        };
        let mut out = Vec::new();
        let mut step = |tmp: &mut Sim, cmd: Command| {
            let _ = tmp.coord.apply(&cmd);
            out.push(cmd);
        };
        let w = c.cfg.uncommitted_window;
        // Between 10 and 59 s before the next multiple of 24 h.
        let dt = (w - c.now % w)
            .saturating_sub(10 + u64::from(sel % 50))
            .max(1);
        step(&mut tmp, Command::Tick { dt });
        for round in 0..2 {
            let attempt = tmp.coord.jobs[&id].attempt;
            let Some(open) = tmp
                .coord
                .slices
                .values()
                .find(|s| {
                    s.id.job == id && s.id.attempt == attempt && s.status == SliceStatus::Open
                })
                .map(|s| s.id)
            else {
                break;
            };
            // The lender with the smallest share is the one that can reach the cap.
            let last = (tmp.coord.jobs[&id].layout.len() - 1) as u8;
            let Some(Command::Claim {
                slice,
                lender,
                mut items,
            }) = tmp.honest_claim_with(open, last, Evidence::Uncommitted)
            else {
                break;
            };
            // One receipt before midnight, two after, so outputs remain to claim.
            items.truncate(if round == 0 { 1 } else { 2 });
            step(
                &mut tmp,
                Command::Claim {
                    slice,
                    lender,
                    items,
                },
            );
            step(&mut tmp, Command::CloseSlice { slice });
            step(&mut tmp, Command::Evaluate { slice });
            if round == 0 {
                step(&mut tmp, Command::ContestReward { slice, lender });
                step(&mut tmp, Command::Tick { dt: 60 });
            }
        }
        out
    }

    /// Client statement on its provisional outputs (JOB-R28): usually "all received", sometimes
    /// "nothing after validated".
    fn client_confirm(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        // The client talks about the type that has provisional outputs, if any.
        let Some(wt) = WorkType::ALL
            .into_iter()
            .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
        else {
            return vec![];
        };
        let t = wt.idx();
        if sel % 4 == 3 {
            return vec![];
        }
        let confirmed = if sel.is_multiple_of(3) {
            j.validated[t]
        } else {
            j.delivered[t]
        };
        vec![Command::ConfirmDelivery {
            job: id,
            wt,
            confirmed,
            digest: c.frame_digest(id, wt, confirmed),
        }]
    }

    /// Honest claim: an attempt's lender claims its range for outputs validated on that attempt and
    /// not claimed yet.
    fn honest_claim(&self, slice: SliceId, sel: u8) -> Option<Command> {
        // An honest lender sometimes sends its claim before its proof comes back, and supplements
        // it before the deadline (JOB-R35).
        let evidence = match sel % 7 {
            0 => Evidence::Uncommitted,
            1 => Evidence::None,
            _ => Evidence::Committed,
        };
        self.honest_claim_with(slice, sel, evidence)
    }

    fn honest_claim_with(&self, slice: SliceId, sel: u8, evidence: Evidence) -> Option<Command> {
        let c = &self.coord;
        let j = c.job(slice.job).ok()?;
        let a = j.attempts.get(&slice.attempt)?;
        let stage = usize::from(sel) % a.lenders.len();
        let lender = a.lenders[stage];
        let (ls, le) = j.layer_range(stage)?;
        let staged: Vec<OutputId> = c.slices[&slice]
            .staged
            .iter()
            .filter(|s| s.lender == lender)
            .filter_map(|s| match s.item {
                ClaimItem::Contribution { output, .. } => Some(output),
                _ => None,
            })
            .collect();
        let todo: Vec<OutputId> = c
            .outputs
            .iter()
            .filter(|(o, at)| o.job == slice.job && **at == slice.attempt)
            .map(|(o, _)| *o)
            .filter(|o| {
                !c.contributions.contains_key(&ContributionId {
                    output: *o,
                    charge: c.charges[o].gen,
                    layer_start: ls,
                    layer_end: le,
                    role: ContributionRole::Executor,
                })
            })
            .filter(|o| !staged.contains(o))
            .take(3)
            .collect();
        if todo.is_empty() {
            return None;
        }
        Some(Command::Claim {
            slice,
            lender,
            items: todo
                .into_iter()
                .map(|o| ClaimItem::Contribution {
                    output: o,
                    stage: stage as u32,
                    evidence,
                })
                .collect(),
        })
    }

    pub fn run_op(&mut self, op: &Op) {
        for cmd in self.resolve(op) {
            let _ = self.exec(cmd);
        }
    }

    /// Liveness (TEST-P06, TEST-P13): stop all activity, let deadlines pass and reconcile. Every
    /// job must end closed with zero escrow, without human action.
    pub fn drain(&mut self) {
        let jobs: Vec<JobId> = self.coord.jobs.keys().copied().collect();
        for id in &jobs {
            let exec = self.coord.jobs[id].exec;
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
        for j in self.coord.jobs.values() {
            if !j.exec.is_terminal() || j.settle != SettleStatus::Closed {
                self.violations.push(Violation {
                    property: "TEST-P06",
                    detail: format!("{:?} stuck: exec {:?}, settle {:?}", j.id, j.exec, j.settle),
                });
            }
        }
        for s in self.coord.slices.values() {
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
        for (o, ch) in &self.coord.charges {
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
