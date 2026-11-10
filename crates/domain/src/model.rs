//! States and structures (spec sections 2.1 to 2.4).

use std::collections::BTreeMap;

use crate::ids::*;
use gpu_ledger::Amount;

/// `execution_status` (section 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecStatus {
    Queued,
    Reserved,
    Placing,
    Running,
    Recovering,
    Paused,
    Settling,
    Completed,
    Failed,
    Cancelled,
}

impl ExecStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecStatus::Completed | ExecStatus::Failed | ExecStatus::Cancelled
        )
    }

    /// Allowed transitions; anything else is forbidden. Used by the code and by the checker
    /// (TEST-P01).
    pub fn allowed(from: ExecStatus, to: ExecStatus) -> bool {
        use ExecStatus::*;
        matches!(
            (from, to),
            (Queued, Reserved)            // JOB-T02
                | (Queued, Cancelled)     // JOB-T03, JOB-T15
                | (Reserved, Placing)     // JOB-T04
                | (Placing, Running)      // JOB-T05
                | (Placing, Reserved)     // JOB-T06 (premier placement)
                | (Placing, Recovering)   // JOB-T06 (resume)
                | (Running, Recovering)   // JOB-T08
                | (Recovering, Placing)   // JOB-T09
                | (Recovering, Paused)    // JOB-T10
                | (Running, Paused)       // JOB-T11
                | (Paused, Reserved)      // JOB-T12
                | (Running, Settling)     // JOB-T13
                | (Settling, Completed)   // JOB-T14
                | (Reserved, Cancelled)
                | (Placing, Cancelled)
                | (Running, Cancelled)
                | (Recovering, Cancelled)
                | (Paused, Cancelled)     // JOB-T15, JOB-T17
                | (Queued, Failed)
                | (Reserved, Failed)
                | (Placing, Failed)
                | (Running, Failed)
                | (Recovering, Failed)
                | (Paused, Failed) // JOB-T16
        )
    }
}

/// `settlement_status` (section 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SettleStatus {
    None,
    Active,
    Finalizing,
    Closed,
}

/// `execution_intent`: monotonic, never goes back to `Initial`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intent {
    Initial,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseReason {
    LowEscrow,
    Requested,
    Preempted,
    ClientSilent,
}

/// Lease of one stage (JOB-R38). Moves forward only: `Assigned` at placement, `Accepted` when the
/// lender signs the assignment, `Loaded` when its layers match the configuration, `Ready` when its
/// state is restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeaseState {
    Assigned,
    Accepted,
    Loaded,
    Ready,
}

/// One node's lease: its own state and its own expiry (JOB-R39). Only its holder renews it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub state: LeaseState,
    pub expires_at: Time,
    /// What the lender signed it restored, once `Ready` (JOB-T05).
    pub restored: Option<Restored>,
    /// The recipient of this stage's output signed that it received that restored state, and
    /// how many recovery segments of it: the restoration is attested by a second account
    /// (JOB-R18). Written once.
    pub corroborated: Option<u32>,
}

/// A lender's restored state: the positions it resumed from and its commitment to that state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restored {
    pub positions: PerType<u32>,
    pub state: u64,
}

/// An attempt: fixed cluster, leases, production counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub no: u32,
    /// Lender assigned to each layer range (index = stage). All distinct (JOB-T04).
    pub lenders: Vec<AccountId>,
    /// Layers per stage, chosen by the scheduler; covers the model exactly.
    pub layout: Vec<u32>,
    pub issued_at: Time,
    /// Assigned delivery witness (JOB-R26), independent of lenders and borrower; the only one
    /// allowed to attest delivery.
    pub witness: AccountId,
    /// Lease of each stage, same order as `lenders` (JOB-R38, JOB-R39).
    pub leases: Vec<Lease>,
    /// The witness's own lease: renewed by the witness only (JOB-R39).
    pub witness_expires_at: Time,
    /// The witness lost its buffer: no more attestation or replay (JOB-R28).
    pub witness_lost: bool,
    /// The witness purged its buffer after retention (JOB-R28).
    pub buffer_purged: bool,
    /// `execution_revoked`: no new unit accepted (JOB-R11).
    pub revoked_at: Option<Time>,
    /// Position of the revocation in the coordinator log (CE-03).
    pub revoked_seq: Option<u64>,
    /// Every lease is `Ready`: the attempt started (JOB-T05).
    pub ready: bool,
    /// Next position to produce, per type.
    pub produced: PerType<u32>,
    /// Receipt commitments recorded by the coordinator: (lender, type) to (covered up to,
    /// coordinator time).
    pub commitments: BTreeMap<(AccountId, WorkType), (u32, Time)>,
    /// Share of the recovery budget set aside for this attempt.
    pub recovery_earmark: Amount,
    /// Recovery amount already reserved in lines (paid or not).
    pub recovery_reserved: Amount,
    /// The unused share went back to the budget.
    pub earmark_returned: bool,
    pub next_slice: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub borrower: AccountId,
    pub pool: PoolId,
    /// Client stream (session) id; binds frames and acks (JOB-R34).
    pub stream: u64,
    /// Catalog model, covered by the frame digest.
    pub model: ModelId,
    /// Layers of the model; every attempt's layout covers exactly this many.
    pub model_layers: u32,
    /// Budget the borrower signed for (escrow total never exceeds it, checked by the ledger).
    pub max_budget: Amount,
    pub version: u64,
    pub exec: ExecStatus,
    pub settle: SettleStatus,
    pub intent: Intent,
    pub exec_since: Time,
    /// State the current placement came from (JOB-T06).
    pub placing_from: Option<ExecStatus>,
    pub placement_failures: u32,
    /// Price of one output, per type, from the pool's tariff at submission.
    pub price: PerType<Amount>,
    pub max_outputs: PerType<u32>,
    pub est_cost: Amount,
    pub recovery_budget: Amount,
    /// Recovery budget not yet given to an attempt.
    pub recovery_unearmarked: Amount,
    pub attempt: u32,
    pub attempts: BTreeMap<u32, Attempt>,
    /// Validated positions `0..validated[t]` (JOB-R23), signed by the client. Never go back. The
    /// flow budget is measured from them.
    pub validated: PerType<u32>,
    /// Delivered positions `0..delivered[t]` (JOB-R27), all charged, definitively or provisionally.
    /// `validated <= delivered`. Only a rewind lowers it, never below `validated` (JOB-R29).
    pub delivered: PerType<u32>,
    pub last_ack_at: Time,
    pub checkpoint: bool,
    pub pause_reason: Option<PauseReason>,
    /// Credits paid in by the pool to relay the recovery budget (JOB-R18).
    pub pool_recovery_funded: Amount,
    /// Recovery paid from the borrower's budget (gross).
    pub recovery_paid_borrower: Amount,
    /// Recovery paid from the pool relay (gross).
    pub recovery_paid_pool: Amount,
    /// Pool share returned to the pool by a contest.
    pub recovery_contested_pool: Amount,
}

impl Job {
    pub fn current(&self) -> Option<&Attempt> {
        self.attempts.get(&self.attempt)
    }

    /// A contribution's share of an output's price: proportional to its layers, rounded down, so
    /// shares never exceed the price (JOB-R21). `None` if the stage does not exist.
    pub fn share(&self, attempt: &Attempt, wt: WorkType, stage: usize) -> Option<Amount> {
        let total = u128::from(attempt.total_layers());
        let layers = u128::from(*attempt.layout.get(stage)?);
        if total == 0 {
            return Some(0);
        }
        // price <= MAX_PRICE and layers <= MAX_LAYERS: the product fits in u128 with room to spare.
        Amount::try_from(u128::from(self.price[wt.idx()]) * layers / total).ok()
    }
}

impl Attempt {
    pub fn total_layers(&self) -> u32 {
        self.layout.iter().sum()
    }

    /// Layer range `[start, end)` of `stage`.
    pub fn layer_range(&self, stage: usize) -> Option<(u32, u32)> {
        let width = *self.layout.get(stage)?;
        let start: u32 = self.layout[..stage].iter().sum();
        Some((start, start + width))
    }

    /// Stage of `lender` in this attempt.
    pub fn stage_of(&self, lender: AccountId) -> Option<usize> {
        self.lenders.iter().position(|l| *l == lender)
    }

    /// Who receives the output of `stage` and commits its receipts (JOB-R15): the next stage, or
    /// the witness for the output node.
    pub fn recipient_of(&self, stage: usize) -> Option<AccountId> {
        if stage + 1 < self.lenders.len() {
            self.lenders.get(stage + 1).copied()
        } else if stage + 1 == self.lenders.len() {
            Some(self.witness)
        } else {
            None
        }
    }

    /// The output node: last stage.
    pub fn output_node(&self) -> Option<AccountId> {
        self.lenders.last().copied()
    }

    /// Nodes whose lease has expired at `now`, lenders then witness (JOB-R39).
    pub fn expired_nodes(&self, now: Time) -> Vec<AccountId> {
        let mut v: Vec<AccountId> = self
            .lenders
            .iter()
            .zip(&self.leases)
            .filter(|(_, l)| now >= l.expires_at)
            .map(|(a, _)| *a)
            .collect();
        if now >= self.witness_expires_at {
            v.push(self.witness);
        }
        v
    }

    /// Some node of the cluster lost its lease: the pipeline cannot run (JOB-R31, JOB-R39).
    pub fn any_expired(&self, now: Time) -> bool {
        now >= self.witness_expires_at || self.leases.iter().any(|l| now >= l.expires_at)
    }

    /// Earliest lease expiry of the cluster.
    pub fn first_expiry(&self) -> Time {
        self.leases
            .iter()
            .map(|l| l.expires_at)
            .fold(self.witness_expires_at, Time::min)
    }
}

/// Slice lifecycle (section 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SliceStatus {
    Open,
    Draining,
    Closed,
    Disputed,
    Final,
}

impl SliceStatus {
    pub fn allowed(from: SliceStatus, to: SliceStatus) -> bool {
        use SliceStatus::*;
        matches!(
            (from, to),
            (Open, Draining)
                | (Open, Closed)
                | (Draining, Closed)
                | (Closed, Final)
                | (Closed, Disputed)
                | (Disputed, Final)
        )
    }
}

/// Proof attached to a claimed item (JOB-R12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Covered by a receipt commitment recorded by the coordinator.
    Committed,
    /// Receipt co-signed by the recipient, not covered by a commitment.
    Uncommitted,
    /// No proof.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimItem {
    Contribution {
        output: OutputId,
        stage: u32,
        evidence: Evidence,
    },
    Recovery {
        segment: u32,
        amount: Amount,
        evidence: Evidence,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemKind {
    Contribution(ContributionId),
    Recovery(RecoveryWorkId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemStatus {
    PendingEvaluation,
    Paid,
    Refunded,
    Disputed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    pub kind: ItemKind,
    pub amount: Amount,
    pub evidence: Evidence,
    pub status: ItemStatus,
    /// Share funded by the pool relay (recovery only).
    pub pool_part: Amount,
    /// This item's reward was released or contested.
    pub reward_done: bool,
    /// When the item was paid: start of its contest window (JOB-R22).
    pub paid_at: Option<Time>,
    /// Contribution to an output still provisional at evaluation: waits for the output's fate,
    /// never arbitrated on its own (JOB-R30).
    pub awaiting_delivery: bool,
}

/// Line `(slice, lender)`. Invariant (JOB-R24): `claimed = pending + paid + refunded + disputed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pub claimed: Amount,
    pub pending: Amount,
    pub paid: Amount,
    pub refunded: Amount,
    pub disputed: Amount,
    pub items: Vec<LineItem>,
    /// Held rewards (paid, not yet released or contested).
    pub held: Amount,
    pub released: Amount,
    pub contested: Amount,
}

/// Claim received while `open` or `draining`, evaluated at closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedClaim {
    pub lender: AccountId,
    pub item: ClaimItem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slice {
    pub id: SliceId,
    pub status: SliceStatus,
    pub opened_at: Time,
    pub receipt_deadline: Option<Time>,
    pub closed_at: Option<Time>,
    /// Position of the closure in the coordinator log (CE-03).
    pub closed_seq: Option<u64>,
    pub final_at: Option<Time>,
    pub staged: Vec<StagedClaim>,
    pub lines: BTreeMap<AccountId, Line>,
    pub rejected_items: u32,
}

/// Why an output is charged (JOB-R26, JOB-R27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeBasis {
    /// Client signature: ack, or position confirmed on resume.
    ClientSigned,
    /// Witness attestation: provisional charge.
    Witnessed,
    /// Delivery window expired without contest.
    WindowExpired,
}

/// Charge currently in force for an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputCharge {
    /// Attempt that produced the output (JOB-R17).
    pub attempt: u32,
    /// Billing generation (idempotency key, `ContributionId::charge`).
    pub gen: u32,
    pub definitive: bool,
    pub basis: ChargeBasis,
    /// The witness's replay buffer holds the output (JOB-R28).
    pub replayable: bool,
    /// Open contest, at most one per output (JOB-R33).
    pub contest: Option<Contest>,
}

/// Contest of a provisional output reported as not received (JOB-R33).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contest {
    pub opened_at: Time,
    /// Without a signed cumulative ack covering the output by then: refund (rewind).
    pub deadline: Time,
}

/// Why an item was refunded (log, fairness property TEST-P23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundReason {
    /// No proof given.
    NoEvidence,
    /// Commitment claimed but missing or too late.
    EvidenceNotFound,
    /// Recovery for an attempt that never started.
    AttemptNotStarted,
    /// Explicit arbitration decision.
    Arbitration,
    /// Default rule at the dispute deadline.
    DefaultRuling,
    /// The output was voided by a rewind (JOB-R29, JOB-R33).
    OutputVoided,
}

impl Evidence {
    /// Proof strength; a supplementary proof must be stronger (JOB-R35).
    pub fn rank(self) -> u8 {
        match self {
            Evidence::None => 0,
            Evidence::Uncommitted => 1,
            Evidence::Committed => 2,
        }
    }
}
