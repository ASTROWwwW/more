//! Requests, answers and errors of the Ledger API.

use std::fmt;

use more_identity::{AuthError, ServiceRole};

use crate::{Account, Amount, LedgerError};

pub use more_identity::{Assignment, JobTerms};

/// Bounds enforced on every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerLimits {
    /// Largest amount a single entry may move.
    pub max_amount: Amount,
    /// Largest single issuance.
    pub max_issue: Amount,
    /// Total credits that may ever be issued.
    pub supply_cap: Amount,
    /// Commission taken on release, in basis points (LEDGER-008). Set here so the orchestrator
    /// cannot change what lenders receive.
    pub commission_bps: u64,
    /// A paid item cannot be released before this long after its own payment: the least contest
    /// window a borrower always gets on every payment (JOB-R22).
    pub reward_hold: u64,
    /// A paid item cannot be contested later than this after its own payment: after it, that
    /// payment can only become final. Never below `reward_hold`, or an item could be stuck.
    pub contest_limit: u64,
    /// Most recovery segments a lender may commit to in one readiness.
    pub max_segments: usize,
}

impl LedgerLimits {
    /// A held payment must always have a way out: it is releasable from `reward_hold` and
    /// contestable until `contest_limit`, so the limit cannot come before the hold.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.contest_limit < self.reward_hold {
            return Err("contest limit shorter than the reward hold");
        }
        Ok(())
    }
}

impl Default for LedgerLimits {
    fn default() -> Self {
        LedgerLimits {
            max_amount: 1_000_000_000_000,
            max_issue: 1_000_000_000_000,
            supply_cap: 1_000_000_000_000_000,
            commission_bps: 1_000,
            reward_hold: 48 * 3600,
            contest_limit: 7 * 24 * 3600,
            max_segments: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowBucket {
    Work,
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTo {
    User(u32),
    Pool(u32),
}

/// Line `(job, attempt, slice, lender)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LineRef {
    pub job: u32,
    pub attempt: u32,
    pub slice: u32,
    pub lender: u32,
}

impl LineRef {
    pub fn line_account(self) -> Account {
        Account::SliceLine {
            job: self.job,
            attempt: self.attempt,
            slice: self.slice,
            lender: self.lender,
        }
    }

    pub fn reward_account(self) -> Account {
        Account::PendingReward {
            job: self.job,
            attempt: self.attempt,
            slice: self.slice,
            lender: self.lender,
        }
    }
}

/// Position `pos` of output type `wt` (0, 1 or 2) of a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputRef {
    pub wt: u8,
    pub pos: u32,
}

/// A line item, named by what it pays for. The Ledger records where its reserve came from; the
/// caller never says where a refund goes (LEDGER-013).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemId {
    /// Stage `stage`'s share of one charge (`gen`) of an output.
    Contribution {
        output: OutputRef,
        gen: u32,
        stage: u32,
    },
    /// Recompute of segment `segment` on a resumed attempt.
    Recovery { attempt: u32, segment: u32 },
}

/// Typed ledger operations. Amounts that follow from signed terms (prices, shares, pool shares)
/// are computed by the Ledger, never taken from the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerOp {
    /// Moves the ledger's clock forward. Clock service only: the orchestrator cannot open or
    /// close a contest window by lying about the time.
    Advance { now: u64 },
    /// LEDGER-003. Treasury only. `key` is the caller's idempotency key (LEDGER-001).
    Issue {
        key: String,
        to: IssueTo,
        amount: Amount,
    },
    /// Opens a job's escrow under the terms its owner signed (JOB-R37).
    OpenEscrow {
        job: u32,
        owner: u32,
        pool: u32,
        terms: JobTerms,
        signature: [u8; 64],
    },
    /// Owner's balance to the job escrow (JOB-T02, JOB-T12), within the signed budget.
    Reserve {
        job: u32,
        bucket: EscrowBucket,
        key: String,
        amount: Amount,
    },
    /// Records who administers a pool's treasury. Platform admin only, once per pool.
    RegisterPool { pool: u32, admin: u32 },
    /// Pool relay of the recovery budget (JOB-R18): the job's own pool only, up to the running
    /// total its admin signed (`relay_message`).
    FundRecovery {
        job: u32,
        amount: Amount,
        signature: [u8; 64],
    },
    /// Records an attempt as placed (LEDGER-015). Nothing can be reserved for it before its
    /// lenders sign it.
    RegisterAttempt { assignment: Assignment },
    /// Lender of `stage` signed the attempt's assignment (JOB-R38).
    AcceptLease {
        job: u32,
        attempt: u32,
        stage: u32,
        signature: [u8; 64],
    },
    /// Lender of `stage` signed that its state is restored to `restored` (JOB-T05).
    LeaseReady {
        job: u32,
        attempt: u32,
        stage: u32,
        restored: [u32; 3],
        /// Commitment to the restored state.
        state: u64,
        /// Commitment to each recovery segment the lender recomputed, by segment number.
        segments: Vec<u64>,
        signature: [u8; 64],
    },
    /// The recipient of `producer`'s output signed that it received `producer`'s restored state
    /// (JOB-R18, LEDGER-016).
    RecordRestore {
        job: u32,
        attempt: u32,
        producer: u32,
        /// The segments the recipient attests, each named, in increasing order. The ledger
        /// takes their commitments from the producer's signed readiness.
        segments: Vec<u32>,
        signature: [u8; 64],
    },
    /// The attempt is revoked: from this record on, no lease step and no corroboration is added
    /// to it (JOB-R18, CE-03). What was recorded before stays.
    RevokeAttempt { job: u32, attempt: u32 },
    /// Receipt signed by the recipient of `producer`'s output (LEDGER-016).
    RecordReceipt {
        job: u32,
        attempt: u32,
        producer: u32,
        wt: u8,
        upto: u32,
        digest: u64,
        signature: [u8; 64],
    },
    /// Work escrow to output hold, at the signed price (JOB-R23, JOB-R27, LEDGER-010).
    ChargeOutput {
        job: u32,
        attempt: u32,
        output: OutputRef,
        gen: u32,
    },
    /// Output hold back to work escrow (JOB-R29, LEDGER-010).
    VoidOutput {
        job: u32,
        output: OutputRef,
        gen: u32,
    },
    /// JOB-S03: output hold to the line of the stage's lender, for its share of the price.
    ReserveContribution {
        line: LineRef,
        output: OutputRef,
        gen: u32,
        stage: u32,
    },
    /// JOB-S03: recovery escrow to the line, within the attempt's earmark.
    ReserveRecovery {
        line: LineRef,
        segment: u32,
        amount: Amount,
    },
    /// JOB-S04: line reserve to held reward, with proof.
    PayLine { line: LineRef, item: ItemId },
    /// JOB-S04: line reserve back to where it came from.
    RefundLine { line: LineRef, item: ItemId },
    /// JOB-R22, LEDGER-008: the whole held reward to the lender of the line, minus commission.
    ReleaseReward { line: LineRef },
    /// JOB-R22: the whole held reward back to the job's pool (what it funded) and owner.
    ContestReward { line: LineRef },
    /// The attempt is over: its unspent earmark goes back to the job's recovery budget.
    ReturnEarmark { job: u32, attempt: u32 },
    /// JOB-S12: unspent pool relay to the pool, everything else to the owner (LEDGER-014).
    SettleJob { job: u32 },
}

impl LedgerOp {
    pub fn kind(&self) -> &'static str {
        match self {
            LedgerOp::Advance { .. } => "Advance",
            LedgerOp::Issue { .. } => "Issue",
            LedgerOp::OpenEscrow { .. } => "OpenEscrow",
            LedgerOp::Reserve { .. } => "Reserve",
            LedgerOp::RegisterPool { .. } => "RegisterPool",
            LedgerOp::FundRecovery { .. } => "FundRecovery",
            LedgerOp::RegisterAttempt { .. } => "RegisterAttempt",
            LedgerOp::AcceptLease { .. } => "AcceptLease",
            LedgerOp::LeaseReady { .. } => "LeaseReady",
            LedgerOp::RecordRestore { .. } => "RecordRestore",
            LedgerOp::RevokeAttempt { .. } => "RevokeAttempt",
            LedgerOp::RecordReceipt { .. } => "RecordReceipt",
            LedgerOp::ChargeOutput { .. } => "ChargeOutput",
            LedgerOp::VoidOutput { .. } => "VoidOutput",
            LedgerOp::ReserveContribution { .. } => "ReserveContribution",
            LedgerOp::ReserveRecovery { .. } => "ReserveRecovery",
            LedgerOp::PayLine { .. } => "PayLine",
            LedgerOp::RefundLine { .. } => "RefundLine",
            LedgerOp::ReleaseReward { .. } => "ReleaseReward",
            LedgerOp::ContestReward { .. } => "ContestReward",
            LedgerOp::ReturnEarmark { .. } => "ReturnEarmark",
            LedgerOp::SettleJob { .. } => "SettleJob",
        }
    }

    /// Permission matrix: the one role allowed to request each operation.
    pub(crate) fn required_role(&self) -> ServiceRole {
        match self {
            LedgerOp::Issue { .. } => ServiceRole::Treasury,
            LedgerOp::Advance { .. } => ServiceRole::Clock,
            LedgerOp::RegisterPool { .. } => ServiceRole::PlatformAdmin,
            _ => ServiceRole::Orchestrator,
        }
    }
}

/// What an accepted operation did, when the caller needs the amounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerOutcome {
    Done,
    /// Amount moved by a charge, a void, a reservation or a refund.
    Moved(Amount),
    /// A line item was paid; `pool_part` of it came from the pool's relay.
    Paid {
        amount: Amount,
        pool_part: Amount,
    },
    Released {
        to_lender: Amount,
        commission: Amount,
    },
    Contested {
        to_pool: Amount,
        to_owner: Amount,
    },
    Settled {
        to_pool: Amount,
        to_owner: Amount,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerApiError {
    /// The credential is not valid or was revoked.
    Unauthenticated(AuthError),
    /// The caller's role may not request this operation or read this data.
    Forbidden {
        role: ServiceRole,
        op: &'static str,
    },
    UnknownEscrow(u32),
    EscrowExists(u32),
    EscrowSettled(u32),
    /// The mandate signature does not verify against the owner's registered key.
    BadMandate,
    /// The owner never agreed to lock that much for this job.
    MandateExceeded {
        job: u32,
        mandate: Amount,
        requested_total: u128,
    },
    /// A lease, readiness or receipt signature is missing, wrong, or from the wrong account
    /// (LEDGER-015, LEDGER-016).
    BadProof(&'static str),
    /// A held reward released before the contest window is over, or contested after the limit
    /// (JOB-R22, LEDGER-018).
    OutOfWindow(&'static str),
    /// The job still has undecided line items (LEDGER-014).
    OpenItems(u32),
    LimitExceeded(&'static str),
    Invalid(&'static str),
    Ledger(LedgerError),
    /// The ledger runs in another process and could not be reached, or the link to it failed.
    /// Nothing is known about the operation: it may or may not have been applied.
    Unavailable(&'static str),
}

impl LedgerApiError {
    pub fn code(&self) -> &'static str {
        match self {
            LedgerApiError::Unauthenticated(_) => "UNAUTHENTICATED",
            LedgerApiError::Forbidden { .. } => "FORBIDDEN",
            LedgerApiError::LimitExceeded(_) => "LIMIT_EXCEEDED",
            LedgerApiError::BadProof(_) => "BAD_PROOF",
            LedgerApiError::OutOfWindow(_) => "OUT_OF_WINDOW",
            LedgerApiError::Unavailable(_) => "LEDGER_UNAVAILABLE",
            _ => "LEDGER_REJECTED",
        }
    }
}

impl From<LedgerError> for LedgerApiError {
    fn from(e: LedgerError) -> Self {
        LedgerApiError::Ledger(e)
    }
}

impl fmt::Display for LedgerApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerApiError {}

/// A refused request, kept for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub caller: Option<ServiceRole>,
    pub op: &'static str,
    pub error: LedgerApiError,
}
