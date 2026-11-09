use crate::ids::{JobId, SliceId};
use crate::model::{ExecStatus, SliceStatus};
use gpu_ledger::LedgerError;
use std::fmt;

/// A rejected command. A rejection never changes state (JOB-R01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    UnknownJob(JobId),
    UnknownSlice(SliceId),
    UnknownPool,
    /// Transition not in the table, hence forbidden (section 2).
    InvalidTransition {
        from: ExecStatus,
        rule: &'static str,
    },
    InvalidSliceTransition {
        from: SliceStatus,
        rule: &'static str,
    },
    /// Optimistic lock (JOB-R03).
    VersionConflict {
        expected: u64,
        actual: u64,
    },
    /// Message from a non-current or revoked attempt (JOB-R05, JOB-R11).
    StaleAttempt,
    /// Cancel or fail requested while `settling` (JOB-T15, JOB-T16).
    JobSettling,
    /// Flow budget exceeded (JOB-R13).
    FlowBudgetExceeded,
    /// Escrow cannot cover the unbilled window (JOB-R25).
    WindowNotCovered,
    /// Recovery budget exhausted (JOB-R18).
    RecoveryBudget,
    /// Inadmissible proof: not signed by the assigned witness, or wrong frame digest (JOB-R26,
    /// JOB-R34).
    InadmissibleProof,
    /// Lease expired (JOB-R31).
    LeaseExpired,
    Precondition(&'static str),
    Ledger(LedgerError),
    /// An internal invariant would break: a model bug, never expected.
    Internal(String),
}

impl From<LedgerError> for DomainError {
    fn from(e: LedgerError) -> Self {
        DomainError::Ledger(e)
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DomainError {}
