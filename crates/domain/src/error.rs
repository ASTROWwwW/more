use crate::ids::{JobId, SliceId};
use crate::model::{ExecStatus, SliceStatus};
use gpu_ledger::LedgerApiError;
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
    /// The caller may not send this command for this resource (SEC-001, SEC-003). Checked before
    /// any mutation.
    Unauthorized(&'static str),
    /// Malformed or out-of-bounds input.
    InvalidInput(&'static str),
    /// An amount, position or time would leave its range (SAFE-001).
    Overflow(&'static str),
    /// The ledger refused the operation.
    Ledger(LedgerApiError),
    /// The ledger runs in another process and the answer to a commit never came. The coordinator
    /// does not know whether its last command was applied there: it accepts nothing until it
    /// has asked (`Coordinator::resolve_commit`). It never sends the command again by itself.
    LedgerOutcomeUnknown,
    /// The ledger this coordinator was working with restarted, and with it lost its state. The
    /// coordinator's own state no longer matches any ledger: it stays stopped.
    LedgerStateLost,
    /// An internal invariant would break: a model bug, never expected.
    Internal(String),
}

impl From<LedgerApiError> for DomainError {
    fn from(e: LedgerApiError) -> Self {
        DomainError::Ledger(e)
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DomainError {}

impl DomainError {
    /// Stable code for every rejection (PROTO-004).
    pub fn code(&self) -> &'static str {
        match self {
            DomainError::UnknownJob(_) => "UNKNOWN_JOB",
            DomainError::UnknownSlice(_) => "UNKNOWN_SLICE",
            DomainError::UnknownPool => "UNKNOWN_POOL",
            DomainError::InvalidTransition { .. } => "INVALID_TRANSITION",
            DomainError::InvalidSliceTransition { .. } => "INVALID_SLICE_TRANSITION",
            DomainError::VersionConflict { .. } => "VERSION_CONFLICT",
            DomainError::StaleAttempt => "STALE_ATTEMPT",
            DomainError::JobSettling => "JOB_SETTLING",
            DomainError::FlowBudgetExceeded => "FLOW_BUDGET_EXCEEDED",
            DomainError::WindowNotCovered => "WINDOW_NOT_COVERED",
            DomainError::RecoveryBudget => "RECOVERY_BUDGET",
            DomainError::InadmissibleProof => "INADMISSIBLE_PROOF",
            DomainError::LeaseExpired => "LEASE_EXPIRED",
            DomainError::Precondition(_) => "PRECONDITION_FAILED",
            DomainError::Unauthorized(_) => "UNAUTHORIZED",
            DomainError::InvalidInput(_) => "INVALID_INPUT",
            DomainError::Overflow(_) => "ARITHMETIC_OVERFLOW",
            DomainError::Ledger(e) => e.code(),
            DomainError::LedgerOutcomeUnknown => "LEDGER_OUTCOME_UNKNOWN",
            DomainError::LedgerStateLost => "LEDGER_STATE_LOST",
            DomainError::Internal(_) => "INTERNAL",
        }
    }
}
