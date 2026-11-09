use crate::ids::{JobId, SliceId};
use crate::model::{ExecStatus, SliceStatus};
use gpu_ledger::LedgerError;
use std::fmt;

/// Refus d'une commande. Un refus ne modifie jamais l'état (JOB-R01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    UnknownJob(JobId),
    UnknownSlice(SliceId),
    UnknownPool,
    /// Transition non listée : interdite (section 2).
    InvalidTransition {
        from: ExecStatus,
        rule: &'static str,
    },
    InvalidSliceTransition {
        from: SliceStatus,
        rule: &'static str,
    },
    /// Verrou optimiste (JOB-R03).
    VersionConflict {
        expected: u64,
        actual: u64,
    },
    /// Message d'une tentative non courante ou révoquée (JOB-R05, JOB-R11).
    StaleAttempt,
    /// Annulation ou échec demandés en `settling` (JOB-T15, JOB-T16).
    JobSettling,
    /// Budget de flux dépassé (JOB-R13).
    FlowBudgetExceeded,
    /// Escrow insuffisant pour couvrir la fenêtre non validée (JOB-R25).
    WindowNotCovered,
    /// Budget de récupération insuffisant (JOB-R18).
    RecoveryBudget,
    /// Preuve non recevable : attestation d'un autre que le témoin assigné (JOB-R26).
    InadmissibleProof,
    /// Autorisation expirée (JOB-R31).
    LeaseExpired,
    Precondition(&'static str),
    Ledger(LedgerError),
    /// Un invariant interne serait violé : bug du modèle, jamais attendu.
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
