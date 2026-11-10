//! Where the coordinator's ledger lives: in this process (the executable model and its property
//! tests) or in a process of its own, behind the ledger link.
//!
//! In its own process the ledger only accepts, from the coordinator, the orchestrator's
//! operations: the coordinator holds no other service's key, so it cannot forward an issuance or
//! a clock tick any more. Those services talk to the ledger themselves.

use std::fmt;
use std::sync::{Arc, Mutex};

use gpu_ledger::link::{LedgerInfo, RemoteLedger};
use gpu_ledger::{
    Account, Amount, LedgerApiError, LedgerLimits, LedgerOp, LedgerOutcome, LedgerService,
};
use more_identity::{Domain, ServiceCredential};

type Port = Arc<Mutex<dyn RemoteLedger>>;

// One per coordinator. Boxing the in-process ledger would add an allocation to every copy of the
// state, which the model makes for each command.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(super) enum LedgerLink {
    Local(LedgerService),
    /// The orchestrator's authenticated connection, and what the ledger said of itself when the
    /// coordinator started.
    Remote(Port, LedgerInfo),
}

impl fmt::Debug for LedgerLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerLink::Local(s) => s.fmt(f),
            LedgerLink::Remote(..) => f.write_str("RemoteLedger"),
        }
    }
}

impl PartialEq for LedgerLink {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LedgerLink::Local(a), LedgerLink::Local(b)) => a == b,
            (LedgerLink::Remote(a, _), LedgerLink::Remote(b, _)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Eq for LedgerLink {}

fn with<V>(
    port: &Port,
    f: impl FnOnce(&mut dyn RemoteLedger) -> Result<V, LedgerApiError>,
) -> Result<V, LedgerApiError> {
    // A poisoned lock means a panic in the middle of a call: the link is not to be trusted.
    match port.lock() {
        Ok(mut p) => f(&mut *p),
        Err(_) => Err(LedgerApiError::Unavailable("the link to the ledger failed")),
    }
}

impl LedgerLink {
    pub(super) fn limits(&self) -> &LedgerLimits {
        match self {
            LedgerLink::Local(s) => s.limits(),
            LedgerLink::Remote(_, info) => &info.limits,
        }
    }

    pub(super) fn domain(&self) -> Domain {
        match self {
            LedgerLink::Local(s) => s.domain(),
            LedgerLink::Remote(_, info) => info.domain,
        }
    }

    pub(super) fn local(&self) -> Option<&LedgerService> {
        match self {
            LedgerLink::Local(s) => Some(s),
            LedgerLink::Remote(..) => None,
        }
    }

    #[cfg(feature = "fault-injection")]
    pub(super) fn local_mut(&mut self) -> Option<&mut LedgerService> {
        match self {
            LedgerLink::Local(s) => Some(s),
            LedgerLink::Remote(..) => None,
        }
    }

    /// One of the orchestrator's own operations.
    pub(super) fn execute(
        &mut self,
        me: &ServiceCredential,
        op: LedgerOp,
    ) -> Result<LedgerOutcome, LedgerApiError> {
        match self {
            LedgerLink::Local(s) => s.execute(me, op),
            LedgerLink::Remote(port, _) => with(port, |p| p.execute(op)),
        }
    }

    /// An operation that belongs to another service (clock, treasury, platform admin), carried
    /// with that service's credential. `None`: the ledger is in its own process and that
    /// service sends the operation there itself.
    pub(super) fn forward(
        &mut self,
        owner: &ServiceCredential,
        op: LedgerOp,
    ) -> Option<Result<LedgerOutcome, LedgerApiError>> {
        match self {
            LedgerLink::Local(s) => Some(s.execute(owner, op)),
            LedgerLink::Remote(..) => None,
        }
    }

    pub(super) fn job_balance(
        &self,
        me: &ServiceCredential,
        account: Account,
    ) -> Result<Amount, LedgerApiError> {
        match self {
            LedgerLink::Local(s) => s.job_balance(me, account),
            LedgerLink::Remote(port, _) => with(port, |p| p.balance(account)),
        }
    }

    /// JOB-R01 across two processes: what the coordinator sends between `begin` and `commit`
    /// is applied by the ledger entirely or not at all. In one process the coordinator's own
    /// copy of the state does that, and these do nothing.
    pub(super) fn begin(&mut self) -> Result<(), LedgerApiError> {
        match self {
            LedgerLink::Local(_) => Ok(()),
            LedgerLink::Remote(port, _) => with(port, |p| p.begin()),
        }
    }

    pub(super) fn commit(&mut self) -> Result<(), LedgerApiError> {
        match self {
            LedgerLink::Local(_) => Ok(()),
            LedgerLink::Remote(port, _) => with(port, |p| p.commit()),
        }
    }

    pub(super) fn abort(&mut self) -> Result<(), LedgerApiError> {
        match self {
            LedgerLink::Local(_) => Ok(()),
            LedgerLink::Remote(port, _) => with(port, |p| p.abort()),
        }
    }
}
