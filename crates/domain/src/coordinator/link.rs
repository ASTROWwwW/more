//! Where the coordinator's ledger lives: in this process (the executable model and its property
//! tests) or in a process of its own, behind the ledger link.
//!
//! In its own process the ledger only accepts, from the coordinator, the orchestrator's
//! operations: the coordinator holds no other service's key, so it cannot forward an issuance or
//! a clock tick any more. Those services talk to the ledger themselves.

use std::fmt;
use std::sync::{Arc, Mutex};

use gpu_ledger::link::{CommitFailure, LedgerInfo, RemoteLedger, TxId, TxState};
use gpu_ledger::{
    Account, Amount, LedgerApiError, LedgerLimits, LedgerOp, LedgerOutcome, LedgerService,
};
use more_identity::{Domain, ServiceCredential};

type Port = Arc<Mutex<dyn RemoteLedger>>;

/// The orchestrator's side of a ledger in another process.
#[derive(Clone)]
pub(super) struct Remote {
    /// The orchestrator's authenticated connection.
    port: Port,
    /// What the ledger said of itself when the connection was set up.
    info: LedgerInfo,
    /// This orchestrator instance, in the names of its transactions.
    node: u64,
    /// Transactions named so far. It only grows: a name is never used twice, whatever became
    /// of the command it was opened for.
    counter: u64,
    /// The transaction open at the ledger for the command being applied, and how many are
    /// nested in it.
    open: Option<TxId>,
    depth: u32,
}

// One per coordinator. Boxing the in-process ledger would add an allocation to every copy of the
// state, which the model makes for each command.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(super) enum LedgerLink {
    Local(LedgerService),
    Remote(Remote),
}

impl fmt::Debug for LedgerLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerLink::Local(s) => s.fmt(f),
            LedgerLink::Remote(r) => write!(f, "RemoteLedger(node {}, tx {})", r.node, r.counter),
        }
    }
}

impl PartialEq for LedgerLink {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LedgerLink::Local(a), LedgerLink::Local(b)) => a == b,
            (LedgerLink::Remote(a), LedgerLink::Remote(b)) => Arc::ptr_eq(&a.port, &b.port),
            _ => false,
        }
    }
}

impl Eq for LedgerLink {}

/// How the commit of a command's transaction ended.
pub(super) enum Committed {
    Yes,
    /// The ledger says it did not commit.
    No(LedgerApiError),
    /// No answer, and the ledger could not be asked: the outcome of this transaction is unknown.
    Unknown(TxId),
}

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
    pub(super) fn remote(port: Port, info: LedgerInfo, node: u64) -> Self {
        LedgerLink::Remote(Remote {
            port,
            info,
            node,
            counter: 0,
            open: None,
            depth: 0,
        })
    }

    pub(super) fn limits(&self) -> &LedgerLimits {
        match self {
            LedgerLink::Local(s) => s.limits(),
            LedgerLink::Remote(r) => &r.info.limits,
        }
    }

    pub(super) fn domain(&self) -> Domain {
        match self {
            LedgerLink::Local(s) => s.domain(),
            LedgerLink::Remote(r) => r.info.domain,
        }
    }

    /// The incarnation of the ledger this coordinator started on, when it is another process.
    pub(super) fn incarnation(&self) -> Option<u64> {
        match self {
            LedgerLink::Local(_) => None,
            LedgerLink::Remote(r) => Some(r.info.incarnation),
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

    /// Takes a new connection to the ledger, after the old one failed, and returns the
    /// incarnation of the ledger at its other end. That is asked with the one question a ledger
    /// answers whatever it is doing; a connection that does not answer it is not taken.
    pub(super) fn reconnect(&mut self, port: Port) -> Result<u64, LedgerApiError> {
        let LedgerLink::Remote(r) = self else {
            return Err(LedgerApiError::Invalid("the ledger is in this process"));
        };
        let any = TxId {
            node: r.node,
            counter: r.counter,
        };
        let (_, incarnation) = with(&port, |p| p.status(any))?;
        r.port = port;
        r.open = None;
        r.depth = 0;
        Ok(incarnation)
    }

    /// The same connection for a copy of the state kept aside. Nothing is open on it.
    pub(super) fn replace(&mut self, port: Port) {
        if let LedgerLink::Remote(r) = self {
            r.port = port;
            r.open = None;
            r.depth = 0;
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
            LedgerLink::Remote(r) => with(&r.port, |p| p.execute(op)),
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
            LedgerLink::Remote(r) => with(&r.port, |p| p.balance(account)),
        }
    }

    /// JOB-R01 across two processes: what the coordinator sends between `begin` and `commit`
    /// is applied by the ledger entirely or not at all. The first `begin` of a command opens a
    /// transaction under a new name; a `begin` inside it (reconciliation applies its
    /// transitions one by one) opens a nested one. In one process the coordinator's own copy
    /// of the state does all that, and these do nothing.
    pub(super) fn begin(&mut self) -> Result<(), LedgerApiError> {
        let LedgerLink::Remote(r) = self else {
            return Ok(());
        };
        if r.depth == 0 {
            // The name is spent even if the ledger never hears of it.
            r.counter = r
                .counter
                .checked_add(1)
                .ok_or(LedgerApiError::Unavailable("transaction names exhausted"))?;
            let id = TxId {
                node: r.node,
                counter: r.counter,
            };
            with(&r.port, |p| p.begin(id))?;
            r.open = Some(id);
        } else {
            with(&r.port, |p| p.savepoint())?;
        }
        r.depth += 1;
        Ok(())
    }

    /// Closes the innermost transaction, keeping it.
    pub(super) fn commit(&mut self) -> Committed {
        let LedgerLink::Remote(r) = self else {
            return Committed::Yes;
        };
        let Some(left) = r.depth.checked_sub(1) else {
            return Committed::No(LedgerApiError::Unavailable("no transaction to commit"));
        };
        let outermost = left == 0;
        r.depth = left;
        let result = match r.port.lock() {
            Ok(mut p) => p.commit(),
            Err(_) => Err(CommitFailure::Unknown),
        };
        let id = if outermost { r.open.take() } else { r.open };
        match (result, id) {
            (Ok(()), _) => Committed::Yes,
            (Err(CommitFailure::NotApplied(e)), _) => Committed::No(e),
            // A nested commit that got no answer: the transaction around it is still open or
            // gone with the connection, never committed. The command fails as a whole.
            (Err(CommitFailure::Unknown), Some(id)) if outermost => Committed::Unknown(id),
            (Err(CommitFailure::Unknown), _) => {
                Committed::No(LedgerApiError::Unavailable("the link to the ledger failed"))
            }
        }
    }

    /// Closes the innermost transaction, undoing it.
    pub(super) fn abort(&mut self) -> Result<(), LedgerApiError> {
        let LedgerLink::Remote(r) = self else {
            return Ok(());
        };
        let Some(left) = r.depth.checked_sub(1) else {
            return Err(LedgerApiError::Unavailable("no transaction to abort"));
        };
        if left == 0 {
            r.open = None;
        }
        r.depth = left;
        with(&r.port, |p| p.abort())
    }

    /// Asks the ledger what became of a transaction.
    pub(super) fn status(&self, id: TxId) -> Result<(TxState, u64), LedgerApiError> {
        match self {
            LedgerLink::Local(_) => Err(LedgerApiError::Invalid("the ledger is in this process")),
            LedgerLink::Remote(r) => with(&r.port, |p| p.status(id)),
        }
    }
}
