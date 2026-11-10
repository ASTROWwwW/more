//! The ledger's side of the link, without any I/O: one call per received payload, one payload
//! back. A daemon feeds it from a socket; tests feed it directly.
//!
//! A connection is nothing until its peer has shown a certificate signed by the authority and
//! proved it holds the certified key, over nonces both sides chose. After that every request
//! runs as that service and no other: there is no field in a request to say who is asking.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use more_identity::{
    CredentialVerifier, KeyDirectory, ServiceCertificate, ServiceCredential, ServiceId, ServiceRole,
};

use super::wire::{
    transcript, Fault, LedgerInfo, LedgerSummary, Message, Refusal, Request, Response, Rollback,
    TxId, TxState, LINK_VERSION,
};
use crate::service::{LedgerApiError, LedgerService};

/// What the host needs from the outside world.
pub trait HostEnv {
    /// Monotonic time in milliseconds, for transaction deadlines only.
    fn now_ms(&mut self) -> u64;
    /// A fresh, unpredictable nonce.
    fn nonce(&mut self) -> [u8; 32];
}

/// Bounds on what one connection can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLimits {
    /// Most operations in one transaction, nested ones included.
    pub max_tx_ops: u32,
    /// Most transactions nested in one another.
    pub max_tx_depth: usize,
    /// A transaction older than this is rolled back: at its owner's next request, at anyone
    /// else's, or by `sweep`. Counted from the outermost `Begin`.
    pub tx_timeout_ms: u64,
    /// How many finished transactions the ledger remembers the outcome of.
    pub tx_log: usize,
}

impl Default for HostLimits {
    fn default() -> Self {
        HostLimits {
            max_tx_ops: 4096,
            max_tx_depth: 4,
            tx_timeout_ms: 5_000,
            tx_log: 1024,
        }
    }
}

enum State {
    New,
    /// Certificate checked; waiting for the proof that the peer holds its key.
    Challenged {
        cert: ServiceCertificate,
        expected: Vec<u8>,
    },
    Ready(ServiceCertificate),
    Closed,
}

/// One connection, as the host sees it.
pub struct Conn {
    id: u64,
    state: State,
    seq: u64,
}

impl Conn {
    /// The service this connection authenticated as, if it did.
    pub fn peer(&self) -> Option<ServiceCertificate> {
        match &self.state {
            State::Ready(cert) => Some(*cert),
            _ => None,
        }
    }
}

/// The payload to send back, and whether the connection ends after it.
pub struct Reply {
    pub frame: Vec<u8>,
    pub close: bool,
}

struct Tx {
    conn: u64,
    id: TxId,
    /// The ledger as it was at `Begin` and at each `Savepoint` still open, outermost first.
    /// Never empty.
    snapshots: Vec<LedgerService>,
    ops: u32,
    opened_ms: u64,
}

pub struct LedgerHost {
    service: LedgerService,
    keys: KeyDirectory,
    verifier: CredentialVerifier,
    identity: ServiceCredential,
    limits: HostLimits,
    incarnation: u64,
    tx: Option<Tx>,
    /// What became of the last transactions, by name, oldest first in `order`.
    outcomes: BTreeMap<TxId, TxState>,
    order: VecDeque<TxId>,
    /// Connections whose transaction the host rolled back behind their back. Their next request
    /// is refused, so that what they meant for the transaction is never applied outside it.
    expired: BTreeSet<u64>,
    next_conn: u64,
}

impl LedgerHost {
    /// `keys` must be the directory `service` verifies statements with, and `identity` a
    /// credential of role `Ledger` from the same authority as `verifier`. `incarnation` is
    /// drawn afresh each time the ledger starts.
    pub fn new(
        service: LedgerService,
        keys: KeyDirectory,
        verifier: CredentialVerifier,
        identity: ServiceCredential,
        limits: HostLimits,
        incarnation: u64,
    ) -> Result<Self, &'static str> {
        if verifier.verify(&identity) != Ok(ServiceRole::Ledger) {
            return Err("the host needs a valid credential of role Ledger");
        }
        if verifier.domain() != service.domain() {
            return Err("verifier and ledger of different deployments");
        }
        service.limits().validate()?;
        Ok(LedgerHost {
            service,
            keys,
            verifier,
            identity,
            limits,
            incarnation,
            tx: None,
            outcomes: BTreeMap::new(),
            order: VecDeque::new(),
            expired: BTreeSet::new(),
            next_conn: 0,
        })
    }

    /// The ledger behind the link, for the process that hosts it.
    pub fn service(&self) -> &LedgerService {
        &self.service
    }

    /// Connections the host still has something to say to, and outcomes it remembers: what a
    /// test checks to see that nothing is kept for ever.
    pub fn retained(&self) -> (usize, usize) {
        (self.expired.len(), self.outcomes.len())
    }

    pub fn open(&mut self) -> Conn {
        self.next_conn += 1;
        Conn {
            id: self.next_conn,
            state: State::New,
            seq: 0,
        }
    }

    /// The connection is gone: what it left uncommitted is rolled back, and nothing is kept
    /// about it.
    pub fn close(&mut self, conn: &mut Conn) {
        conn.state = State::Closed;
        self.expired.remove(&conn.id);
        if self.tx.as_ref().is_some_and(|tx| tx.conn == conn.id) {
            self.rollback(Rollback::Disconnected);
        }
    }

    /// Rolls back a transaction that outlived its deadline, whoever is or is not asking. A
    /// daemon calls it on a timer, so that an idle transaction does not hold the ledger until
    /// someone else shows up. Returns whether one was rolled back.
    pub fn sweep(&mut self, now_ms: u64) -> bool {
        let Some(tx) = self.tx.as_ref() else {
            return false;
        };
        // A clock that went back proves nothing: the transaction is kept.
        let age = now_ms.checked_sub(tx.opened_ms);
        if age.is_none_or(|a| a < self.limits.tx_timeout_ms) {
            return false;
        }
        self.expired.insert(tx.conn);
        self.rollback(Rollback::Expired);
        true
    }

    /// Remembers what became of a transaction, forgetting the oldest past the limit.
    fn record(&mut self, id: TxId, state: TxState) {
        if self.outcomes.insert(id, state).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > self.limits.tx_log {
            if let Some(old) = self.order.pop_front() {
                self.outcomes.remove(&old);
            }
        }
    }

    /// Undoes the whole transaction, nested ones included.
    fn rollback(&mut self, why: Rollback) {
        let Some(tx) = self.tx.take() else { return };
        let id = tx.id;
        if let Some(first) = tx.snapshots.into_iter().next() {
            self.service = first;
        }
        self.record(id, TxState::RolledBack(why));
    }

    /// Closes the innermost transaction, keeping what it did or undoing it.
    fn end(&mut self, keep: bool) -> Response {
        let Some(tx) = self.tx.as_mut() else {
            return Response::Refused(Refusal::NoTransaction);
        };
        let id = tx.id;
        let inner = tx.snapshots.pop();
        let outermost = tx.snapshots.is_empty();
        if outermost {
            self.tx = None;
        }
        match inner {
            Some(before) if !keep => self.service = before,
            _ => {}
        }
        if outermost {
            let state = if keep {
                TxState::Committed {
                    seq: self.service.seq(),
                }
            } else {
                TxState::RolledBack(Rollback::Asked)
            };
            self.record(id, state);
        }
        Response::Done
    }

    fn fault(&mut self, conn: &mut Conn, fault: Fault) -> Reply {
        self.close(conn);
        Reply {
            frame: Message::Fault(fault).encode(),
            close: true,
        }
    }

    pub fn handle(&mut self, conn: &mut Conn, frame: &[u8], env: &mut dyn HostEnv) -> Reply {
        let Ok(msg) = Message::decode(frame) else {
            return self.fault(conn, Fault::Malformed);
        };
        let reply = match (std::mem::replace(&mut conn.state, State::Closed), msg) {
            (
                State::New,
                Message::Hello {
                    version,
                    domain,
                    cert,
                    nonce,
                },
            ) => {
                if version != LINK_VERSION {
                    return self.fault(conn, Fault::UnsupportedVersion);
                }
                if domain != self.service.domain() {
                    return self.fault(conn, Fault::WrongDeployment);
                }
                if self.verifier.verify_certificate(&cert).is_err() {
                    return self.fault(conn, Fault::Unauthenticated);
                }
                let mine = self.identity.certificate();
                let ours = env.nonce();
                let sign = |server| transcript(server, &domain, &cert, &mine, &nonce, &ours);
                let signature = self.identity.sign(&sign(true));
                conn.state = State::Challenged {
                    cert,
                    expected: sign(false),
                };
                Message::Challenge {
                    cert: mine,
                    nonce: ours,
                    signature,
                }
            }
            (State::Challenged { cert, expected }, Message::Proof { signature }) => {
                // The certificate is public. Only this signature shows the peer holds its key.
                if cert.verify(&expected, &signature).is_err() {
                    return self.fault(conn, Fault::Unauthenticated);
                }
                conn.state = State::Ready(cert);
                Message::Ready
            }
            (State::Ready(cert), Message::Request { seq, body }) => {
                if conn.seq.checked_add(1) != Some(seq) {
                    return self.fault(conn, Fault::OutOfOrder);
                }
                conn.seq = seq;
                // A revocation takes effect on the next request, not on the next connection.
                if self.verifier.verify_certificate(&cert).is_err() {
                    return self.fault(conn, Fault::Unauthenticated);
                }
                conn.state = State::Ready(cert);
                let body = self.request(conn.id, &cert, body, env.now_ms());
                Message::Response { seq, body }
            }
            _ => return self.fault(conn, Fault::OutOfOrder),
        };
        Reply {
            frame: reply.encode(),
            close: false,
        }
    }

    fn request(
        &mut self,
        conn: u64,
        cert: &ServiceCertificate,
        body: Request,
        now_ms: u64,
    ) -> Response {
        let role = cert.role();
        let forbidden = |op| Response::Denied(LedgerApiError::Forbidden { role, op });
        let denied = |e| Response::Denied(e);
        // A deadline binds its owner as much as the others, and is checked on every request.
        self.sweep(now_ms);
        // The one question that is answered whatever the ledger is doing: it reads the outcome
        // log, never uncommitted state.
        if let Request::TxStatus { id } = body {
            if role != ServiceRole::Orchestrator {
                return forbidden("TxStatus");
            }
            let open = self.tx.as_ref().is_some_and(|tx| tx.id == id);
            let state = match self.outcomes.get(&id) {
                _ if open => TxState::Open,
                Some(known) => *known,
                None => TxState::Unknown,
            };
            return Response::Tx {
                state,
                incarnation: self.incarnation,
            };
        }
        // The host rolled this connection's transaction back. Whatever it sends next was meant
        // for that transaction: it is refused, once, so the client learns of it.
        if self.expired.remove(&conn) {
            return Response::Refused(Refusal::TransactionExpired);
        }
        // Someone else's open transaction: its uncommitted state is nobody's business.
        if self.tx.as_ref().is_some_and(|tx| tx.conn != conn) {
            return Response::Refused(Refusal::Busy);
        }
        match body {
            Request::TxStatus { .. } => Response::Refused(Refusal::NoTransaction),
            Request::Execute(op) => {
                if let Some(tx) = self.tx.as_mut() {
                    tx.ops += 1;
                    if tx.ops > self.limits.max_tx_ops {
                        self.rollback(Rollback::TooLarge);
                        return Response::Refused(Refusal::TransactionTooLarge);
                    }
                }
                match self.service.execute_as(cert, op) {
                    Ok(out) => Response::Outcome(out),
                    Err(e) => denied(e),
                }
            }
            Request::Begin { .. } | Request::Savepoint if role != ServiceRole::Orchestrator => {
                forbidden("Begin")
            }
            Request::Begin { .. } if self.tx.is_some() => {
                Response::Refused(Refusal::TransactionOpen)
            }
            // A name is used once. Committed or not, the transaction is never run again.
            Request::Begin { id } if self.outcomes.contains_key(&id) => {
                Response::Refused(Refusal::TransactionKnown)
            }
            Request::Begin { id } => {
                self.tx = Some(Tx {
                    conn,
                    id,
                    snapshots: vec![self.service.clone()],
                    ops: 0,
                    opened_ms: now_ms,
                });
                Response::Done
            }
            Request::Savepoint => {
                let now = self.service.clone();
                match self.tx.as_mut() {
                    None => Response::Refused(Refusal::NoTransaction),
                    Some(tx) if tx.snapshots.len() >= self.limits.max_tx_depth => {
                        Response::Refused(Refusal::TransactionTooDeep)
                    }
                    Some(tx) => {
                        tx.snapshots.push(now);
                        Response::Done
                    }
                }
            }
            Request::Commit => self.end(true),
            Request::Abort => self.end(false),
            Request::Info => Response::Info(LedgerInfo {
                limits: self.service.limits().clone(),
                domain: self.service.domain(),
                incarnation: self.incarnation,
                now: self.service.now(),
                seq: self.service.seq(),
            }),
            Request::Balance(account) => match self.service.job_balance_as(cert, account) {
                Ok(amount) => Response::Balance(amount),
                Err(e) => denied(e),
            },
            Request::AuditBalances => match self.service.audit_view_as(cert) {
                Ok(l) => Response::Balances(l.accounts().map(|(a, b)| (*a, *b)).collect()),
                Err(e) => denied(e),
            },
            Request::AuditSummary => match self.service.audit_view_as(cert) {
                Ok(l) => Response::Summary(LedgerSummary {
                    entries: l.entries().len() as u64,
                    head: l.entries().last().map_or(0, |e| e.hash),
                    seq: self.service.seq(),
                    now: self.service.now(),
                    denied: self.service.denied(),
                }),
                Err(e) => denied(e),
            },
            Request::RegisterKey { .. } if role != ServiceRole::Identity => {
                forbidden("RegisterKey")
            }
            Request::RegisterKey { account, key } => {
                match self.keys.register_bytes(account, &key) {
                    Ok(()) => Response::Done,
                    Err(e) => denied(LedgerApiError::Unauthenticated(e)),
                }
            }
            Request::Revoke { service, signature } => {
                match self
                    .verifier
                    .apply_revocation(ServiceId(service), &signature)
                {
                    Ok(()) => Response::Done,
                    Err(e) => denied(LedgerApiError::Unauthenticated(e)),
                }
            }
        }
    }
}
