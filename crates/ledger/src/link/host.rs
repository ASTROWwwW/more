//! The ledger's side of the link, without any I/O: one call per received payload, one payload
//! back. A daemon feeds it from a socket; tests feed it directly.
//!
//! A connection is nothing until its peer has shown a certificate signed by the authority and
//! proved it holds the certified key, over nonces both sides chose. After that every request
//! runs as that service and no other: there is no field in a request to say who is asking.

use more_identity::{
    CredentialVerifier, KeyDirectory, ServiceCertificate, ServiceCredential, ServiceId, ServiceRole,
};

use super::wire::{
    transcript, Fault, LedgerInfo, LedgerSummary, Message, Refusal, Request, Response, LINK_VERSION,
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
    /// A transaction older than this is rolled back as soon as another connection needs the
    /// ledger.
    pub tx_timeout_ms: u64,
}

impl Default for HostLimits {
    fn default() -> Self {
        HostLimits {
            max_tx_ops: 4096,
            max_tx_depth: 4,
            tx_timeout_ms: 5_000,
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
    /// The ledger as it was at each `Begin` still open, outermost first. Never empty.
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
    tx: Option<Tx>,
    next_conn: u64,
}

impl LedgerHost {
    /// `keys` must be the directory `service` verifies statements with, and `identity` a
    /// credential of role `Ledger` from the same authority as `verifier`.
    pub fn new(
        service: LedgerService,
        keys: KeyDirectory,
        verifier: CredentialVerifier,
        identity: ServiceCredential,
        limits: HostLimits,
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
            tx: None,
            next_conn: 0,
        })
    }

    /// The ledger behind the link, for the process that hosts it.
    pub fn service(&self) -> &LedgerService {
        &self.service
    }

    pub fn open(&mut self) -> Conn {
        self.next_conn += 1;
        Conn {
            id: self.next_conn,
            state: State::New,
            seq: 0,
        }
    }

    /// The connection is gone: what it left uncommitted is rolled back.
    pub fn close(&mut self, conn: &mut Conn) {
        conn.state = State::Closed;
        if self.tx.as_ref().is_some_and(|tx| tx.conn == conn.id) {
            self.rollback();
        }
    }

    /// Undoes the whole transaction, nested ones included.
    fn rollback(&mut self) {
        if let Some(first) = self
            .tx
            .take()
            .and_then(|tx| tx.snapshots.into_iter().next())
        {
            self.service = first;
        }
    }

    /// Closes the innermost transaction, keeping what it did or undoing it.
    fn end(&mut self, keep: bool) -> Response {
        let Some(tx) = self.tx.as_mut() else {
            return Response::Refused(Refusal::NoTransaction);
        };
        let inner = tx.snapshots.pop();
        if tx.snapshots.is_empty() {
            self.tx = None;
        }
        match inner {
            Some(before) if !keep => self.service = before,
            _ => {}
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
        // Someone else's open transaction: its uncommitted state is nobody's business. Wait, or
        // roll it back if its owner has held the ledger for too long.
        if let Some(tx) = self.tx.as_ref().filter(|tx| tx.conn != conn) {
            let age = now_ms.checked_sub(tx.opened_ms);
            if age.is_none_or(|a| a < self.limits.tx_timeout_ms) {
                return Response::Refused(Refusal::Busy);
            }
            self.rollback();
        }
        let role = cert.role();
        let forbidden = |op| Response::Denied(LedgerApiError::Forbidden { role, op });
        let denied = |e| Response::Denied(e);
        match body {
            Request::Execute(op) => {
                if let Some(tx) = self.tx.as_mut() {
                    tx.ops += 1;
                    if tx.ops > self.limits.max_tx_ops {
                        self.rollback();
                        return Response::Refused(Refusal::TransactionTooLarge);
                    }
                }
                match self.service.execute_as(cert, op) {
                    Ok(out) => Response::Outcome(out),
                    Err(e) => denied(e),
                }
            }
            Request::Begin if role != ServiceRole::Orchestrator => forbidden("Begin"),
            Request::Begin => {
                let now = self.service.clone();
                match self.tx.as_mut() {
                    Some(tx) if tx.snapshots.len() >= self.limits.max_tx_depth => {
                        return Response::Refused(Refusal::TransactionTooDeep);
                    }
                    Some(tx) => tx.snapshots.push(now),
                    None => {
                        self.tx = Some(Tx {
                            conn,
                            snapshots: vec![now],
                            ops: 0,
                            opened_ms: now_ms,
                        });
                    }
                }
                Response::Done
            }
            Request::Commit => self.end(true),
            Request::Abort => self.end(false),
            Request::Info => Response::Info(LedgerInfo {
                limits: self.service.limits().clone(),
                domain: self.service.domain(),
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
