//! A service's side of the link: connect, prove who it is, check it really talks to this
//! deployment's ledger, then send typed requests.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use more_identity::{CredentialVerifier, ServiceCertificate, ServiceCredential, ServiceRole};

use super::host::{Conn, HostEnv, LedgerHost};
use super::wire::{
    transcript, Fault, LedgerInfo, LedgerSummary, Message, Refusal, Request, Response,
    LINK_VERSION, MAX_FRAME,
};
use crate::service::{LedgerApiError, LedgerOp, LedgerOutcome};
use crate::{Account, Amount};

/// Why a call did not get an answer from the ledger's rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    Io(String),
    /// The peer sent something that does not decode or does not belong here.
    Protocol(&'static str),
    /// The ledger ended the connection.
    Fault(Fault),
    /// The peer is not this deployment's ledger: wrong authority, wrong role, or no proof of its
    /// key.
    NotTheLedger,
    Refused(Refusal),
}

/// Carries whole payloads. Framing, if any, is the transport's business.
pub trait Transport {
    fn send(&mut self, payload: &[u8]) -> Result<(), LinkError>;
    fn recv(&mut self) -> Result<Vec<u8>, LinkError>;
}

/// Writes one payload with its length in front.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_FRAME)
        .ok_or_else(|| std::io::Error::other("payload above the frame limit"))?;
    w.write_all(&n.to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads one payload. A length above the limit is refused before anything is allocated.
pub fn read_frame(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::other("frame above the limit"));
    }
    let mut payload = vec![0u8; n];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Length-prefixed frames over a byte stream (a local socket).
pub struct StreamTransport<S>(pub S);

impl<S: Read + Write> Transport for StreamTransport<S> {
    fn send(&mut self, payload: &[u8]) -> Result<(), LinkError> {
        write_frame(&mut self.0, payload).map_err(|e| LinkError::Io(e.to_string()))
    }
    fn recv(&mut self) -> Result<Vec<u8>, LinkError> {
        read_frame(&mut self.0).map_err(|e| LinkError::Io(e.to_string()))
    }
}

/// The host in the same process, reached through the same messages as over a socket. Nothing is
/// shared with the caller but the payloads.
pub struct Loopback {
    host: Arc<Mutex<LedgerHost>>,
    conn: Conn,
    env: Box<dyn HostEnv + Send>,
    inbox: VecDeque<Vec<u8>>,
    closed: bool,
}

impl Loopback {
    pub fn new(host: Arc<Mutex<LedgerHost>>, env: Box<dyn HostEnv + Send>) -> Self {
        let conn = host.lock().unwrap_or_else(|e| e.into_inner()).open();
        Loopback {
            host,
            conn,
            env,
            inbox: VecDeque::new(),
            closed: false,
        }
    }
}

impl Transport for Loopback {
    fn send(&mut self, payload: &[u8]) -> Result<(), LinkError> {
        if self.closed {
            return Err(LinkError::Io("connection closed".into()));
        }
        let mut host = self.host.lock().unwrap_or_else(|e| e.into_inner());
        let reply = host.handle(&mut self.conn, payload, self.env.as_mut());
        self.closed = reply.close;
        self.inbox.push_back(reply.frame);
        Ok(())
    }
    fn recv(&mut self) -> Result<Vec<u8>, LinkError> {
        self.inbox
            .pop_front()
            .ok_or_else(|| LinkError::Io("nothing to read".into()))
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        let mut host = self.host.lock().unwrap_or_else(|e| e.into_inner());
        host.close(&mut self.conn);
    }
}

/// An authenticated connection to the ledger.
pub struct LedgerClient<T> {
    transport: T,
    seq: u64,
    ledger: ServiceCertificate,
}

impl<T: Transport> LedgerClient<T> {
    /// Connects as `me`. `nonce` must be fresh and unpredictable. Fails unless the peer shows a
    /// certificate of role `Ledger` signed by `verifier`'s authority and proves it holds its key.
    pub fn connect(
        mut transport: T,
        me: &ServiceCredential,
        verifier: &CredentialVerifier,
        nonce: [u8; 32],
    ) -> Result<Self, LinkError> {
        let domain = verifier.domain();
        let mine = me.certificate();
        let hello = Message::Hello {
            version: LINK_VERSION,
            domain,
            cert: mine,
            nonce,
        };
        transport.send(&hello.encode())?;
        let (ledger, theirs, signature) = match Self::read(&mut transport)? {
            Message::Challenge {
                cert,
                nonce,
                signature,
            } => (cert, nonce, signature),
            Message::Fault(f) => return Err(LinkError::Fault(f)),
            _ => return Err(LinkError::Protocol("expected a challenge")),
        };
        let sign = |server| transcript(server, &domain, &mine, &ledger, &nonce, &theirs);
        if verifier.verify_certificate(&ledger) != Ok(ServiceRole::Ledger)
            || ledger.verify(&sign(true), &signature).is_err()
        {
            return Err(LinkError::NotTheLedger);
        }
        let proof = Message::Proof {
            signature: me.sign(&sign(false)),
        };
        transport.send(&proof.encode())?;
        match Self::read(&mut transport)? {
            Message::Ready => Ok(LedgerClient {
                transport,
                seq: 0,
                ledger,
            }),
            Message::Fault(f) => Err(LinkError::Fault(f)),
            _ => Err(LinkError::Protocol("expected ready")),
        }
    }

    fn read(transport: &mut T) -> Result<Message, LinkError> {
        Message::decode(&transport.recv()?).map_err(|_| LinkError::Protocol("malformed message"))
    }

    /// The ledger this connection authenticated.
    pub fn ledger(&self) -> ServiceCertificate {
        self.ledger
    }

    /// The transport underneath, for a caller that frames its own payloads.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn call(&mut self, body: Request) -> Result<Response, LinkError> {
        self.seq += 1;
        let request = Message::Request {
            seq: self.seq,
            body,
        };
        self.transport.send(&request.encode())?;
        match Self::read(&mut self.transport)? {
            Message::Response { seq, body } if seq == self.seq => match body {
                Response::Refused(r) => Err(LinkError::Refused(r)),
                other => Ok(other),
            },
            Message::Fault(f) => Err(LinkError::Fault(f)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    /// Runs one operation as this connection's service.
    pub fn execute(
        &mut self,
        op: LedgerOp,
    ) -> Result<Result<LedgerOutcome, LedgerApiError>, LinkError> {
        match self.call(Request::Execute(op))? {
            Response::Outcome(out) => Ok(Ok(out)),
            Response::Denied(e) => Ok(Err(e)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    fn done(&mut self, body: Request) -> Result<Result<(), LedgerApiError>, LinkError> {
        match self.call(body)? {
            Response::Done => Ok(Ok(())),
            Response::Denied(e) => Ok(Err(e)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    pub fn begin(&mut self) -> Result<Result<(), LedgerApiError>, LinkError> {
        self.done(Request::Begin)
    }

    pub fn commit(&mut self) -> Result<Result<(), LedgerApiError>, LinkError> {
        self.done(Request::Commit)
    }

    pub fn abort(&mut self) -> Result<Result<(), LedgerApiError>, LinkError> {
        self.done(Request::Abort)
    }

    pub fn register_key(
        &mut self,
        account: u32,
        key: [u8; 32],
    ) -> Result<Result<(), LedgerApiError>, LinkError> {
        self.done(Request::RegisterKey { account, key })
    }

    pub fn revoke(
        &mut self,
        service: u32,
        signature: [u8; 64],
    ) -> Result<Result<(), LedgerApiError>, LinkError> {
        self.done(Request::Revoke { service, signature })
    }

    pub fn info(&mut self) -> Result<LedgerInfo, LinkError> {
        match self.call(Request::Info)? {
            Response::Info(i) => Ok(i),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    pub fn balance(
        &mut self,
        account: Account,
    ) -> Result<Result<Amount, LedgerApiError>, LinkError> {
        match self.call(Request::Balance(account))? {
            Response::Balance(a) => Ok(Ok(a)),
            Response::Denied(e) => Ok(Err(e)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    pub fn audit_balances(
        &mut self,
    ) -> Result<Result<Vec<(Account, i128)>, LedgerApiError>, LinkError> {
        match self.call(Request::AuditBalances)? {
            Response::Balances(all) => Ok(Ok(all)),
            Response::Denied(e) => Ok(Err(e)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }

    pub fn audit_summary(&mut self) -> Result<Result<LedgerSummary, LedgerApiError>, LinkError> {
        match self.call(Request::AuditSummary)? {
            Response::Summary(s) => Ok(Ok(s)),
            Response::Denied(e) => Ok(Err(e)),
            _ => Err(LinkError::Protocol("unexpected answer")),
        }
    }
}

/// The ledger as the orchestrator uses it when it runs in another process: its own operations,
/// and a transaction around each command so that a command is applied entirely or not at all.
pub trait RemoteLedger: Send {
    fn execute(&mut self, op: LedgerOp) -> Result<LedgerOutcome, LedgerApiError>;
    /// Balance of one of the orchestrator's job accounts.
    fn balance(&mut self, account: Account) -> Result<Amount, LedgerApiError>;
    fn begin(&mut self) -> Result<(), LedgerApiError>;
    fn commit(&mut self) -> Result<(), LedgerApiError>;
    fn abort(&mut self) -> Result<(), LedgerApiError>;
}

fn unavailable<V>(r: Result<Result<V, LedgerApiError>, LinkError>) -> Result<V, LedgerApiError> {
    match r {
        Ok(inner) => inner,
        Err(LinkError::Refused(Refusal::Busy)) => {
            Err(LedgerApiError::Unavailable("the ledger is busy"))
        }
        Err(LinkError::Refused(_)) => Err(LedgerApiError::Unavailable(
            "the ledger refused the transaction",
        )),
        Err(_) => Err(LedgerApiError::Unavailable("the link to the ledger failed")),
    }
}

impl<T: Transport + Send> RemoteLedger for LedgerClient<T> {
    fn execute(&mut self, op: LedgerOp) -> Result<LedgerOutcome, LedgerApiError> {
        unavailable(LedgerClient::execute(self, op))
    }
    fn balance(&mut self, account: Account) -> Result<Amount, LedgerApiError> {
        unavailable(LedgerClient::balance(self, account))
    }
    fn begin(&mut self) -> Result<(), LedgerApiError> {
        unavailable(LedgerClient::begin(self))
    }
    fn commit(&mut self) -> Result<(), LedgerApiError> {
        unavailable(LedgerClient::commit(self))
    }
    fn abort(&mut self) -> Result<(), LedgerApiError> {
        unavailable(LedgerClient::abort(self))
    }
}
