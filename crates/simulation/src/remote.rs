//! A second coordinator whose ledger runs behind the ledger link, fed every command the
//! simulation sends. It must answer the same and end in the same state, and its ledger must hold
//! the same journal: the split into two processes changes where the ledger lives, never what it
//! does.
//!
//! The coordinator behind the link holds the orchestrator's key and nothing else. What belongs
//! to the clock, the treasury and the platform admin goes to the ledger on their own
//! connections, as it would between real processes.

use std::sync::{Arc, Mutex};

use gpu_domain::*;
use gpu_ledger::link::{
    HostLimits, LedgerClient, LedgerHost, LinkError, Loopback, Message, RemoteLedger, Request,
    Transport,
};
use gpu_ledger::{Account, IssueTo, LedgerOp};
use more_identity::{AuthContext, CredentialVerifier, ServiceCredential};

use crate::world::{sim_config, SimIdentity};

/// A connection of one service to the ledger behind the link.
trait Service {
    fn send(&mut self, op: LedgerOp);
    fn balances(&mut self) -> Vec<(Account, i128)>;
    /// Journal length, hash of its last entry, operations accepted, ledger time.
    fn summary(&mut self) -> (u64, u64, u64, u64);
}

impl<T: Transport> Service for LedgerClient<T> {
    fn send(&mut self, op: LedgerOp) {
        let kind = op.kind();
        let answer = self.execute(op).expect("ledger link");
        assert!(
            answer.is_ok(),
            "{kind} accepted in process, refused behind the link: {answer:?}"
        );
    }
    fn balances(&mut self) -> Vec<(Account, i128)> {
        self.audit_balances()
            .expect("ledger link")
            .expect("auditor")
    }
    fn summary(&mut self) -> (u64, u64, u64, u64) {
        let s = self.audit_summary().expect("ledger link").expect("auditor");
        (s.entries, s.head, s.seq, s.now)
    }
}

pub struct RemoteRig {
    /// The coordinator whose ledger is behind the link.
    pub coord: Coordinator,
    clock: Box<dyn Service>,
    treasury: Box<dyn Service>,
    platform: Box<dyn Service>,
    auditor: Box<dyn Service>,
    orchestrator: ServiceCredential,
    verifier: CredentialVerifier,
    connections: u8,
    /// Commands followed so far.
    pub followed: u64,
}

/// A connection of the orchestrator, as `Coordinator` takes it.
pub type Port = Arc<Mutex<dyn RemoteLedger>>;

fn dial<T: Transport + Send + 'static>(
    transport: T,
    me: &ServiceCredential,
    verifier: &CredentialVerifier,
    n: u8,
) -> LedgerClient<T> {
    let mut nonce = [0x33; 32];
    nonce[0] = n;
    LedgerClient::connect(transport, me, verifier, nonce).expect("ledger link")
}

impl RemoteRig {
    /// Connects every service of `ids` through `transport`, each with its own key, and starts
    /// the coordinator on the orchestrator's connection, which is the first one asked for.
    /// Account keys must already be known to the ledger behind the link.
    pub fn new<T: Transport + Send + 'static>(
        ids: &SimIdentity,
        mut transport: impl FnMut() -> T,
    ) -> Self {
        let verifier = ids.verifier();
        let mut n = 0u8;
        let mut connect = |me: &ServiceCredential| {
            n += 1;
            dial(transport(), me, &verifier, n)
        };
        let mut orchestrator = connect(&ids.orchestrator);
        let info = orchestrator.info().expect("ledger link");
        let port: Arc<Mutex<dyn RemoteLedger>> = Arc::new(Mutex::new(orchestrator));
        let coord = Coordinator::with_remote_ledger(
            sim_config(),
            port,
            info,
            1,
            ids.orchestrator.clone(),
            ids.verifier(),
        )
        .expect("valid simulation config");
        RemoteRig {
            coord,
            clock: Box::new(connect(&ids.clock)),
            treasury: Box::new(connect(&ids.treasury)),
            platform: Box::new(connect(&ids.platform)),
            auditor: Box::new(connect(&ids.auditor)),
            orchestrator: ids.orchestrator.clone(),
            verifier,
            connections: 5,
            followed: 0,
        }
    }

    /// A new connection of the orchestrator over `transport`, not yet given to the coordinator.
    pub fn dial<T: Transport + Send + 'static>(&mut self, transport: T) -> Port {
        self.connections += 1;
        let n = self.connections;
        Arc::new(Mutex::new(dial(
            transport,
            &self.orchestrator,
            &self.verifier,
            n,
        )))
    }

    /// Replaces the coordinator's connection to the ledger, as after a failure of the link.
    pub fn reconnect<T: Transport + Send + 'static>(
        &mut self,
        transport: T,
    ) -> Result<(), DomainError> {
        let port = self.dial(transport);
        self.coord.reconnect_ledger(port)
    }

    /// Sends `cmd` to the coordinator behind the link as `ctx` did in process, and compares.
    /// `local` is what the in-process coordinator answered, `reference` its state afterwards.
    pub fn follow(
        &mut self,
        ctx: &AuthContext,
        cmd: &Command,
        local: &Result<Outcome, DomainError>,
        reference: &Coordinator,
        ledger: &gpu_ledger::Ledger,
    ) {
        let remote = self.send(ctx, cmd, local, reference);
        assert_eq!(*local, remote, "answers differ for {cmd:?}");
        self.compare(cmd, reference, ledger);
    }

    /// The sending half of `follow`: what the coordinator behind the link answers, unchecked.
    pub fn send(
        &mut self,
        ctx: &AuthContext,
        cmd: &Command,
        local: &Result<Outcome, DomainError>,
        reference: &Coordinator,
    ) -> Result<Outcome, DomainError> {
        self.followed += 1;
        let applied = *local == Ok(Outcome::Applied);
        // The part of a command that is another service's business at the ledger. In process the
        // coordinator carried it with that service's credential; here the service sends it.
        match cmd {
            Command::Issue { id, to, amount } => {
                // Behind the link the coordinator is only told of an issuance, it does not ask
                // the ledger. So it hears of the ones the ledger accepted, and of the ones the
                // coordinator itself refuses; a duplicate or a refusal by the ledger is between
                // the treasury and the ledger.
                let by_the_ledger = matches!(local, Err(DomainError::Ledger(_)))
                    || *local == Ok(Outcome::AlreadyApplied);
                if by_the_ledger {
                    return local.clone();
                }
                if applied {
                    let to = match to {
                        IssueTarget::User(a) => IssueTo::User(a.0),
                        IssueTarget::Pool(p) => IssueTo::Pool(p.0),
                    };
                    self.treasury.send(LedgerOp::Issue {
                        key: format!("issue/{id}"),
                        to,
                        amount: *amount,
                    });
                }
            }
            Command::Tick { .. } if applied => self.clock.send(LedgerOp::Advance {
                now: reference.now(),
            }),
            Command::CreatePool { pool, admin, .. } if applied => {
                self.platform.send(LedgerOp::RegisterPool {
                    pool: pool.0,
                    admin: admin.0,
                });
            }
            _ => {}
        }
        self.coord.execute(ctx, cmd)
    }

    /// The checking half of `follow`: the coordinator behind the link and its ledger hold what
    /// `reference` and `ledger` hold.
    pub fn check(&mut self, reference: &Coordinator, ledger: &gpu_ledger::Ledger) {
        self.compare(&Command::Reconcile, reference, ledger);
    }

    /// Journal length, hash of its last entry, operations accepted and time of the ledger
    /// behind the link.
    pub fn ledger_summary(&mut self) -> (u64, u64, u64, u64) {
        self.auditor.summary()
    }

    fn compare(&mut self, cmd: &Command, reference: &Coordinator, ledger: &gpu_ledger::Ledger) {
        let c = &self.coord;
        assert_eq!(
            (reference.now(), reference.seq()),
            (c.now(), c.seq()),
            "clock or log position after {cmd:?}"
        );
        assert!(reference.jobs() == c.jobs(), "jobs differ after {cmd:?}");
        assert!(
            reference.slices() == c.slices(),
            "slices differ after {cmd:?}"
        );
        assert!(
            reference.registry() == c.registry(),
            "registry differs after {cmd:?}"
        );
        assert!(
            reference.delivery() == c.delivery(),
            "delivery differs after {cmd:?}"
        );
        assert!(
            reference.audit_log() == c.audit_log(),
            "audit log differs after {cmd:?}"
        );
        let balances: Vec<(Account, i128)> = ledger.accounts().map(|(a, b)| (*a, *b)).collect();
        assert_eq!(
            balances,
            self.auditor.balances(),
            "balances differ after {cmd:?}"
        );
        let (entries, head, _, now) = self.auditor.summary();
        let last = ledger.entries().last().map_or(0, |e| e.hash);
        assert_eq!(
            (entries, head),
            (ledger.entries().len() as u64, last),
            "journals differ after {cmd:?}"
        );
        let local_now = reference
            .ledger_service()
            .map(|l| l.now())
            .expect("the reference keeps its ledger in process");
        assert_eq!(now, local_now, "ledger clocks differ after {cmd:?}");
    }
}

/// Nonces for a host in this process: distinct, not secret. A daemon takes its own from the
/// operating system.
struct Counter(u64);

impl gpu_ledger::link::HostEnv for Counter {
    fn now_ms(&mut self) -> u64 {
        0
    }
    fn nonce(&mut self) -> [u8; 32] {
        self.0 += 1;
        let mut n = [0x77; 32];
        n[..8].copy_from_slice(&self.0.to_le_bytes());
        n
    }
}

/// A ledger of its own for `ids`, behind the link, in this process.
pub fn host_in_process(ids: &SimIdentity) -> Arc<Mutex<LedgerHost>> {
    host_with(ids, HostLimits::default(), 1)
}

/// As `host_in_process`, with its own limits and incarnation.
pub fn host_with(
    ids: &SimIdentity,
    limits: HostLimits,
    incarnation: u64,
) -> Arc<Mutex<LedgerHost>> {
    let host = LedgerHost::new(
        ids.verifier_ledger(),
        ids.keys.clone(),
        ids.verifier(),
        ids.ledger.clone(),
        limits,
        incarnation,
    )
    .expect("a ledger identity of this deployment");
    Arc::new(Mutex::new(host))
}

/// The `n`-th connection to a host in this process. Its clock stays at zero: a test ends a
/// transaction's time by calling `LedgerHost::sweep` itself.
pub fn loopback(host: &Arc<Mutex<LedgerHost>>, n: u64) -> Loopback {
    Loopback::new(host.clone(), Box::new(Counter(n << 32)))
}

impl crate::world::Sim {
    /// The default simulation, with a second coordinator that reaches its own ledger through
    /// the link's messages only.
    pub fn shadowed_in_process() -> Self {
        Self::shadowed(|ids| {
            let host = host_in_process(ids);
            let mut n = 0u64;
            RemoteRig::new(ids, move || {
                n += 1;
                loopback(&host, n)
            })
        })
    }
}

/// Where a failing link loses a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    /// The request never reaches the ledger.
    Before,
    /// The ledger handles the request. Its answer never comes back.
    After,
}

type Plan = Box<dyn FnMut(&Request) -> Option<Cut> + Send>;

#[derive(Default)]
struct FaultState {
    plan: Option<Plan>,
    hold: bool,
    held: Vec<Box<dyn Send>>,
}

/// The switch of a `Flaky` link, kept by the test.
#[derive(Clone, Default)]
pub struct Faults(Arc<Mutex<FaultState>>);

impl Faults {
    /// The link fails once, at the first request for which `plan` says so. A link that failed
    /// stays dead, as a cut connection does.
    pub fn arm(&self, plan: impl FnMut(&Request) -> Option<Cut> + Send + 'static) {
        self.0.lock().expect("faults").plan = Some(Box::new(plan));
    }

    /// The link fails at the commit that closes the next command's transaction, not at the
    /// commits nested in it.
    pub fn at_outer_commit(&self, cut: Cut) {
        let mut depth = 0u32;
        self.arm(move |r| match r {
            Request::Begin { .. } | Request::Savepoint => {
                depth += 1;
                None
            }
            Request::Abort => {
                depth -= 1;
                None
            }
            Request::Commit => {
                depth -= 1;
                (depth == 0).then_some(cut)
            }
            _ => None,
        });
    }

    /// From now on a dead link is not closed when its owner drops it: the ledger goes on
    /// believing the connection open, as with a peer that vanished without a word.
    pub fn hold_dead_links(&self) {
        self.0.lock().expect("faults").hold = true;
    }

    /// Closes the dead links held so far.
    pub fn release(&self) {
        let held = std::mem::take(&mut self.0.lock().expect("faults").held);
        drop(held);
    }
}

/// A link that fails where its `Faults` say.
pub struct Flaky<T: Send + 'static> {
    inner: Option<T>,
    faults: Faults,
    dead: bool,
}

impl<T: Send + 'static> Flaky<T> {
    pub fn new(inner: T, faults: &Faults) -> Self {
        Flaky {
            inner: Some(inner),
            faults: faults.clone(),
            dead: false,
        }
    }
}

impl<T: Transport + Send + 'static> Transport for Flaky<T> {
    fn send(&mut self, payload: &[u8]) -> Result<(), LinkError> {
        let cut = match Message::decode(payload) {
            Ok(Message::Request { body, .. }) if !self.dead => {
                let mut state = self.faults.0.lock().expect("faults");
                let cut = state.plan.as_mut().and_then(|plan| plan(&body));
                if cut.is_some() {
                    state.plan = None;
                }
                cut
            }
            _ => None,
        };
        let inner = self.inner.as_mut().expect("until dropped");
        match cut {
            _ if self.dead => Err(LinkError::Io("the link is cut".into())),
            Some(Cut::Before) => {
                self.dead = true;
                Err(LinkError::Io("the request was lost".into()))
            }
            Some(Cut::After) => {
                self.dead = true;
                inner.send(payload)
            }
            None => inner.send(payload),
        }
    }

    fn recv(&mut self) -> Result<Vec<u8>, LinkError> {
        if self.dead {
            return Err(LinkError::Io("the answer was lost".into()));
        }
        self.inner.as_mut().expect("until dropped").recv()
    }
}

impl<T: Send + 'static> Drop for Flaky<T> {
    fn drop(&mut self) {
        let mut state = self.faults.0.lock().expect("faults");
        if let (true, true, Some(inner)) = (self.dead, state.hold, self.inner.take()) {
            state.held.push(Box::new(inner));
        }
    }
}
