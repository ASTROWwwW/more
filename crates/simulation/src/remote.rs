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
use gpu_ledger::link::{LedgerClient, RemoteLedger, Transport};
use gpu_ledger::{Account, IssueTo, LedgerOp};
use more_identity::{AuthContext, ServiceCredential};

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
    /// Commands followed so far.
    pub followed: u64,
}

impl RemoteRig {
    /// Connects every service of `ids` through `transport`, each with its own key, and starts
    /// the coordinator on the orchestrator's connection. Account keys must already be known to
    /// the ledger behind the link.
    pub fn new<T: Transport + Send + 'static>(
        ids: &SimIdentity,
        mut transport: impl FnMut() -> T,
    ) -> Self {
        let verifier = ids.verifier();
        let mut n = 0u8;
        let mut connect = |me: &ServiceCredential| {
            n += 1;
            let mut nonce = [0x33; 32];
            nonce[0] = n;
            LedgerClient::connect(transport(), me, &verifier, nonce).expect("ledger link")
        };
        let mut orchestrator = connect(&ids.orchestrator);
        let info = orchestrator.info().expect("ledger link");
        let port: Arc<Mutex<dyn RemoteLedger>> = Arc::new(Mutex::new(orchestrator));
        let coord = Coordinator::with_remote_ledger(
            sim_config(),
            port,
            info,
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
            followed: 0,
        }
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
                    return;
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
        let remote = self.coord.execute(ctx, cmd);
        assert_eq!(*local, remote, "answers differ for {cmd:?}");
        self.compare(cmd, reference, ledger);
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
pub fn host_in_process(ids: &SimIdentity) -> Arc<Mutex<gpu_ledger::link::LedgerHost>> {
    let host = gpu_ledger::link::LedgerHost::new(
        ids.verifier_ledger(),
        ids.keys.clone(),
        ids.verifier(),
        ids.ledger.clone(),
        gpu_ledger::link::HostLimits::default(),
    )
    .expect("a ledger identity of this deployment");
    Arc::new(Mutex::new(host))
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
                gpu_ledger::link::Loopback::new(host.clone(), Box::new(Counter(n << 32)))
            })
        })
    }
}
