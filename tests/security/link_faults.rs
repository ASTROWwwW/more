//! Third review of the isolation: what the coordinator does when the link to a ledger in
//! another process fails around a commit. The ledger here is behind the link's messages, in
//! this process, and the orchestrator's connection can be cut at a chosen request.
//!
//! The rule under test: a command whose outcome is unknown is never sent again on a guess. The
//! coordinator stops, asks the ledger what became of the transaction by its name, and acts on
//! the answer only.

use std::sync::{Arc, Mutex};

use super::*;
use gpu_ledger::link::{HostLimits, LedgerHost, Request, Rollback, Transport, TxId, TxState};
use gpu_ledger::LedgerApiError;

struct Rigged {
    /// The reference: coordinator and ledger in one process. Its shadow is the coordinator
    /// behind the link.
    sim: Sim,
    faults: Faults,
    host: Arc<Mutex<LedgerHost>>,
    links: u64,
}

const UNKNOWN: &str = "LEDGER_OUTCOME_UNKNOWN";
const LOST: &str = "LEDGER_STATE_LOST";

impl Rigged {
    /// Job 1 running, as in `Edge::running`, followed command by command behind the link.
    fn new(limits: HostLimits) -> Self {
        let faults = Faults::default();
        let mut host = None;
        let mut sim = Sim::shadowed(|ids| {
            let h = host_with(ids, limits, 1);
            host = Some(h.clone());
            let f = faults.clone();
            let mut n = 0u64;
            RemoteRig::new(ids, move || -> Box<dyn Transport + Send> {
                n += 1;
                let link = loopback(&h, n);
                // The first connection asked for is the orchestrator's.
                if n == 1 {
                    Box::new(Flaky::new(link, &f))
                } else {
                    Box::new(link)
                }
            })
        });
        for c in [
            Command::Reserve { job: J1 },
            Command::Place {
                job: J1,
                lenders: LENDERS[..3].to_vec(),
                layout: layout_of(J1),
                recovery_estimate: 0,
                witness: WITNESS,
                expected_version: None,
            },
        ] {
            sim.exec(c).unwrap();
        }
        sim.start_cluster(J1, 1, [0; 3]).unwrap();
        Rigged {
            sim,
            faults,
            host: host.unwrap(),
            links: 100,
        }
    }

    fn rig(&mut self) -> &mut RemoteRig {
        self.sim.shadow.as_mut().unwrap()
    }

    fn behind(&mut self) -> &mut Coordinator {
        &mut self.rig().coord
    }

    /// To the coordinator behind the link only.
    fn remote(&mut self, cmd: Command) -> Result<Outcome, DomainError> {
        let ctx = self.sim.actor(&cmd);
        let cmd = self.sim.signed(&ctx, cmd);
        self.behind().execute(&ctx, &cmd)
    }

    /// To the reference only.
    fn local(&mut self, cmd: Command) -> Result<Outcome, DomainError> {
        let rig = self.sim.shadow.take();
        let answer = self.sim.exec(cmd);
        self.sim.shadow = rig;
        answer
    }

    /// To both, compared as in every other test.
    fn both(&mut self, cmd: Command) -> Result<Outcome, DomainError> {
        self.sim.exec(cmd)
    }

    /// Both coordinators and both ledgers hold the same.
    #[track_caller]
    fn in_step(&mut self) {
        let mut rig = self.sim.shadow.take().unwrap();
        rig.check(&self.sim.coord, self.sim.ledger());
        self.sim.shadow = Some(rig);
    }

    fn link(&mut self) -> Flaky<gpu_ledger::link::Loopback> {
        self.links += 1;
        Flaky::new(loopback(&self.host, self.links), &self.faults)
    }

    fn reconnect(&mut self) -> Result<(), DomainError> {
        let link = self.link();
        self.rig().reconnect(link)
    }

    /// What the ledger behind the link holds: journal length and accepted operations.
    fn ledger(&self) -> (usize, u64) {
        let host = self.host.lock().unwrap();
        let s = host.service();
        (
            s.audit_view_as(&self.sim.ids.auditor.certificate())
                .unwrap()
                .entries()
                .len(),
            s.seq(),
        )
    }

    #[track_caller]
    fn stopped(&mut self, code: &str) {
        let before = self.behind().clone();
        let ledger = self.ledger();
        for cmd in [
            Command::Reserve { job: J2 },
            Command::Tick { dt: 1 },
            Command::Reconcile,
        ] {
            assert_eq!(self.remote(cmd).map_err(|e| e.code()), Err(code));
        }
        assert!(
            *self.behind() == before,
            "a stopped coordinator changes nothing"
        );
        assert_eq!(self.ledger(), ledger, "and sends nothing to the ledger");
    }
}

fn reserve_j2() -> Command {
    Command::Reserve { job: J2 }
}

/// The answer to a commit is lost exactly after the ledger applied it. The coordinator does not
/// know, says so, stops, and never sends the command again: once it can ask, it takes the state
/// that goes with the commit.
#[test]
fn r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice() {
    let mut t = Rigged::new(HostLimits::default());
    let before = t.behind().clone();
    let journal = t.ledger().0;
    t.faults.at_outer_commit(Cut::After);
    assert_eq!(t.local(reserve_j2()), Ok(Outcome::Applied));
    let answer = t.remote(reserve_j2());
    assert_eq!(answer, Err(DomainError::LedgerOutcomeUnknown));
    // The ledger did commit: the reserve is in its journal. The coordinator kept nothing yet.
    assert!(t.ledger().0 > journal);
    let tx = t
        .behind()
        .unknown_commit()
        .expect("stopped on a transaction");
    assert_eq!(tx.node, 1);
    t.stopped(UNKNOWN);
    // On the dead connection nothing can be asked, and nothing is assumed.
    assert!(matches!(
        t.behind().resolve_commit(),
        Err(DomainError::Ledger(LedgerApiError::Unavailable(_)))
    ));
    t.stopped(UNKNOWN);
    let ledger = t.ledger();
    t.reconnect().unwrap();
    t.stopped(UNKNOWN);
    let state = t.behind().resolve_commit().unwrap();
    assert!(matches!(state, TxState::Committed { .. }), "{state:?}");
    assert_eq!(
        t.ledger(),
        ledger,
        "asking wrote nothing, and nothing was sent again"
    );
    assert!(*t.behind() != before);
    assert_eq!(t.behind().unknown_commit(), None);
    t.in_step();
    // Nothing left to resolve, and work goes on, on the new connection.
    assert_eq!(
        t.behind().resolve_commit(),
        Err(DomainError::Precondition("no commit to resolve"))
    );
    let again = t.both(reserve_j2());
    assert!(again.is_err(), "already reserved: {again:?}");
    t.both(Command::Tick { dt: 5 }).unwrap();
    t.in_step();
    assert!(t.sim.violations.is_empty(), "{:#?}", t.sim.violations);
}

/// The commit itself is lost on the way. The coordinator cannot tell this from the case above
/// and behaves the same. The ledger says "rolled back": the coordinator keeps the state it had,
/// and the command, sent again by its sender, runs under a new name.
#[test]
fn r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again() {
    let mut t = Rigged::new(HostLimits::default());
    let jobs = t.behind().jobs().clone();
    let ledger = t.ledger();
    t.faults.at_outer_commit(Cut::Before);
    assert_eq!(
        t.remote(reserve_j2()),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    let tx = t.behind().unknown_commit().unwrap();
    t.stopped(UNKNOWN);
    // Dropping the failed connection is what tells the ledger: it rolls back at once.
    t.reconnect().unwrap();
    assert_eq!(
        t.behind().resolve_commit(),
        Ok(TxState::RolledBack(Rollback::Disconnected))
    );
    assert_eq!(t.ledger(), ledger, "nothing of the command was kept");
    assert_eq!(t.behind().unknown_commit(), None);
    // The reference never saw the command: both sides are where they were.
    t.in_step();
    assert!(*t.behind().jobs() == jobs);
    assert_eq!(t.both(reserve_j2()), Ok(Outcome::Applied));
    t.in_step();
    // The old name was not used again, and still says what happened.
    let link = t.link();
    let port = t.rig().dial(link);
    let mut port = port.lock().unwrap();
    assert_eq!(
        port.status(tx),
        Ok((TxState::RolledBack(Rollback::Disconnected), 1))
    );
    let next = TxId {
        node: tx.node,
        counter: tx.counter + 1,
    };
    assert!(matches!(
        port.status(next),
        Ok((TxState::Committed { .. }, 1))
    ));
}

/// The peer vanished without closing: the ledger still believes the transaction open. The
/// coordinator stays stopped, however often it asks, until the ledger's deadline has rolled the
/// transaction back.
#[test]
fn r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline() {
    let mut t = Rigged::new(HostLimits::default());
    let ledger = t.ledger();
    t.faults.hold_dead_links();
    t.faults.at_outer_commit(Cut::Before);
    assert_eq!(
        t.remote(reserve_j2()),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    t.reconnect().unwrap();
    for _ in 0..3 {
        assert_eq!(t.behind().resolve_commit(), Ok(TxState::Open));
        assert!(t.behind().unknown_commit().is_some());
        assert_eq!(
            t.remote(reserve_j2()).map_err(|e| e.code()),
            Err(UNKNOWN),
            "still stopped"
        );
    }
    let limit = HostLimits::default().tx_timeout_ms;
    assert!(!t.host.lock().unwrap().sweep(limit - 1));
    assert_eq!(t.behind().resolve_commit(), Ok(TxState::Open));
    assert!(t.host.lock().unwrap().sweep(limit));
    assert_eq!(
        t.behind().resolve_commit(),
        Ok(TxState::RolledBack(Rollback::Expired))
    );
    assert_eq!(t.ledger(), ledger);
    t.in_step();
    assert_eq!(t.both(reserve_j2()), Ok(Outcome::Applied));
    t.in_step();
    // The dead connection finally closes: nothing is left of it at the ledger.
    t.faults.release();
    assert_eq!(t.host.lock().unwrap().retained().0, 0);
    t.both(Command::Tick { dt: 5 }).unwrap();
}

/// The ledger keeps its state in memory: one that restarted has lost it. Its incarnation
/// number says so, and the coordinator stops for good instead of going on against an empty
/// ledger. With or without a commit in doubt.
#[test]
fn r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there() {
    for in_doubt in [true, false] {
        let mut t = Rigged::new(HostLimits::default());
        if in_doubt {
            t.faults.at_outer_commit(Cut::After);
            assert_eq!(
                t.remote(reserve_j2()),
                Err(DomainError::LedgerOutcomeUnknown)
            );
        }
        // A connection that does not answer is not taken: the coordinator keeps what it had.
        let before = t.behind().clone();
        let link = t.link();
        let dead = t.rig().dial(link);
        t.faults.arm(|_| Some(Cut::Before));
        assert!(matches!(
            t.behind().reconnect_ledger(dead),
            Err(DomainError::Ledger(LedgerApiError::Unavailable(_)))
        ));
        assert!(*t.behind() == before);
        let link = t.link();
        let first = t.rig().dial(link);

        // A ledger with the same identity and the same keys, started anew.
        let fresh = host_with(&t.sim.ids, HostLimits::default(), 2);
        let link = loopback(&fresh, 1);
        assert_eq!(t.rig().reconnect(link), Err(DomainError::LedgerStateLost));
        assert_eq!(t.behind().unknown_commit(), None);
        assert_eq!(
            t.behind().resolve_commit(),
            Err(DomainError::LedgerStateLost)
        );
        // Going back to the first ledger does not undo that: a coordinator that stopped for
        // this reason is started again from scratch, not reconnected.
        assert_eq!(
            t.behind().reconnect_ledger(first),
            Err(DomainError::LedgerStateLost)
        );

        let ctx = t.sim.actor(&reserve_j2());
        let cmd = t.sim.signed(&ctx, reserve_j2());
        for _ in 0..2 {
            let answer = t.behind().execute(&ctx, &cmd);
            assert_eq!(answer.map_err(|e| e.code()), Err(LOST));
        }
        let journal = fresh.lock().unwrap().service().seq();
        assert_eq!(journal, 0, "nothing was sent to the new ledger");
    }
}

/// The ledger remembers a bounded number of outcomes. If the one in doubt has been forgotten,
/// it says "unknown", and the coordinator stays stopped: comparing both sides is then a
/// person's job, not a guess.
#[test]
fn r5_an_outcome_the_ledger_forgot_is_left_to_a_person() {
    let limits = HostLimits {
        tx_log: 2,
        ..HostLimits::default()
    };
    let mut t = Rigged::new(limits);
    t.faults.at_outer_commit(Cut::After);
    assert_eq!(t.local(reserve_j2()), Ok(Outcome::Applied));
    assert_eq!(
        t.remote(reserve_j2()),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    t.reconnect().unwrap();
    // Another orchestrator instance works in the meantime.
    let link = t.link();
    let port = t.rig().dial(link);
    for counter in 1..=2 {
        let mut port = port.lock().unwrap();
        port.begin(TxId { node: 7, counter }).unwrap();
        port.commit().unwrap();
    }
    for _ in 0..2 {
        assert_eq!(t.behind().resolve_commit(), Ok(TxState::Unknown));
        t.stopped(UNKNOWN);
    }
    assert!(t.behind().unknown_commit().is_some());
}

/// A command can hold transactions nested in its own (reconciliation). An answer lost inside
/// it is not an unknown outcome: nothing was committed, the command fails as a whole and the
/// ledger undoes all of it. Lost at the outermost commit, it is one, with everything nested.
#[test]
fn r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome() {
    let mut t = Rigged::new(HostLimits::default());
    t.both(reserve_j2()).unwrap();
    t.both(Command::Tick { dt: 901 }).unwrap();
    let before = t.behind().clone();
    let ledger = t.ledger();
    // The first commit nested in the command's transaction.
    let mut depth = 0u32;
    t.faults.arm(move |r| match r {
        Request::Begin { .. } | Request::Savepoint => {
            depth += 1;
            None
        }
        Request::Commit if depth == 2 => Some(Cut::After),
        _ => None,
    });
    let answer = t.remote(Command::Reconcile);
    assert!(
        matches!(answer, Err(DomainError::Internal(_))),
        "{answer:?}"
    );
    assert_eq!(t.behind().unknown_commit(), None, "not stopped on a commit");
    assert!(*t.behind() == before);
    // The link is dead: nothing goes through, nothing changes.
    let unavailable = t.remote(reserve_j2());
    assert!(
        matches!(
            unavailable,
            Err(DomainError::Ledger(LedgerApiError::Unavailable(_)))
        ),
        "{unavailable:?}"
    );
    assert!(*t.behind() == before);
    // A copy of the coordinator shares its connection: let go of it, as a restart would.
    drop(before);
    t.reconnect().unwrap();
    assert_eq!(
        t.ledger().0,
        ledger.0,
        "the nested commit went with the rest"
    );
    t.in_step();
    // The same command, lost at its outermost commit this time.
    t.faults.at_outer_commit(Cut::After);
    assert_eq!(t.local(Command::Reconcile), Ok(Outcome::Applied));
    assert_eq!(
        t.remote(Command::Reconcile),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    t.reconnect().unwrap();
    assert!(matches!(
        t.behind().resolve_commit(),
        Ok(TxState::Committed { .. })
    ));
    t.in_step();
    assert!(t.ledger().0 > ledger.0);
    t.both(Command::Reconcile).unwrap();
    t.in_step();
}
