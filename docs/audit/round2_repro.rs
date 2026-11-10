//! Reproduction of the second audit's findings, written against commit e398159. Each test prints
//! what happened; an assertion marks the faulty behavior so the test passes on the faulty code.
//! It does not compile against the fixed API. To rerun: check out e398159, copy this file to
//! tests/round2_repro/main.rs, add a `[[test]]` entry for it, then
//! `cargo test --release --test round2_repro -- --nocapture --test-threads=1`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gpu_domain::*;
use gpu_ledger::*;
use gpu_simulation::*;
use more_identity::{mandate_message, IdentityAuthority, KeyDirectory, ServiceRole, UserKey};

const OWNER: u32 = 1;
const STRANGER_ACC: u32 = 66;
const POOL: u32 = 7;
const JOB: u32 = 1;

struct W {
    ledger: LedgerService,
    orch: more_identity::ServiceCredential,
    auditor: more_identity::ServiceCredential,
}

fn world() -> W {
    let mut auth = IdentityAuthority::new([3; 32]);
    let keys = KeyDirectory::new();
    let owner = UserKey::from_seed([11; 32]);
    keys.register(OWNER, owner.public()).unwrap();
    let mut ledger = LedgerService::new(auth.verifier(), keys, LedgerLimits::default());
    let treasury = auth.issue(ServiceRole::Treasury);
    let orch = auth.issue(ServiceRole::Orchestrator);
    let auditor = auth.issue(ServiceRole::Auditor);
    for (k, to) in [("i1", IssueTo::User(OWNER)), ("i2", IssueTo::Pool(POOL))] {
        let op = LedgerOp::Issue {
            key: k.into(),
            to,
            amount: 1_000,
        };
        ledger.execute(&treasury, op).unwrap();
    }
    let signature = owner.sign(&mandate_message(JOB, POOL, OWNER, 500));
    let op = LedgerOp::OpenEscrow {
        job: JOB,
        owner: OWNER,
        pool: POOL,
        max_budget: 500,
        signature,
    };
    ledger.execute(&orch, op).unwrap();
    W {
        ledger,
        orch,
        auditor,
    }
}

impl W {
    fn run(&mut self, op: LedgerOp) -> Result<LedgerOutcome, LedgerApiError> {
        self.ledger.execute(&self.orch, op)
    }
    fn bal(&self, a: Account) -> i128 {
        self.ledger.audit_view(&self.auditor).unwrap().balance(a)
    }
}

const LINE: LineRef = LineRef {
    job: JOB,
    attempt: 1,
    slice: 0,
    lender: 10,
};

#[test]
fn finding1_pool_credits_reach_the_owner() {
    let mut w = world();
    w.run(LedgerOp::FundRecovery {
        job: JOB,
        key: "f".into(),
        amount: 50,
    })
    .unwrap();
    let r1 = w.run(LedgerOp::ReserveLine {
        line: LINE,
        source: LineSource::Recovery,
        key: "r".into(),
        amount: 50,
    });
    let r2 = w.run(LedgerOp::RefundLine {
        line: LINE,
        to: LineSource::OutputHold,
        key: "b".into(),
        amount: 50,
    });
    let r3 = w.run(LedgerOp::SettleJob {
        job: JOB,
        pool_unspent: 0,
    });
    println!("reserve from recovery {r1:?}, refund to hold {r2:?}, settle {r3:?}");
    println!(
        "pool {} owner {}",
        w.bal(Account::PoolReserve(POOL)),
        w.bal(Account::User(OWNER))
    );
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 950);
    assert_eq!(w.bal(Account::User(OWNER)), 1_050);
}

#[test]
fn finding1b_settle_with_a_chosen_pool_share() {
    let mut w = world();
    w.run(LedgerOp::FundRecovery {
        job: JOB,
        key: "f".into(),
        amount: 50,
    })
    .unwrap();
    let r = w.run(LedgerOp::SettleJob {
        job: JOB,
        pool_unspent: 0,
    });
    println!("settle with pool_unspent = 0: {r:?}");
    println!(
        "pool {} owner {}",
        w.bal(Account::PoolReserve(POOL)),
        w.bal(Account::User(OWNER))
    );
    assert_eq!(w.bal(Account::User(OWNER)), 1_050);
}

#[test]
fn finding2_settle_with_an_open_line_then_orphan_funds() {
    let mut w = world();
    for op in [
        LedgerOp::Reserve {
            job: JOB,
            bucket: EscrowBucket::Work,
            key: "w".into(),
            amount: 100,
        },
        LedgerOp::ChargeOutput {
            job: JOB,
            key: "c".into(),
            amount: 40,
        },
        LedgerOp::ReserveLine {
            line: LINE,
            source: LineSource::OutputHold,
            key: "r".into(),
            amount: 40,
        },
    ] {
        w.run(op).unwrap();
    }
    let s1 = w.run(LedgerOp::SettleJob {
        job: JOB,
        pool_unspent: 0,
    });
    let late = w.run(LedgerOp::RefundLine {
        line: LINE,
        to: LineSource::OutputHold,
        key: "late".into(),
        amount: 40,
    });
    let s2 = w.run(LedgerOp::SettleJob {
        job: JOB,
        pool_unspent: 0,
    });
    println!("settle with open line {s1:?}; late refund {late:?}; settle again {s2:?}");
    println!("output hold after closure: {}", w.bal(Account::OutputHold(JOB)));
    assert!(s1.is_ok() && late.is_ok() && s2.is_err());
    assert_eq!(w.bal(Account::OutputHold(JOB)), 40);
}

#[test]
fn finding3_pay_an_account_that_never_worked() {
    let mut w = world();
    let line = LineRef {
        lender: STRANGER_ACC,
        ..LINE
    };
    for op in [
        LedgerOp::Reserve {
            job: JOB,
            bucket: EscrowBucket::Work,
            key: "w".into(),
            amount: 100,
        },
        LedgerOp::ChargeOutput {
            job: JOB,
            key: "c".into(),
            amount: 100,
        },
        LedgerOp::ReserveLine {
            line,
            source: LineSource::OutputHold,
            key: "r".into(),
            amount: 100,
        },
        LedgerOp::PayLine {
            line,
            key: "p".into(),
            amount: 100,
        },
        LedgerOp::ReleaseReward {
            line,
            key: "x".into(),
        },
    ] {
        let k = op.kind();
        println!("{k}: {:?}", w.run(op));
    }
    println!("stranger balance {}", w.bal(Account::User(STRANGER_ACC)));
    assert_eq!(w.bal(Account::User(STRANGER_ACC)), 90);
}

fn placed() -> Sim {
    let mut sim = Sim::new(sim_config());
    let j = JobId(1);
    let n = layout_of(j).len();
    sim.exec(Command::Reserve { job: j }).unwrap();
    sim.exec(Command::Place {
        job: j,
        lenders: LENDERS[..n].to_vec(),
        layout: layout_of(j),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim
}

#[test]
fn finding4_one_lender_starts_the_cluster() {
    let mut sim = placed();
    let j = JobId(1);
    let ctx = more_identity::assume_account(LENDERS[0].0);
    let r = sim.exec_as(
        &ctx,
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
    );
    let job = &sim.coord.jobs()[&j];
    println!(
        "ready from {:?} only ({} lenders): {r:?}, exec {:?}",
        LENDERS[0],
        job.current().unwrap().lenders.len(),
        job.exec
    );
    assert_eq!(job.exec, ExecStatus::Running);
}

#[test]
fn finding5_one_heartbeat_keeps_every_lease() {
    let mut sim = placed();
    let j = JobId(1);
    sim.exec(Command::AttemptReady {
        job: j,
        attempt: 1,
        restored: [0; 3],
    })
    .unwrap();
    let ttl = sim.coord.config().lease_ttl;
    let first = more_identity::assume_account(LENDERS[0].0);
    // Only the first lender speaks, for three lease lifetimes.
    for _ in 0..(3 * ttl / 10) {
        sim.exec_as(&first, Command::Heartbeat { job: j, attempt: 1 })
            .unwrap();
        sim.exec(Command::Tick { dt: 10 }).unwrap();
    }
    sim.exec(Command::Reconcile).unwrap();
    let job = &sim.coord.jobs()[&j];
    println!(
        "after {}s with lenders 2..n silent: exec {:?}, lease expires at {}, now {}",
        3 * ttl,
        job.exec,
        job.current().unwrap().lease_expires_at,
        sim.coord.now()
    );
    assert_eq!(job.exec, ExecStatus::Running);
}
