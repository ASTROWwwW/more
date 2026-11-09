//! Baseline reproduction of the audit findings, written against commit 8e020bd. It does not
//! compile against the current API. To rerun: check out 8e020bd, copy this file to
//! tests/baseline_repro/main.rs, add a `[[test]]` entry for it in Cargo.toml, then
//! `cargo test --test baseline_repro -- --nocapture --test-threads=1` (debug and release).
use gpu_domain::*;
use gpu_protocol::*;
use gpu_simulation::*;

fn env(sender: u32, seq: u64, body: Message) -> Envelope {
    Envelope { version: PROTOCOL_VERSION, sender: AccountId(sender), seq, signature: 1, body }
}

fn running_job() -> Coordinator {
    let mut sim = Sim::new(sim_config());
    for c in [
        Command::Reserve { job: JobId(1) },
        Command::Place { job: JobId(1), lenders: vec![AccountId(10), AccountId(11), AccountId(12)], recovery_estimate: 0, witness: WITNESS, expected_version: None },
        Command::AttemptReady { job: JobId(1), attempt: 1, restored: [0; 3] },
        Command::Produce { job: JobId(1), attempt: 1, wt: WorkType::Generate, upto: 2 },
    ] { sim.exec(c).unwrap(); }
    sim.coord
}

#[test]
fn sec001_cancel_other_users_job() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    // Account 2 (another borrower) cancels job 1 owned by account 1.
    let r = handle(&mut g, &mut c, &env(2, 1, Message::CancelJob { job: JobId(1) }));
    println!("SEC-001 cancel by non-owner: {r:?}, exec now {:?}", c.jobs[&JobId(1)].exec);
}

#[test]
fn sec001_ack_other_users_tokens() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    let r = handle(&mut g, &mut c, &env(13, 1, Message::TokenAck { job: JobId(1), attempt: 1, wt: WorkType::Generate, upto: 2 }));
    println!("SEC-001 ack by an unrelated lender: {r:?}, validated {:?}", c.jobs[&JobId(1)].validated);
}

#[test]
fn sec001_heartbeat_and_produce_by_anyone() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    let r1 = handle(&mut g, &mut c, &env(2, 1, Message::Heartbeat { job: JobId(1), attempt: 1 }));
    let r2 = handle(&mut g, &mut c, &env(2, 2, Message::Produced { job: JobId(1), attempt: 1, wt: WorkType::Generate, upto: 3 }));
    println!("SEC-001 heartbeat by a borrower of another job: {r1:?}; produce: {r2:?}");
}

#[test]
fn sec003_sec004_self_commit_bypasses_cap() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    // Lender 10 commits receipts for itself (it should be the next stage, 11).
    let r = handle(&mut g, &mut c, &env(10, 1, Message::ReceiptCommit { job: JobId(1), attempt: 1, producer: AccountId(10), wt: WorkType::Generate, upto: 2 }));
    println!("SEC-004 self commitment: {r:?}");
}

#[test]
fn sec002_zero_price_and_any_pool() {
    let mut c = Coordinator::new(sim_config());
    c.apply(&Command::CreatePool { pool: PoolId(7), mode: PoolMode::Credits }).unwrap();
    let mut g = ReplayGuard::default();
    let r = handle(&mut g, &mut c, &env(55, 1, Message::SubmitJob { job: JobId(9), pool: PoolId(7), layout: vec![1, 1], price: [0, 0, 0], max_outputs: [0, 1000, 0] }));
    println!("SEC-002/003 zero price, non-member account 55 in pool 7: {r:?}, est_cost {}", c.jobs[&JobId(9)].est_cost);
}

#[test]
fn safe001_overflow_price() {
    let mut c = Coordinator::new(sim_config());
    c.apply(&Command::CreatePool { pool: PoolId(7), mode: PoolMode::Credits }).unwrap();
    let r = std::panic::catch_unwind(move || {
        let mut c = c;
        c.apply(&Command::Submit { job: JobId(9), borrower: AccountId(1), pool: PoolId(7), layout: vec![1], price: [0, u64::MAX / 2, 0], max_outputs: [0, 4, 0] }).map(|_| c.jobs[&JobId(9)].est_cost)
    });
    println!("SAFE-001 price u64::MAX/2 x 4 outputs: {r:?}");
}

#[test]
fn safe001_overflow_tick() {
    let r = std::panic::catch_unwind(|| {
        let mut c = Coordinator::new(sim_config());
        c.apply(&Command::Tick { dt: u64::MAX }).unwrap();
        c.apply(&Command::Tick { dt: 2 })
    });
    println!("SAFE-001 tick overflow: {:?}", r.map_err(|_| "panic"));
}

#[test]
fn safe002_duplicate_lenders() {
    let mut sim = Sim::new(sim_config());
    sim.exec(Command::Reserve { job: JobId(1) }).unwrap();
    let r = sim.exec(Command::Place { job: JobId(1), lenders: vec![AccountId(10), AccountId(10), AccountId(10)], recovery_estimate: 0, witness: WITNESS, expected_version: None });
    println!("SAFE-002 same lender on all stages: {r:?}");
}

#[test]
fn sec005_retransmission_after_refusal() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    let m = Message::Heartbeat { job: JobId(1), attempt: 7 };
    let r1 = handle(&mut g, &mut c, &env(10, 5, m.clone()));
    let r2 = handle(&mut g, &mut c, &env(10, 5, m));
    let r3 = handle(&mut g, &mut c, &env(10, 1, Message::Heartbeat { job: JobId(1), attempt: 1 }));
    println!("SEC-005 refused: {r1:?}; same seq again: {r2:?}; restarted sender (seq 1): {r3:?}");
}

#[test]
fn sec006_signature_is_not_checked() {
    let mut c = running_job();
    let mut g = ReplayGuard::default();
    let mut e = env(1, 1, Message::CancelJob { job: JobId(1) });
    e.signature = 0xdead_beef;
    println!("SEC-006 arbitrary non-zero signature: {:?}", handle(&mut g, &mut c, &e));
}

#[test]
fn ledger_is_writable_by_anyone_holding_the_coordinator() {
    let mut c = running_job();
    let r = c.ledger.transfer("x", gpu_ledger::Account::User(1), gpu_ledger::Account::User(99), 100, "theft");
    let r2 = c.ledger.transfer("y", gpu_ledger::Account::Issuance, gpu_ledger::Account::User(99), 1_000_000, "mint");
    println!("Ledger direct write: {r:?} {r2:?}, user 99 balance {}", c.ledger.balance(gpu_ledger::Account::User(99)));
}
