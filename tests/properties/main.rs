//! Property tests (spec section 9, TEST-P01 to TEST-P28). `proptest` generates sequences of
//! commands, faults, duplicates, concurrent versions, clock jumps and adversarial behaviour; every
//! property is checked after each command, and liveness and fairness after a final drain.
//! Counterexamples are saved in `tests/properties/proptest-regressions.txt` and copied, reduced,
//! into `tests/regressions/`. Each test writes its coverage figures to `target/coverage/`.

use std::sync::Mutex;

use gpu_simulation::*;
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, TestCaseError, TestRunner};

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

fn report(sim: &Sim, ops: &[Op]) -> String {
    format!(
        "{} violation(s):\n{}\nops: {ops:#?}",
        sim.violations.len(),
        sim.violations
            .iter()
            .map(|v| format!("  [{}] {}", v.property, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Runs one property: each trace is replayed command by command under the full checker, then
/// drained.
fn run_property(
    name: &str,
    cases: u32,
    max_len: usize,
    strategy: impl Strategy<Value = Op>,
    cfg: gpu_domain::Config,
) {
    let config = ProptestConfig {
        cases,
        max_shrink_iters: 20_000,
        // Saved counterexamples are replayed first on every run.
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/properties/proptest-regressions.txt",
        ))),
        ..ProptestConfig::default()
    };
    let stats = Mutex::new(Stats::default());
    let mut runner = TestRunner::new(config);
    let result = runner.run(&prop::collection::vec(strategy, 1..max_len), |ops| {
        let mut sim = Sim::new(cfg.clone());
        for op in &ops {
            sim.run_op(op);
            if !sim.violations.is_empty() {
                return Err(TestCaseError::fail(report(&sim, &ops)));
            }
        }
        sim.drain();
        if !sim.violations.is_empty() {
            return Err(TestCaseError::fail(report(&sim, &ops)));
        }
        stats.lock().unwrap().add(&sim);
        Ok(())
    });
    let stats = stats.into_inner().unwrap();
    stats.write(name);
    if let Err(e) = result {
        panic!("{name}: {e}");
    }
}

/// All safety properties after each command, then liveness.
#[test]
fn invariants_hold_on_random_traces() {
    run_property("random", cases(), 160, op_strategy(), sim_config());
}

/// Long fault-heavy traces: more lost nodes, resumes and late claims.
#[test]
fn invariants_hold_under_heavy_faults() {
    run_property("faults", cases(), 220, fault_heavy_op(), sim_config());
}

/// Partial initial reserve: escrow can run out (JOB-R25, JOB-F10) and resumes need top-ups
/// (JOB-T12).
#[test]
fn invariants_hold_with_partial_reserve() {
    run_property(
        "partial_reserve",
        cases() / 2,
        200,
        fault_heavy_op(),
        gpu_domain::Config {
            initial_reserve_max: 40,
            ..sim_config()
        },
    );
}

/// Delivery: attested outputs, clients that never ack, lenders attesting themselves, lost buffers,
/// clients lying on resume, simultaneous faults.
#[test]
fn invariants_hold_under_delivery_adversaries() {
    run_property(
        "delivery",
        cases(),
        200,
        delivery_adversary_op(),
        sim_config(),
    );
}

/// Mix that pushes the normal path plus faults.
fn fault_heavy_op() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        2 => b().prop_map(Op::Reserve),
        3 => (b(), b(), b()).prop_map(|(job, rot, est)| Op::Place { job, rot, est }),
        3 => b().prop_map(|job| Op::Ready { job, correct: true }),
        2 => (b(), b(), b()).prop_map(|(job, stage, step)| Op::LeaseStep { job, stage, step }),
        2 => (b(), b()).prop_map(|(job, node)| Op::NodeHeartbeat { job, node }),
        1 => (b(), b()).prop_map(|(job, node)| Op::SilentNode { job, node }),
        2 => (b(), b(), prop::bool::weighted(0.2)).prop_map(|(job, stage, forged)| Op::Corroborate { job, stage, forged }),
        6 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        12 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        3 => (b(), b(), b()).prop_map(|(job, stage, wt)| Op::Commit { job, stage, wt, partial: false }),
        6 => (b(), b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, wt, pos, ev)| Op::Claim { job, slice, stage, wt, pos, ev, honest: true }),
        2 => (b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, amount, ev)| Op::ClaimRecovery { job, slice, stage, amount, ev }),
        3 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(|job| Op::StaleProduce { job }),
        2 => b().prop_map(Op::Pause),
        2 => (b(), b()).prop_map(|(job, topup)| Op::Resume { job, topup }),
        1 => (b(), b()).prop_map(|(job, amount)| Op::Fund { job, amount }),
        3 => (b(), b()).prop_map(|(job, slice)| Op::Close { job, slice }),
        3 => (b(), b()).prop_map(|(job, slice)| Op::Evaluate { job, slice }),
        2 => b().prop_map(Op::Tick),
        2 => Just(Op::Reconcile),
        2 => any::<u16>().prop_map(Op::Duplicate),
        1 => (b(), b()).prop_map(|(job, pair)| Op::Concurrent { job, pair }),
        1 => b().prop_map(Op::Finish),
        30 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        3 => (b(), b(), b(), b()).prop_map(|(job, slice, stage, pos)| Op::CrossAttemptClaim { job, slice, stage, pos }),
        3 => (b(), b(), b(), prop::bool::weighted(0.1)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        1 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        1 => (b(), b(), b(), b()).prop_map(|(job, slice, lender, pay)| Op::Arbitrate { job, slice, lender, pay: pay % 2 == 0 }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        9 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        10 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        2 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        3 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::ContestReplay { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::BoundaryBurst { job, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
        3 => (b(), b(), b()).prop_map(|(job, sel, sender)| Op::Impersonate { job, sel, sender }),
    ]
}

/// Delivery-focused mix: few acks, many attestations, client statements, lost witnesses and
/// simultaneous faults.
fn delivery_adversary_op() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        3 => b().prop_map(|job| Op::Ready { job, correct: true }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        2 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        8 => (b(), b(), b(), prop::bool::weighted(0.25)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        6 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        3 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::WitnessLost { job, prev }),
        3 => (b(), b()).prop_map(|(job, kind)| Op::DoubleFault { job, kind }),
        3 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(Op::Pause),
        2 => b().prop_map(Op::Finish),
        3 => b().prop_map(Op::Heartbeat),
        2 => (b(), b()).prop_map(|(job, node)| Op::NodeHeartbeat { job, node }),
        1 => (b(), b()).prop_map(|(job, node)| Op::SilentNode { job, node }),
        2 => (b(), b(), b()).prop_map(|(job, stage, step)| Op::LeaseStep { job, stage, step }),
        3 => (b(), b(), b()).prop_map(|(job, stage, wt)| Op::Commit { job, stage, wt, partial: false }),
        4 => (b(), b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, wt, pos, ev)| Op::Claim { job, slice, stage, wt, pos, ev, honest: true }),
        2 => b().prop_map(Op::Tick),
        2 => Just(Op::Reconcile),
        2 => any::<u16>().prop_map(Op::Duplicate),
        30 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        5 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        5 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        2 => b().prop_map(|job| Op::ContestUnderLiveResume { job }),
        4 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        3 => b().prop_map(Op::ClientHeartbeat),
        4 => (b(), b()).prop_map(|(job, sel)| Op::ContestReplay { job, sel }),
        1 => b().prop_map(|job| Op::ContestAtWindowEnd { job }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::BoundaryBurst { job, sel }),
        3 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
        3 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
        3 => (b(), b(), b()).prop_map(|(job, sel, sender)| Op::Impersonate { job, sel, sender }),
    ]
}

/// Coverage check: without it, properties could pass only because interesting paths are never
/// reached. Each path must be hit a minimum number of times.
#[test]
fn generator_reaches_interesting_paths() {
    use proptest::strategy::ValueTree;

    // 180 operations per trace (150 before per-node leases): starting a cluster now takes three
    // steps per lender and a corroboration per stage. The thresholds below did not move.
    const TRACE: usize = 180;
    let mut total = Stats::default();
    for (gen_name, n) in [("faults", 300usize), ("delivery", 300)] {
        let mut runner = TestRunner::deterministic();
        let mut st = Stats::default();
        for _ in 0..n {
            let ops = if gen_name == "faults" {
                prop::collection::vec(fault_heavy_op(), TRACE)
                    .new_tree(&mut runner)
                    .unwrap()
                    .current()
            } else {
                prop::collection::vec(delivery_adversary_op(), TRACE)
                    .new_tree(&mut runner)
                    .unwrap()
                    .current()
            };
            let mut sim = Sim::default();
            for op in &ops {
                sim.run_op(op);
            }
            sim.drain();
            st.add(&sim);
        }
        total.merge(&st);
    }
    total.write("generator_paths");
    let minimum = [
        ("resumes (running → recovering)", 200),
        ("attempts ≥ 2 started", 200),
        ("outputs charged on ack", 200),
        ("outputs charged provisionally (witness)", 200),
        ("provisional confirmed by client", 20),
        ("provisional confirmed by window expiry", 20),
        ("outputs replayed", 20),
        ("outputs voided (rewind)", 20),
        ("rewinds", 10),
        ("delivery contests opened", 30),
        ("late attestations admitted", 10),
        ("buffers purged after retention", 10),
        ("supplementary proofs", 5),
        ("contribution payments", 100),
        ("recovery payments", 20),
        ("contributions awaiting delivery", 30),
        ("contributions voided with their output", 3),
        ("items disputed", 10),
        ("payments by arbitration", 5),
        ("refunds by arbitration", 10),
        ("reward contests", 10),
        ("rewards released", 100),
        ("attempts revoked with an expired lease", 50),
        ("attempts revoked for one silent node", 10),
        ("restorations corroborated", 500),
        ("recovery held (cap or no corroboration)", 5),
    ];
    let missing: Vec<String> = minimum
        .iter()
        .filter(|(k, min)| total.counts.get(k).copied().unwrap_or(0) < *min)
        .map(|(k, min)| format!("{k}: {} < {min}", total.counts.get(k).copied().unwrap_or(0)))
        .collect();
    for refusal in [
        "InadmissibleProof",
        "LeaseExpired",
        "Precondition",
        "Unauthorized",
    ] {
        assert!(
            total.refusals.get(refusal).copied().unwrap_or(0) > 0,
            "generator never triggered a {refusal} refusal"
        );
    }
    assert!(missing.is_empty(), "generator under-covers: {missing:#?}");
}
