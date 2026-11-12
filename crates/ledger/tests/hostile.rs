//! TEST-P30: the Ledger under a hostile orchestrator. Random sequences of public API calls, all
//! with a valid Orchestrator credential, none going through the coordinator.
//!
//! Threat model. The attacker holds the orchestrator's credential and the key of one registered
//! account (`MALLORY`), which it may place as a lender. The owner, the lenders `L1` and `L2` and
//! the witness are honest: a lender signs a lease or its readiness only when the attempt names
//! it, and a recipient signs a receipt only for what it received (attempt 1, outputs `0..3`, from
//! an honest producer), and corroborates a restoration only from an honest producer. The pool's
//! admin agrees to relay at most 60 credits.
//! Out of scope: an attacker that also holds the keys of every recipient of its own stage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::hostile::*;
use common::*;
use gpu_ledger::*;
use proptest::prelude::*;

/// 512 sequences by default; `PROPTEST_CASES` overrides it for long campaigns.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn p30_hostile_orchestrator_never_moves_credits_it_should_not(
        seq in prop::collection::vec(calls(), 1..120)
    ) {
        let mut w = world();
        w.open(JOB, 500).unwrap();
                for c in &seq {
            let before = w.balances();
            let records = w.escrow().clone();
            let now = w.ledger.now();
            if apply(&mut w, c).is_err() {
                // A refused call leaves no trace, in the journal or in the job records.
                prop_assert_eq!(&before, &w.balances(), "{:?}", c);
                prop_assert_eq!(&records, w.escrow(), "{:?}", c);
            }
            check(&w, c)?;
            finality(&records, now, &w, c)?;
        }
        // Closure is always reachable once the open items are decided, and it is final.
        let open: Vec<(ItemId, LineRef)> = w
            .escrow()
            .items
            .iter()
            .filter(|(_, i)| i.state == ItemState::Reserved)
            .map(|(id, i)| (*id, i.line))
            .collect();
        for (item, line) in open {
            w.run(LedgerOp::RefundLine { line, item }).unwrap();
        }
        if !w.escrow().settled {
            w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
        }
        check(&w, &Call::Settle(0))?;
    }
}

/// The generator is not vacuous: over a fixed set of sequences, every kind of call is accepted at
/// least once, payments and settlement included.
#[test]
fn p30_generator_reaches_every_operation() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    let strat = prop::collection::vec(calls(), 100..200);
    let mut accepted = std::collections::BTreeMap::<String, u32>::new();
    for _ in 0..2_000 {
        let seq = strat.new_tree(&mut runner).unwrap().current();
        let mut w = world();
        w.open(JOB, 500).unwrap();
        for c in &seq {
            if apply(&mut w, c).is_ok() {
                let name = format!("{c:?}");
                let name = name.split([' ', '(']).next().unwrap().to_string();
                *accepted.entry(name).or_default() += 1;
            }
        }
        // Both kinds of payment happen, so their proofs are really exercised.
        for (id, it) in &w.escrow().items {
            if it.state == ItemState::Paid {
                let kind = match id {
                    ItemId::Contribution { .. } => "paid contributions",
                    ItemId::Recovery { .. } => "paid recovery items",
                };
                *accepted.entry(kind.to_string()).or_default() += 1;
            }
        }
    }
    for kind in [
        "Reserve",
        "Fund",
        "Register",
        "Accept",
        "Ready",
        "Corroborate",
        "Receipt",
        "Charge",
        "Void",
        "Contribution",
        "Recovery",
        "Pay",
        "Refund",
        "Release",
        "Contest",
        "ReturnEarmark",
        "Revoke",
        "Settle",
        "Tick",
        "paid contributions",
        "paid recovery items",
    ] {
        assert!(
            accepted.get(kind).copied().unwrap_or(0) > 0,
            "{kind} never accepted: {accepted:?}"
        );
    }
    println!("accepted calls: {accepted:?}");
}
