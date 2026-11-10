//! TEST-P30: the Ledger under a hostile orchestrator. Random sequences of public API calls, all
//! with a valid Orchestrator credential, none going through the coordinator.
//!
//! Threat model. The attacker holds the orchestrator's credential and the key of one registered
//! account (`MALLORY`), which it may place as a lender. The owner, the lenders `L1` and `L2` and
//! the witness are honest: a lender signs a lease or its readiness only when the attempt names
//! it, and a recipient signs a receipt only for what it received (attempt 1, outputs `0..3`, from
//! an honest producer). The pool's admin agrees to relay at most 60 credits.
//! Out of scope: an attacker that also holds the keys of every recipient of its own stage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gpu_ledger::*;
use more_identity::{lease_message, ready_message, receipt_message};
use proptest::prelude::*;

/// What the honest recipients really received on attempt 1.
const RECEIVED: u32 = 3;
/// The most the pool's admin agrees to relay for the job.
const RELAY: u64 = 60;

#[derive(Clone, Debug)]
enum Call {
    Reserve(bool, u8),
    Fund(u8, u8),
    Register {
        attempt: u8,
        shape: u8,
        earmark: u8,
    },
    Accept {
        attempt: u8,
        stage: u8,
        signer: u8,
    },
    Ready {
        attempt: u8,
        stage: u8,
        signer: u8,
    },
    Receipt {
        attempt: u8,
        producer: u8,
        upto: u8,
        signer: u8,
    },
    Charge {
        attempt: u8,
        pos: u8,
        gen: u8,
    },
    Void {
        pos: u8,
        gen: u8,
    },
    Contribution {
        attempt: u8,
        lender: u8,
        pos: u8,
        gen: u8,
        stage: u8,
    },
    Recovery {
        attempt: u8,
        lender: u8,
        segment: u8,
        amount: u8,
    },
    Pay {
        attempt: u8,
        lender: u8,
        item: u8,
        pos: u8,
        gen: u8,
        stage: u8,
    },
    Refund {
        attempt: u8,
        lender: u8,
        item: u8,
        pos: u8,
        gen: u8,
        stage: u8,
    },
    Release {
        attempt: u8,
        lender: u8,
    },
    Contest {
        attempt: u8,
        lender: u8,
    },
    ReturnEarmark(u8),
    /// Settles on a few values only, so most sequences live long enough to pay.
    Settle(u8),
}

fn calls() -> impl Strategy<Value = Call> {
    let b = any::<u8>;
    prop_oneof![
        2 => (any::<bool>(), b()).prop_map(|(w, a)| Call::Reserve(w, a)),
        2 => (b(), b()).prop_map(|(a, s)| Call::Fund(a, s)),
        4 => (b(), b(), b()).prop_map(|(attempt, shape, earmark)| Call::Register { attempt, shape, earmark }),
        6 => (b(), b(), b()).prop_map(|(attempt, stage, signer)| Call::Accept { attempt, stage, signer }),
        5 => (b(), b(), b()).prop_map(|(attempt, stage, signer)| Call::Ready { attempt, stage, signer }),
        6 => (b(), b(), b(), b()).prop_map(|(attempt, producer, upto, signer)| Call::Receipt { attempt, producer, upto, signer }),
        6 => (b(), b(), b()).prop_map(|(attempt, pos, gen)| Call::Charge { attempt, pos, gen }),
        2 => (b(), b()).prop_map(|(pos, gen)| Call::Void { pos, gen }),
        8 => (b(), b(), b(), b(), b()).prop_map(|(attempt, lender, pos, gen, stage)| Call::Contribution { attempt, lender, pos, gen, stage }),
        5 => (b(), b(), b(), b()).prop_map(|(attempt, lender, segment, amount)| Call::Recovery { attempt, lender, segment, amount }),
        8 => (b(), b(), b(), b(), b(), b()).prop_map(|(attempt, lender, item, pos, gen, stage)| Call::Pay { attempt, lender, item, pos, gen, stage }),
        4 => (b(), b(), b(), b(), b(), b()).prop_map(|(attempt, lender, item, pos, gen, stage)| Call::Refund { attempt, lender, item, pos, gen, stage }),
        4 => (b(), b()).prop_map(|(attempt, lender)| Call::Release { attempt, lender }),
        3 => (b(), b()).prop_map(|(attempt, lender)| Call::Contest { attempt, lender }),
        2 => b().prop_map(Call::ReturnEarmark),
        1 => b().prop_map(Call::Settle),
    ]
}

const PEOPLE: [u32; 5] = [L1, L2, MALLORY, WIT, ALICE];

fn who(sel: u8) -> u32 {
    PEOPLE[usize::from(sel) % PEOPLE.len()]
}

/// Selectors are resolved against what exists most of the time (so sequences reach payments),
/// and left arbitrary one time in four (so nonsense is tried too).
fn real(sel: u8) -> bool {
    sel % 4 != 3
}

fn pick<T: Copy>(xs: &[T], sel: u8) -> Option<T> {
    (!xs.is_empty()).then(|| xs[usize::from(sel / 4) % xs.len()])
}

fn att_of(w: &World, sel: u8) -> u32 {
    let known: Vec<u32> = w.escrow().attempts.keys().copied().collect();
    match pick(&known, sel) {
        Some(a) if real(sel) => a,
        _ => 1 + u32::from(sel % 3),
    }
}

fn lender_of(w: &World, attempt: u32, sel: u8) -> u32 {
    let lenders = w
        .escrow()
        .attempts
        .get(&attempt)
        .map(|a| a.assignment.lenders.clone())
        .unwrap_or_default();
    match pick(&lenders, sel) {
        Some(l) if real(sel) => l,
        _ => who(sel),
    }
}

/// An existing reserved item and its line, or an arbitrary one.
fn some_item(w: &World, c: (u8, u8, u8, u8, u8, u8)) -> (LineRef, ItemId) {
    let (attempt, lender, i, pos, gen, stage) = c;
    let open: Vec<(LineRef, ItemId)> = w
        .escrow()
        .items
        .iter()
        .filter(|(_, it)| it.state == ItemState::Reserved)
        .map(|(id, it)| (it.line, *id))
        .collect();
    match pick(&open, i) {
        Some(x) if real(i) => x,
        _ => {
            let a = att_of(w, attempt);
            (
                line(a, lender_of(w, a, lender)),
                item(i, a, pos, gen, stage),
            )
        }
    }
}

/// A line with a held reward, or an arbitrary one.
fn some_line(w: &World, attempt: u8, lender: u8) -> LineRef {
    let held: Vec<LineRef> = w
        .escrow()
        .items
        .values()
        .filter(|it| it.state == ItemState::Paid && !it.rewarded)
        .map(|it| it.line)
        .collect();
    match pick(&held, lender) {
        Some(l) if real(lender) => l,
        _ => {
            let a = att_of(w, attempt);
            line(a, lender_of(w, a, lender))
        }
    }
}

/// Clusters the attacker may try to place, valid or not.
fn shape(sel: u8) -> (Vec<u32>, Vec<u32>) {
    match sel % 7 {
        0 | 1 => (vec![L1, L2], vec![3, 1]),
        2 => (vec![L2, L1], vec![2, 2]),
        3 => (vec![L1, MALLORY], vec![3, 1]),
        4 => (vec![MALLORY, L2], vec![1, 3]),
        5 => (vec![MALLORY], vec![4]),
        _ => (vec![L1, L2], vec![3, 3]),
    }
}

/// The key that signs: the honest account `honest` if it would sign this, otherwise the
/// attacker's. `signer % 4 == 0` forces the attacker's key.
fn signer(honest: Option<u32>, sel: u8) -> u32 {
    match honest {
        Some(a) if !sel.is_multiple_of(4) && a != MALLORY => a,
        _ => MALLORY,
    }
}

fn item(sel: u8, attempt: u32, pos: u8, gen: u8, stage: u8) -> ItemId {
    if sel.is_multiple_of(3) {
        ItemId::Recovery {
            attempt,
            segment: u32::from(pos % 3),
        }
    } else {
        ItemId::Contribution {
            output: out(u32::from(pos % 5)),
            gen: u32::from(gen % 2),
            stage: u32::from(stage % 2),
        }
    }
}

fn apply(w: &mut World, c: &Call) -> Res {
    match *c {
        Call::Reserve(work, a) => w.reserve(
            if work {
                EscrowBucket::Work
            } else {
                EscrowBucket::Recovery
            },
            u64::from(a % 40),
        ),
        Call::Fund(a, s) => {
            // The honest admin agrees to relay up to `RELAY` in total for this job.
            let amount = u64::from(a % 40);
            let agreed = w.escrow().pool_funded + amount <= RELAY;
            w.fund_signed(amount, signer(agreed.then_some(ADMIN), s))
        }
        Call::Register {
            attempt,
            shape: s,
            earmark,
        } => {
            let (lenders, layout) = shape(s);
            let next = w.escrow().attempts.keys().next_back().map_or(1, |n| n + 1);
            let n = if real(attempt) {
                next
            } else {
                1 + u32::from(attempt % 3)
            };
            let a = assignment(n, &lenders, &layout, u64::from(earmark % 30));
            w.run(LedgerOp::RegisterAttempt { assignment: a })
        }
        Call::Accept {
            attempt,
            stage,
            signer: s,
        } => {
            let stage = u32::from(stage % 2);
            let attempt = att_of(w, attempt);
            let Some(rec) = w.escrow().attempts.get(&attempt).cloned() else {
                return Err(LedgerApiError::Invalid("test: unknown attempt"));
            };
            // An honest lender signs the assignment that names it.
            let honest = rec.assignment.lenders.get(stage as usize).copied();
            let signature = key(signer(honest, s)).sign(&lease_message(&rec.assignment));
            w.run(LedgerOp::AcceptLease {
                job: JOB,
                attempt,
                stage,
                signature,
            })
        }
        Call::Ready {
            attempt,
            stage,
            signer: s,
        } => {
            let stage = u32::from(stage % 2);
            let attempt = att_of(w, attempt);
            let Some(rec) = w.escrow().attempts.get(&attempt).cloned() else {
                return Err(LedgerApiError::Invalid("test: unknown attempt"));
            };
            let honest = rec.assignment.lenders.get(stage as usize).copied();
            let lender = honest.unwrap_or(MALLORY);
            let m = ready_message(JOB, attempt, lender, [0; 3]);
            w.run(LedgerOp::LeaseReady {
                job: JOB,
                attempt,
                stage,
                restored: [0; 3],
                signature: key(signer(honest, s)).sign(&m),
            })
        }
        Call::Receipt {
            attempt,
            producer,
            upto,
            signer: s,
        } => {
            let attempt = att_of(w, attempt);
            let (producer, upto) = (lender_of(w, attempt, producer), u32::from(upto % 6));
            // An honest recipient signs only for what it received.
            let recipient = w.escrow().attempts.get(&attempt).and_then(|r| {
                let stage = r.stage_of(producer)?;
                r.recipient_of(stage)
            });
            // The attacker's account never produces anything, so nobody honest signs for it.
            let honest =
                recipient.filter(|_| attempt == 1 && upto <= RECEIVED && producer != MALLORY);
            let m = receipt_message(JOB, attempt, producer, WT, upto, 0);
            w.run(LedgerOp::RecordReceipt {
                job: JOB,
                attempt,
                producer,
                wt: WT,
                upto,
                digest: 0,
                signature: key(signer(honest, s)).sign(&m),
            })
        }
        Call::Charge { attempt, pos, gen } => {
            let output = out(u32::from(pos % 5));
            let next = w.escrow().outputs.get(&output).map_or(0, |o| o.next_gen);
            w.run(LedgerOp::ChargeOutput {
                job: JOB,
                attempt: att_of(w, attempt),
                output,
                gen: if real(gen) { next } else { u32::from(gen % 2) },
            })
        }
        Call::Void { pos, gen } => w.run(LedgerOp::VoidOutput {
            job: JOB,
            output: out(u32::from(pos % 5)),
            gen: u32::from(gen % 2),
        }),
        Call::Contribution {
            attempt,
            lender,
            pos,
            gen,
            stage,
        } => {
            // Mostly a charged output, on its own attempt, for the lender of the stage.
            let charged: Vec<(OutputRef, u32, u32)> = w
                .escrow()
                .outputs
                .iter()
                .filter_map(|(o, r)| r.charged.map(|(a, g)| (*o, a, g)))
                .collect();
            let stage = u32::from(stage % 2);
            let (output, a, g) = match pick(&charged, pos) {
                Some(x) if real(pos) => x,
                _ => (
                    out(u32::from(pos % 5)),
                    att_of(w, attempt),
                    u32::from(gen % 2),
                ),
            };
            let holder = w
                .escrow()
                .attempts
                .get(&a)
                .and_then(|r| r.assignment.lenders.get(stage as usize).copied());
            let lender = match holder {
                Some(l) if real(lender) => l,
                _ => who(lender),
            };
            w.run(LedgerOp::ReserveContribution {
                line: line(a, lender),
                output,
                gen: g,
                stage,
            })
        }
        Call::Recovery {
            attempt,
            lender,
            segment,
            amount,
        } => {
            let a = att_of(w, attempt);
            w.run(LedgerOp::ReserveRecovery {
                line: line(a, lender_of(w, a, lender)),
                segment: u32::from(segment % 3),
                amount: u64::from(amount % 25),
            })
        }
        Call::Pay {
            attempt,
            lender,
            item: i,
            pos,
            gen,
            stage,
        } => {
            let (line, item) = some_item(w, (attempt, lender, i, pos, gen, stage));
            w.run(LedgerOp::PayLine { line, item })
        }
        Call::Refund {
            attempt,
            lender,
            item: i,
            pos,
            gen,
            stage,
        } => {
            let (line, item) = some_item(w, (attempt, lender, i, pos, gen, stage));
            w.run(LedgerOp::RefundLine { line, item })
        }
        Call::Release { attempt, lender } => {
            let line = some_line(w, attempt, lender);
            w.run(LedgerOp::ReleaseReward { line })
        }
        Call::Contest { attempt, lender } => {
            let line = some_line(w, attempt, lender);
            w.run(LedgerOp::ContestReward { line })
        }
        Call::ReturnEarmark(a) => w.run(LedgerOp::ReturnEarmark {
            job: JOB,
            attempt: att_of(w, a),
        }),
        Call::Settle(sel) if sel < 24 => w.run(LedgerOp::SettleJob { job: JOB }),
        Call::Settle(_) => Err(LedgerApiError::Invalid("test: not now")),
    }
}

/// What must hold after every call, accepted or refused.
fn check(w: &World, c: &Call) -> Result<(), TestCaseError> {
    let ledger = w.ledger.audit_view(&w.auditor).unwrap();
    prop_assert!(ledger.check_invariants().is_empty(), "{c:?}");
    // A bystander's balance never moves. The attacker's account is never paid a contribution:
    // that takes a receipt from an honest recipient. Known limit (JOB-R18, see the audit): placed
    // as a lender of an attempt whose lenders all sign ready, it can claim recovery, within the
    // budget the owner and the pool's admin agreed to.
    prop_assert_eq!(w.bal(Account::User(BOB)), 1_000, "{:?}", c);
    let e = w.escrow();
    let budget = i128::from(e.owner_recovery) + i128::from(e.pool_funded);
    prop_assert!(w.bal(Account::User(MALLORY)) <= budget, "{c:?}");
    let paid_contribution = e.items.iter().any(|(id, it)| {
        matches!(id, ItemId::Contribution { .. })
            && it.line.lender == MALLORY
            && it.state == ItemState::Paid
    });
    prop_assert!(!paid_contribution, "{c:?}");
    // The pool's treasury never relays more than its admin agreed to.
    prop_assert!(e.pool_funded <= RELAY, "{c:?}");
    // The owner never ends with more than it had: pool credits never become the owner's.
    prop_assert!(w.bal(Account::User(ALICE)) <= 1_000, "{c:?}");
    let reserved: i128 = e
        .items
        .values()
        .filter(|i| i.state == ItemState::Reserved)
        .map(|i| i128::from(i.amount))
        .sum();
    let in_lines: i128 = ledger
        .accounts()
        .filter(|(a, _)| matches!(a, Account::SliceLine { .. }))
        .map(|(_, b)| *b)
        .sum();
    prop_assert_eq!(reserved, in_lines, "{:?}", c);
    // The pool is never out of more than it relayed, and once the job is settled, of more than
    // the Ledger paid from its relay to lenders that signed ready.
    let pool = w.bal(Account::PoolReserve(POOL));
    prop_assert!(pool >= 1_000 - i128::from(e.pool_funded), "{c:?}");
    prop_assert!(e.recovery_paid_pool <= e.pool_funded, "{c:?}");
    if e.settled {
        prop_assert!(pool >= 1_000 - i128::from(e.recovery_paid_pool), "{c:?}");
        prop_assert_eq!(reserved, 0, "{:?}", c);
        for a in [
            Account::EscrowWork(JOB),
            Account::EscrowRecovery(JOB),
            Account::OutputHold(JOB),
        ] {
            prop_assert_eq!(w.bal(a), 0, "{:?} after {:?}", a, c);
        }
    }
    // Every item that holds or took money belongs to a lender that signed its lease; every paid
    // contribution has its recipient's receipt; every recovery a lender that signed ready.
    for (id, it) in e
        .items
        .iter()
        .filter(|(_, i)| i.state != ItemState::Refunded)
    {
        let a = &e.attempts[&it.line.attempt];
        let s = a.stage_of(it.line.lender);
        prop_assert!(s.is_some_and(|s| a.accepted[s]), "{id:?} after {c:?}");
        match id {
            ItemId::Contribution { output, .. } if it.state == ItemState::Paid => {
                let r = e
                    .receipts
                    .get(&(it.line.attempt, it.line.lender, output.wt));
                prop_assert!(r.is_some_and(|u| *u > output.pos), "{id:?} after {c:?}");
            }
            ItemId::Recovery { .. } => {
                prop_assert!(s.is_some_and(|s| a.ready[s]), "{id:?} after {c:?}");
            }
            ItemId::Contribution { .. } => {}
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn p30_hostile_orchestrator_never_moves_credits_it_should_not(
        seq in prop::collection::vec(calls(), 1..120)
    ) {
        let mut w = world();
        w.open(JOB, 500).unwrap();
        for c in &seq {
            let before = w.balances();
            let records = w.escrow().clone();
            if apply(&mut w, c).is_err() {
                // A refused call leaves no trace, in the journal or in the job records.
                prop_assert_eq!(&before, &w.balances(), "{:?}", c);
                prop_assert_eq!(&records, w.escrow(), "{:?}", c);
            }
            check(&w, c)?;
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
    }
    for kind in [
        "Reserve",
        "Fund",
        "Register",
        "Accept",
        "Ready",
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
        "Settle",
    ] {
        assert!(
            accepted.get(kind).copied().unwrap_or(0) > 0,
            "{kind} never accepted: {accepted:?}"
        );
    }
    println!("accepted calls: {accepted:?}");
}
