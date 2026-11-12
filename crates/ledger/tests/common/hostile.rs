//! The hostile orchestrator of TEST-P30: the calls it may try and what must hold after each.
//! Shared by the in-process run, the run over the link and the run against the daemon.

use gpu_ledger::*;
use more_identity::{lease_message, receipt_message, Readiness};
use proptest::prelude::*;

use super::*;

/// What the honest recipients really received on attempt 1.
pub const RECEIVED: u32 = 3;
/// The most the pool's admin agrees to relay for the job.
pub const RELAY: u64 = 60;

#[derive(Clone, Debug)]
pub enum Call {
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
    Corroborate {
        attempt: u8,
        producer: u8,
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
    /// Records the revocation of an attempt: its set of proofs is closed from then on.
    Revoke(u8),
    /// The honest clock service moves time forward: minutes, hours, or past the windows.
    Tick(u8),
    /// Settles on a few values only, so most sequences live long enough to pay.
    Settle(u8),
}

pub fn calls() -> impl Strategy<Value = Call> {
    let b = any::<u8>;
    prop_oneof![
        2 => (any::<bool>(), b()).prop_map(|(w, a)| Call::Reserve(w, a)),
        2 => (b(), b()).prop_map(|(a, s)| Call::Fund(a, s)),
        4 => (b(), b(), b()).prop_map(|(attempt, shape, earmark)| Call::Register { attempt, shape, earmark }),
        6 => (b(), b(), b()).prop_map(|(attempt, stage, signer)| Call::Accept { attempt, stage, signer }),
        5 => (b(), b(), b()).prop_map(|(attempt, stage, signer)| Call::Ready { attempt, stage, signer }),
                5 => (b(), b(), b()).prop_map(|(attempt, producer, signer)| Call::Corroborate { attempt, producer, signer }),
        6 => (b(), b(), b(), b()).prop_map(|(attempt, producer, upto, signer)| Call::Receipt { attempt, producer, upto, signer }),
        6 => (b(), b(), b()).prop_map(|(attempt, pos, gen)| Call::Charge { attempt, pos, gen }),
        2 => (b(), b()).prop_map(|(pos, gen)| Call::Void { pos, gen }),
        8 => (b(), b(), b(), b(), b()).prop_map(|(attempt, lender, pos, gen, stage)| Call::Contribution { attempt, lender, pos, gen, stage }),
        5 => (b(), b(), b(), b()).prop_map(|(attempt, lender, segment, amount)| Call::Recovery { attempt, lender, segment, amount }),
        10 => (b(), b(), b(), b(), b(), b()).prop_map(|(attempt, lender, item, pos, gen, stage)| Call::Pay { attempt, lender, item, pos, gen, stage }),
        4 => (b(), b(), b(), b(), b(), b()).prop_map(|(attempt, lender, item, pos, gen, stage)| Call::Refund { attempt, lender, item, pos, gen, stage }),
        6 => (b(), b()).prop_map(|(attempt, lender)| Call::Release { attempt, lender }),
        3 => (b(), b()).prop_map(|(attempt, lender)| Call::Contest { attempt, lender }),
                2 => b().prop_map(Call::ReturnEarmark),
        1 => b().prop_map(Call::Revoke),
        6 => b().prop_map(Call::Tick),
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

pub fn apply(w: &mut World, c: &Call) -> Res {
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
            let signature = key(signer(honest, s)).sign(&lease_message(&dom(), &rec.assignment));
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
            let r = Readiness {
                job: JOB,
                attempt,
                lender: honest.unwrap_or(MALLORY),
                restored: [0; 3],
                state: STATE,
                segments: SEGS.to_vec(),
            };
            w.ready_with(stage, &r, signer(honest, s))
        }
        Call::Corroborate {
            attempt,
            producer,
            signer: s,
        } => {
            let attempt = att_of(w, attempt);
            let producer = lender_of(w, attempt, producer);
            // An honest recipient attests a restoration only if it received the restored state,
            // which the attacker's account never sends.
            let recipient = w.escrow().attempts.get(&attempt).and_then(|r| {
                let stage = r.stage_of(producer)?;
                r.recipient_of(stage)
            });
            let honest = recipient.filter(|_| producer != MALLORY);
            let Some(rec) = w.escrow().attempts.get(&attempt).cloned() else {
                return Err(LedgerApiError::Invalid("test: unknown attempt"));
            };
            let Some(stage) = rec.stage_of(producer) else {
                return Err(LedgerApiError::Invalid("test: not a lender"));
            };
            // The recipient names what it received: all segments, a prefix, or some of them.
            let named: &[u32] = match s / 4 % 6 {
                0 | 1 => &[0, 1, 2],
                2 => &[0],
                3 => &[0, 1],
                4 => &[0, 2],
                _ => &[1],
            };
            let r = restoration_of(&rec.assignment, stage as u32, named, STATE);
            w.corroborate_with(&r, signer(honest, s))
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
            // The attacker's account never produces anything, so nobody honest signs for it, and
            // an honest recipient only signs the true digest (0). The attacker, where it is the
            // recipient, may try a second digest for the same coverage.
            let digest = u64::from(s / 4 % 4 == 0);
            let honest = recipient
                .filter(|_| attempt == 1 && upto <= RECEIVED && producer != MALLORY && digest == 0);
            let m = receipt_message(&dom(), JOB, attempt, producer, WT, upto, digest);
            w.run(LedgerOp::RecordReceipt {
                job: JOB,
                attempt,
                producer,
                wt: WT,
                upto,
                digest,
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
        Call::Revoke(a) => {
            // Mostly an older attempt, as the honest scheduler would when it places the next one.
            let known: Vec<u32> = w.escrow().attempts.keys().copied().collect();
            let older = known.len().checked_sub(2).and_then(|i| known.get(i));
            match older {
                _ if a % 8 == 0 => w.revoke(att_of(w, a)),
                Some(older) => w.revoke(*older),
                None => Err(LedgerApiError::Invalid("test: nothing older")),
            }
        }
        Call::Tick(sel) => {
            w.advance(match sel % 6 {
                0 => 8 * 24 * HOUR,
                1 | 2 => 49 * HOUR,
                3 => 20 * HOUR,
                _ => 600,
            });
            Ok(LedgerOutcome::Done)
        }
        Call::Settle(sel) if sel < 24 => w.run(LedgerOp::SettleJob { job: JOB }),
        Call::Settle(_) => Err(LedgerApiError::Invalid("test: not now")),
    }
}

/// What must hold after every call, accepted or refused.
pub fn check(w: &World, c: &Call) -> Result<(), TestCaseError> {
    let ledger = w.ledger.audit_view(&w.auditor).unwrap();
    prop_assert!(ledger.check_invariants().is_empty(), "{c:?}");
    // A bystander's balance never moves, and the attacker's account never receives a credit:
    // a contribution takes a receipt from an honest recipient, recovery a restoration that an
    // honest recipient corroborated (JOB-R18).
    prop_assert_eq!(w.bal(Account::User(BOB)), 1_000, "{:?}", c);
    prop_assert_eq!(w.bal(Account::User(MALLORY)), 0, "{:?}", c);
    let e = w.escrow();
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
        // A share that holds or took money keeps its output charged: no void under it.
        if let ItemId::Contribution { output, gen, .. } = id {
            let charged = e.outputs.get(output).and_then(|o| o.charged);
            prop_assert_eq!(
                charged,
                Some((it.line.attempt, *gen)),
                "{:?} after {:?}",
                id,
                c
            );
        }
        match id {
            ItemId::Contribution { output, .. } if it.state == ItemState::Paid => {
                let r = e
                    .receipts
                    .get(&(it.line.attempt, it.line.lender, output.wt));
                let covered = r.is_some_and(|m| m.keys().any(|u| *u > output.pos));
                prop_assert!(covered, "{id:?} after {c:?}");
            }
            ItemId::Recovery { segment, .. } => {
                prop_assert!(a.ready.iter().all(|r| *r), "{id:?} after {c:?}");
                // Paid only for a segment the recipient named, in a corroboration recorded before
                // the attempt's revocation.
                let proven = s.is_some_and(|s| {
                    a.corroborates(s, *segment)
                        && a.corroborated[s]
                            .as_ref()
                            .is_some_and(|c| a.revoked.is_none_or(|r| c.seq < r))
                });
                prop_assert!(it.state != ItemState::Paid || proven, "{id:?} after {c:?}");
            }
            ItemId::Contribution { .. } => {}
        }
    }
    Ok(())
}

/// LEDGER-018: what was recorded stays recorded, a revoked attempt takes no new proof, and a held
/// payment leaves through its own cycle only: released after its hold, contested before its
/// limit, each counted from that payment on the ledger's own clock.
pub fn finality(before: &Escrow, now: u64, w: &World, c: &Call) -> Result<(), TestCaseError> {
    let after = w.escrow();
    let limits = w.ledger.limits();
    for (key, old) in &before.receipts {
        for (upto, digest) in old {
            let kept = after.receipts.get(key).and_then(|r| r.get(upto));
            prop_assert_eq!(kept, Some(digest), "receipt replaced by {:?}", c);
        }
    }
    for (n, a) in &before.attempts {
        let b = &after.attempts[n];
        for s in 0..a.accepted.len() {
            prop_assert!(!a.accepted[s] || b.accepted[s], "{c:?}");
            prop_assert!(
                !a.ready[s] || (b.ready[s] && b.state[s] == a.state[s]),
                "{c:?}"
            );
            let kept = a.corroborated[s].is_none() || b.corroborated[s] == a.corroborated[s];
            prop_assert!(kept, "corroboration replaced by {:?}", c);
        }
        if a.revoked.is_some() {
            let same = (&b.accepted, &b.ready, &b.corroborated, b.revoked)
                == (&a.accepted, &a.ready, &a.corroborated, a.revoked);
            prop_assert!(same, "{c:?} added a proof to a revoked attempt");
        }
    }
    let mut left: Vec<u64> = Vec::new();
    for (id, old) in &before.items {
        let new = &after.items[id];
        match old.state {
            ItemState::Reserved => {}
            ItemState::Refunded => prop_assert_eq!(new.state, ItemState::Refunded, "{:?}", c),
            ItemState::Paid => {
                prop_assert_eq!(new.state, ItemState::Paid, "{:?} undid a payment", c);
                prop_assert_eq!((new.amount, new.paid_at), (old.amount, old.paid_at));
                prop_assert!(new.rewarded || !old.rewarded, "{c:?} reopened a reward");
                if new.rewarded && !old.rewarded {
                    left.extend(old.paid_at);
                }
            }
        }
    }
    for paid_at in left {
        match c {
            Call::Release { .. } => {
                prop_assert!(
                    now >= paid_at + limits.reward_hold,
                    "a payment released inside its own window"
                );
            }
            Call::Contest { .. } => {
                prop_assert!(
                    now < paid_at + limits.contest_limit,
                    "a payment contested past its own limit"
                );
            }
            other => prop_assert!(false, "{other:?} closed a held reward"),
        }
    }
    // No payment is ever stuck: while held, it can be contested, released, or both.
    for it in after.items.values() {
        if let (ItemState::Paid, false, Some(t)) = (it.state, it.rewarded, it.paid_at) {
            let now = w.ledger.now();
            prop_assert!(
                now < t + limits.contest_limit || now >= t + limits.reward_hold,
                "held payment with no way out"
            );
        }
    }
    Ok(())
}
