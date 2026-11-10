//! What the Ledger holds against a compromised orchestrator (second audit; LEDGER-013 to
//! LEDGER-016). Every test calls the public API directly with a valid Orchestrator credential:
//! the honest coordinator is not in the loop.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gpu_ledger::*;

fn contribution(pos: u32, stage: u32) -> ItemId {
    ItemId::Contribution {
        output: out(pos),
        gen: 0,
        stage,
    }
}

fn reserve_contribution(w: &mut World, attempt: u32, lender: u32, pos: u32, stage: u32) -> Res {
    w.run(LedgerOp::ReserveContribution {
        line: line(attempt, lender),
        output: out(pos),
        gen: 0,
        stage,
    })
}

fn reserve_recovery(w: &mut World, attempt: u32, lender: u32, segment: u32, amount: Amount) -> Res {
    w.run(LedgerOp::ReserveRecovery {
        line: line(attempt, lender),
        segment,
        amount,
    })
}

/// A resumed attempt 2 on the same lenders with `earmark`, both ready, each restoration
/// corroborated by its recipient (L2 for L1, the witness for L2).
fn resumed(w: &mut World, earmark: Amount) -> Assignment {
    let a = assignment(2, &[L1, L2], &[3, 1], earmark);
    w.place(&a);
    w.ready(&a, 0, L1).unwrap();
    w.ready(&a, 1, L2).unwrap();
    w.corroborate(&a, 0, L2).unwrap();
    w.corroborate(&a, 1, WIT).unwrap();
    a
}

/// Finding 1: a reserve funded by the recovery budget goes back to it, and the pool's relay
/// never ends with the owner. The request has no field to say otherwise.
#[test]
fn r2_recovery_reserve_goes_back_where_it_came_from() {
    let (mut w, _) = World::running();
    w.fund(50).unwrap();
    resumed(&mut w, 60);
    reserve_recovery(&mut w, 2, L1, 0, 60).unwrap();
    assert_eq!(w.bal(Account::EscrowRecovery(JOB)), 10);
    let item = ItemId::Recovery {
        attempt: 2,
        segment: 0,
    };
    w.run(LedgerOp::RefundLine {
        line: line(2, L1),
        item,
    })
    .unwrap();
    assert_eq!(w.bal(Account::EscrowRecovery(JOB)), 70);
    assert_eq!(w.bal(Account::OutputHold(JOB)), 0);
    let out = w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
    assert_eq!(
        out,
        LedgerOutcome::Settled {
            to_pool: 50,
            to_owner: 120
        }
    );
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 1_000);
    assert_eq!(w.bal(Account::User(ALICE)), 1_000);
}

/// Finding 1, shorter path: the caller no longer states the pool's share at settlement.
#[test]
fn r2_settlement_computes_the_pool_share() {
    let (mut w, _) = World::running();
    w.fund(50).unwrap();
    w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 1_000);
    assert_eq!(w.bal(Account::User(ALICE)), 1_000);
}

/// Recovery is paid from the owner's budget first, then the pool's relay; a contest gives each
/// payer its own share back, and settlement returns to the pool only what it did not pay.
#[test]
fn r2_recovery_split_and_contest_follow_the_ledgers_records() {
    let (mut w, _) = World::running();
    w.fund(50).unwrap();
    resumed(&mut w, 60);
    reserve_recovery(&mut w, 2, L1, 0, 30).unwrap();
    reserve_recovery(&mut w, 2, L2, 1, 25).unwrap();
    let pay = |w: &mut World, lender, segment| {
        w.run(LedgerOp::PayLine {
            line: line(2, lender),
            item: ItemId::Recovery {
                attempt: 2,
                segment,
            },
        })
        .unwrap()
    };
    // Owner budget is 20: the first payment takes it all and 10 from the pool.
    assert_eq!(
        pay(&mut w, L1, 0),
        LedgerOutcome::Paid {
            amount: 30,
            pool_part: 10
        }
    );
    assert_eq!(
        pay(&mut w, L2, 1),
        LedgerOutcome::Paid {
            amount: 25,
            pool_part: 25
        }
    );
    // Contesting L1's reward: 10 back to the pool, 20 to the owner.
    assert_eq!(
        w.run(LedgerOp::ContestReward { line: line(2, L1) })
            .unwrap(),
        LedgerOutcome::Contested {
            to_pool: 10,
            to_owner: 20
        }
    );
    w.advance(48 * HOUR);
    w.run(LedgerOp::ReleaseReward { line: line(2, L2) })
        .unwrap();
    w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
    // The pool paid 25 to L2 and nothing else; the owner paid nothing in the end.
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 975);
    assert_eq!(w.bal(Account::User(ALICE)), 1_000);
    assert_eq!(w.bal(Account::User(L2)) + w.bal(Account::Commission), 25);
}

/// Finding 2: no closure while an item is undecided, and nothing written to the job's escrow,
/// hold or lines after closure.
#[test]
fn r2_settlement_waits_for_every_item_and_is_final() {
    let (mut w, a) = World::running();
    w.charge(1, 0).unwrap();
    reserve_contribution(&mut w, 1, L1, 0, 0).unwrap();
    assert_eq!(
        w.run(LedgerOp::SettleJob { job: JOB }).unwrap_err(),
        LedgerApiError::OpenItems(JOB)
    );
    w.run(LedgerOp::RefundLine {
        line: line(1, L1),
        item: contribution(0, 0),
    })
    .unwrap();
    w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
    let closed = w.balances();
    let late: Vec<LedgerOp> = vec![
        LedgerOp::SettleJob { job: JOB },
        LedgerOp::Reserve {
            job: JOB,
            bucket: EscrowBucket::Work,
            key: "late".into(),
            amount: 5,
        },
        LedgerOp::FundRecovery {
            job: JOB,
            amount: 5,
            signature: key(ADMIN).sign(&more_identity::relay_message(&dom(), JOB, POOL, 5)),
        },
        LedgerOp::ChargeOutput {
            job: JOB,
            attempt: 1,
            output: out(1),
            gen: 0,
        },
        LedgerOp::ReserveContribution {
            line: line(1, L1),
            output: out(0),
            gen: 0,
            stage: 0,
        },
        LedgerOp::RefundLine {
            line: line(1, L1),
            item: contribution(0, 0),
        },
        LedgerOp::PayLine {
            line: line(1, L1),
            item: contribution(0, 0),
        },
        LedgerOp::RegisterAttempt {
            assignment: assignment(2, &[L1, L2], &[3, 1], 0),
        },
    ];
    // Each is refused because the job is settled, whatever else would also have stopped it.
    for op in late {
        assert_eq!(
            w.run(op.clone()),
            Err(LedgerApiError::EscrowSettled(JOB)),
            "{op:?} after closure"
        );
    }
    assert!(w.accept(&a, 0, L1).is_err());
    assert_eq!(closed, w.balances());
    for acct in [
        Account::EscrowWork(JOB),
        Account::EscrowRecovery(JOB),
        Account::OutputHold(JOB),
        line(1, L1).line_account(),
    ] {
        assert_eq!(w.bal(acct), 0, "{acct:?}");
    }
}

/// Finding 3: a line is reserved only for the lender who signed that stage of that attempt, for
/// the share the signed terms give it.
#[test]
fn r2_only_a_lender_that_signed_its_lease_gets_a_line() {
    let mut w = world();
    w.open(JOB, 500).unwrap();
    w.reserve(EscrowBucket::Work, 100).unwrap();
    let a = assignment(1, &[L1, L2], &[3, 1], 0);
    w.run(LedgerOp::RegisterAttempt {
        assignment: a.clone(),
    })
    .unwrap();
    w.charge(1, 0).unwrap();
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // Nobody signed yet.
    bad_proof(reserve_contribution(&mut w, 1, L1, 0, 0));
    // A lease signed by someone else, or over another assignment, is not an acceptance.
    bad_proof(w.accept(&a, 0, MALLORY));
    bad_proof(w.accept(&a, 0, L2));
    let other = assignment(1, &[L1, MALLORY], &[3, 1], 0);
    bad_proof(w.run(LedgerOp::AcceptLease {
        job: JOB,
        attempt: 1,
        stage: 0,
        signature: key(L1).sign(&more_identity::lease_message(&dom(), &other)),
    }));
    w.accept(&a, 0, L1).unwrap();
    w.accept(&a, 1, L2).unwrap();
    // An account outside the attempt, or a lender on another lender's stage.
    bad_proof(reserve_contribution(&mut w, 1, MALLORY, 0, 0));
    bad_proof(reserve_contribution(&mut w, 1, L2, 0, 0));
    // Shares come from the signed terms: 8 * 3 / 4 and 8 * 1 / 4.
    assert_eq!(
        reserve_contribution(&mut w, 1, L1, 0, 0),
        Ok(LedgerOutcome::Moved(6))
    );
    assert_eq!(
        reserve_contribution(&mut w, 1, L2, 0, 1),
        Ok(LedgerOutcome::Moved(2))
    );
    // Once per output, charge and stage; never for an output that was not charged.
    assert!(reserve_contribution(&mut w, 1, L1, 0, 0).is_err());
    assert!(reserve_contribution(&mut w, 1, L1, 1, 0).is_err());
    assert_eq!(w.bal(Account::User(MALLORY)), 0);
}

/// Finding 3: a contribution is paid only with a receipt signed by the stage's recipient.
#[test]
fn r2_no_payment_without_the_recipients_receipt() {
    let (mut w, _) = World::running();
    w.charge(1, 0).unwrap();
    w.charge(1, 1).unwrap();
    reserve_contribution(&mut w, 1, L1, 0, 0).unwrap();
    reserve_contribution(&mut w, 1, L2, 0, 1).unwrap();
    reserve_contribution(&mut w, 1, L1, 1, 0).unwrap();
    let pay = |w: &mut World, lender, pos, stage| {
        w.run(LedgerOp::PayLine {
            line: line(1, lender),
            item: contribution(pos, stage),
        })
    };
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    bad_proof(pay(&mut w, L1, 0, 0));
    // L1's recipient is L2; L2's is the witness. Nobody else can sign for them, not even the
    // producer itself.
    for signer in [L1, WIT, MALLORY] {
        bad_proof(w.receipt(1, L1, 1, signer));
    }
    bad_proof(w.receipt(1, L2, 1, L1));
    w.receipt(1, L1, 1, L2).unwrap();
    w.receipt(1, L2, 1, WIT).unwrap();
    assert!(pay(&mut w, L1, 0, 0).is_ok());
    assert!(pay(&mut w, L2, 0, 1).is_ok());
    // The receipt covers output 0 only.
    bad_proof(pay(&mut w, L1, 1, 0));
    w.advance(48 * HOUR);
    w.run(LedgerOp::ReleaseReward { line: line(1, L1) })
        .unwrap();
    // 6 held, 10 % commission rounded down to 0.
    assert_eq!(w.bal(Account::User(L1)) + w.bal(Account::Commission), 6);
}

/// Recovery is reserved only for a lender that signed ready, within the earmark its attempt was
/// registered with; earmarks never exceed the recovery budget.
#[test]
fn r2_recovery_needs_readiness_and_stays_within_the_earmark() {
    let (mut w, _) = World::running();
    // 20 from the owner, nothing from the pool: an earmark of 21 is refused.
    assert!(w
        .run(LedgerOp::RegisterAttempt {
            assignment: assignment(2, &[L1, L2], &[3, 1], 21),
        })
        .is_err());
    let a = assignment(2, &[L1, L2], &[3, 1], 15);
    w.place(&a);
    let r = reserve_recovery(&mut w, 2, L1, 0, 5);
    assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // Readiness signed by another account does not count.
    assert!(w.ready(&a, 0, MALLORY).is_err());
    w.ready(&a, 0, L1).unwrap();
    // One ready lender is not a started attempt (JOB-R18, JOB-R38): every lender must sign.
    let r = reserve_recovery(&mut w, 2, L1, 0, 10);
    assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    w.ready(&a, 1, L2).unwrap();
    reserve_recovery(&mut w, 2, L1, 0, 10).unwrap();
    w.corroborate(&a, 0, L2).unwrap();
    assert!(
        reserve_recovery(&mut w, 2, L1, 1, 6).is_err(),
        "above earmark"
    );
    assert!(reserve_recovery(&mut w, 2, MALLORY, 2, 1).is_err());
    // The earmark comes back only once nothing is undecided, and then the attempt is closed.
    assert_eq!(
        w.run(LedgerOp::ReturnEarmark {
            job: JOB,
            attempt: 2
        })
        .unwrap_err(),
        LedgerApiError::OpenItems(JOB)
    );
    w.run(LedgerOp::PayLine {
        line: line(2, L1),
        item: ItemId::Recovery {
            attempt: 2,
            segment: 0,
        },
    })
    .unwrap();
    assert_eq!(
        w.run(LedgerOp::ReturnEarmark {
            job: JOB,
            attempt: 2
        }),
        Ok(LedgerOutcome::Moved(5))
    );
    assert!(reserve_recovery(&mut w, 2, L1, 3, 1).is_err());
    // 10 spent of 20: the next attempt can earmark 10, not 11.
    assert!(w
        .run(LedgerOp::RegisterAttempt {
            assignment: assignment(3, &[L1, L2], &[3, 1], 11),
        })
        .is_err());
    w.place(&assignment(3, &[L1, L2], &[3, 1], 10));
}

/// Attempts must cover the signed model with distinct lenders and an independent witness.
#[test]
fn r2_attempts_are_checked_against_the_signed_terms() {
    let mut w = world();
    w.open(JOB, 500).unwrap();
    let mut bad = vec![
        assignment(1, &[L1, L2], &[3, 2], 0),
        assignment(1, &[L1, L2], &[4, 0], 0),
        assignment(1, &[L1, L1], &[3, 1], 0),
        assignment(1, &[L1, WIT], &[3, 1], 0),
        assignment(1, &[L1], &[3, 1], 0),
    ];
    bad.push(Assignment {
        witness: ALICE,
        ..assignment(1, &[L1, L2], &[3, 1], 0)
    });
    for a in bad {
        let r = w.run(LedgerOp::RegisterAttempt {
            assignment: a.clone(),
        });
        assert!(r.is_err(), "{a:?} registered");
    }
    w.place(&assignment(2, &[L1, L2], &[3, 1], 0));
    // Never an older or the same attempt again.
    for n in [1, 2] {
        assert!(w
            .run(LedgerOp::RegisterAttempt {
                assignment: assignment(n, &[L1, L2], &[3, 1], 0),
            })
            .is_err());
    }
}

/// Charges follow the signed price and the billing generation; a void needs its shares back.
#[test]
fn r2_charges_and_voids_follow_the_ledgers_records() {
    let (mut w, _) = World::running();
    assert_eq!(w.charge(1, 0), Ok(LedgerOutcome::Moved(8)));
    assert!(w.charge(1, 0).is_err(), "charged twice");
    assert!(w.charge(1, 10).is_err(), "beyond the signed maximum");
    assert!(w.charge(9, 1).is_err(), "unknown attempt");
    reserve_contribution(&mut w, 1, L1, 0, 0).unwrap();
    let void = LedgerOp::VoidOutput {
        job: JOB,
        output: out(0),
        gen: 0,
    };
    // A second charged output keeps enough in the hold to cover the void, so the refusal below
    // comes from the live share and not from a short balance.
    w.charge(1, 1).unwrap();
    let before = w.balances();
    assert_eq!(
        w.run(void.clone()),
        Err(LedgerApiError::Invalid(
            "void of an output with live shares"
        ))
    );
    assert_eq!(before, w.balances());
    let other = LedgerOp::VoidOutput {
        job: JOB,
        output: out(1),
        gen: 0,
    };
    assert_eq!(w.run(other), Ok(LedgerOutcome::Moved(8)));
    w.run(LedgerOp::RefundLine {
        line: line(1, L1),
        item: contribution(0, 0),
    })
    .unwrap();
    assert_eq!(w.run(void.clone()), Ok(LedgerOutcome::Moved(8)));
    assert!(w.run(void).is_err(), "voided twice");
    assert_eq!(w.bal(Account::EscrowWork(JOB)), 100);
    // Charged again at the next generation only.
    let recharge = |gen| LedgerOp::ChargeOutput {
        job: JOB,
        attempt: 1,
        output: out(0),
        gen,
    };
    assert!(w.run(recharge(0)).is_err());
    assert!(w.run(recharge(1)).is_ok());
}

/// The pool's treasury moves only with its admin's signature over the new running total, and a
/// consent already used cannot be replayed.
#[test]
fn r2_pool_relay_needs_the_admins_consent() {
    let (mut w, _) = World::running();
    for signer in [MALLORY, ALICE, L1] {
        let r = w.fund_signed(30, signer);
        assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    }
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 1_000);
    let consent = key(ADMIN).sign(&more_identity::relay_message(&dom(), JOB, POOL, 30));
    let relay = |amount| LedgerOp::FundRecovery {
        job: JOB,
        amount,
        signature: consent,
    };
    // The admin agreed to a total of 30: not 31, and not 30 twice.
    assert!(w.run(relay(31)).is_err());
    w.run(relay(30)).unwrap();
    assert!(w.run(relay(30)).is_err());
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 970);
    // Only the platform admin names a pool's admin, once.
    let rename = LedgerOp::RegisterPool {
        pool: POOL,
        admin: MALLORY,
    };
    assert!(w.run(rename.clone()).is_err());
    let platform = w.auth.issue(more_identity::ServiceRole::PlatformAdmin);
    assert!(w.ledger.execute(&platform, rename).is_err());
}

/// JOB-R18, decision after the second audit. Reservation: the amount is locked within the
/// earmark before any payment. Execution: the lender signs its restoration and its recipient
/// corroborates it. Settlement: nothing is paid on the lender's word alone.
#[test]
fn r2_recovery_is_settled_only_on_a_corroborated_restoration() {
    let (mut w, _) = World::running();
    w.fund(40).unwrap();
    // The orchestrator places an account it controls next to an honest lender.
    let a = assignment(2, &[MALLORY, L2], &[3, 1], 50);
    w.place(&a);
    w.ready(&a, 0, MALLORY).unwrap();
    w.ready(&a, 1, L2).unwrap();
    reserve_recovery(&mut w, 2, MALLORY, 0, 50).unwrap();
    let item = ItemId::Recovery {
        attempt: 2,
        segment: 0,
    };
    let pay = LedgerOp::PayLine {
        line: line(2, MALLORY),
        item,
    };
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // Ready, signed by everyone, is not enough.
    bad_proof(w.run(pay.clone()));
    // Corroboration by the accomplice itself, by the orchestrator's other guesses, or by an
    // honest account that is not the stage's recipient: refused.
    for signer in [MALLORY, WIT, L1, ALICE] {
        bad_proof(w.corroborate(&a, 0, signer));
    }
    bad_proof(w.run(pay.clone()));
    // A corroboration of another attempt or another lender cannot be replayed here.
    let honest = resumed_like(&mut w, 3);
    let replay = LedgerOp::RecordRestore {
        job: JOB,
        attempt: 2,
        producer: MALLORY,
        segments: (0..SEGMENTS).collect(),
        signature: key(L2).sign(&more_identity::restore_message(
            &dom(),
            &restoration(&honest, 0, SEGMENTS, STATE),
        )),
    };
    bad_proof(w.run(replay));
    // The amount stays reserved, never paid; the only way out is back to the recovery escrow.
    assert_eq!(w.bal(Account::User(MALLORY)), 0);
    w.run(LedgerOp::RefundLine {
        line: line(2, MALLORY),
        item,
    })
    .unwrap();
    assert!(w.run(pay).is_err());
    w.run(LedgerOp::SettleJob { job: JOB }).unwrap();
    assert_eq!(w.bal(Account::User(MALLORY)), 0);
    assert_eq!(w.bal(Account::PoolReserve(POOL)), 1_000);
    assert_eq!(w.bal(Account::User(ALICE)), 1_000);
}

/// Another resumed attempt on the honest lenders, ready and corroborated.
fn resumed_like(w: &mut World, attempt: u32) -> Assignment {
    let a = assignment(attempt, &[L1, L2], &[3, 1], 0);
    w.place(&a);
    w.ready(&a, 0, L1).unwrap();
    w.ready(&a, 1, L2).unwrap();
    w.corroborate(&a, 0, L2).unwrap();
    a
}

/// A valid receipt pays one contribution once: presenting it again, on the same attempt, on
/// another attempt or on another job, never opens a second payment.
#[test]
fn r2_a_replayed_receipt_never_pays_twice() {
    let (mut w, _) = World::running();
    w.charge(1, 0).unwrap();
    reserve_contribution(&mut w, 1, L1, 0, 0).unwrap();
    w.receipt(1, L1, 1, L2).unwrap();
    let pay = LedgerOp::PayLine {
        line: line(1, L1),
        item: contribution(0, 0),
    };
    assert_eq!(
        w.run(pay.clone()),
        Ok(LedgerOutcome::Paid {
            amount: 6,
            pool_part: 0
        })
    );
    // The same receipt again: accepted as a record, worth nothing more.
    w.receipt(1, L1, 1, L2).unwrap();
    assert!(w.run(pay.clone()).is_err(), "paid twice");
    assert!(
        reserve_contribution(&mut w, 1, L1, 0, 0).is_err(),
        "reserved twice"
    );
    // Same slice of another line of the same lender: the item, not the line, is unique.
    let other_slice = LineRef {
        slice: 2,
        ..line(1, L1)
    };
    let again = LedgerOp::ReserveContribution {
        line: other_slice,
        output: out(0),
        gen: 0,
        stage: 0,
    };
    assert!(w.run(again).is_err());
    // The signature binds the attempt and the job: it does not verify anywhere else.
    w.place(&assignment(2, &[L1, L2], &[3, 1], 0));
    let signature = key(L2).sign(&more_identity::receipt_message(
        &dom(),
        JOB,
        1,
        L1,
        WT,
        1,
        0,
    ));
    let replay = |job, attempt| LedgerOp::RecordReceipt {
        job,
        attempt,
        producer: L1,
        wt: WT,
        upto: 1,
        digest: 0,
        signature,
    };
    let r = w.run(replay(JOB, 2));
    assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    w.open(2, 100).unwrap();
    let mut second = assignment(1, &[L1, L2], &[3, 1], 0);
    second.job = 2;
    w.place(&second);
    let r = w.run(replay(2, 1));
    assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // One payment of 6 in all.
    w.advance(48 * HOUR);
    w.run(LedgerOp::ReleaseReward { line: line(1, L1) })
        .unwrap();
    assert_eq!(w.bal(Account::User(L1)) + w.bal(Account::Commission), 6);
}

/// Verification 1: what the recipient signs is the restoration itself. Change the job, the
/// attempt, the lender, the layer range, the positions, the state commitment, the segments
/// named or the commitment of one of them, and the signature no longer verifies; a
/// corroboration covers the segments it names and no other recovery.
#[test]
fn r2_a_corroboration_is_bound_to_what_was_restored() {
    let (mut w, _) = World::running();
    w.fund(40).unwrap();
    let a = resumed_uncorroborated(&mut w, 2, 40);
    let good = restoration(&a, 0, 2, STATE);
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // The recipient (L2) signs something else than what the ledger holds for this stage.
    let altered = [
        more_identity::Restoration {
            job: 9,
            ..good.clone()
        },
        more_identity::Restoration {
            attempt: 1,
            ..good.clone()
        },
        more_identity::Restoration {
            producer: L2,
            ..good.clone()
        },
        more_identity::Restoration {
            layers: (0, 4),
            ..good.clone()
        },
        more_identity::Restoration {
            restored: [0, 5, 0],
            ..good.clone()
        },
        more_identity::Restoration {
            state: STATE + 1,
            ..good.clone()
        },
        // One segment more, another segment, or another content for the same segment.
        restoration(&a, 0, 3, STATE),
        restoration_of(&a, 0, &[0, 2], STATE),
        more_identity::Restoration {
            segments: vec![(0, SEGS[0]), (1, SEGS[1] + 1)],
            ..good.clone()
        },
    ];
    for r in altered {
        // The ledger rebuilds the statement from its own records and the announced segments.
        let op = LedgerOp::RecordRestore {
            job: JOB,
            attempt: 2,
            producer: L1,
            segments: vec![0, 1],
            signature: key(L2).sign(&more_identity::restore_message(&dom(), &r)),
        };
        bad_proof(w.run(op));
    }
    assert!(
        w.corroborate_with(&restoration(&a, 0, 0, STATE), L2)
            .is_err(),
        "no segment"
    );
    w.corroborate_with(&good, L2).unwrap();
    // Segments 0 and 1 were attested: they are payable, segment 2 is not.
    for (segment, amount) in [(0, 10), (1, 10), (2, 10)] {
        reserve_recovery(&mut w, 2, L1, segment, amount).unwrap();
    }
    let pay = |w: &mut World, attempt, lender, segment| {
        w.run(LedgerOp::PayLine {
            line: line(attempt, lender),
            item: ItemId::Recovery { attempt, segment },
        })
    };
    assert!(pay(&mut w, 2, L1, 0).is_ok());
    assert!(pay(&mut w, 2, L1, 1).is_ok());
    bad_proof(pay(&mut w, 2, L1, 2));
    // Not reusable: the same corroboration pays nothing for the other lender of the attempt,
    // nor on the next attempt of the same lender.
    reserve_recovery(&mut w, 2, L2, 5, 5).unwrap();
    bad_proof(pay(&mut w, 2, L2, 5));
    let next = resumed_uncorroborated(&mut w, 3, 5);
    reserve_recovery(&mut w, 3, L1, 0, 5).unwrap();
    bad_proof(pay(&mut w, 3, L1, 0));
    let replay = LedgerOp::RecordRestore {
        job: JOB,
        attempt: 3,
        producer: L1,
        segments: vec![0, 1],
        signature: key(L2).sign(&more_identity::restore_message(&dom(), &good)),
    };
    bad_proof(w.run(replay));
    let _ = next;
}

/// Attempt `n` on the honest lenders, both ready, nothing corroborated.
fn resumed_uncorroborated(w: &mut World, n: u32, earmark: Amount) -> Assignment {
    let a = assignment(n, &[L1, L2], &[3, 1], earmark);
    w.place(&a);
    w.ready(&a, 0, L1).unwrap();
    w.ready(&a, 1, L2).unwrap();
    a
}

/// Verification 2, proofs: once recorded, a proof is final. A corroboration cannot be replaced,
/// a receipt cannot come back with another digest, and a paid item never goes back.
#[test]
fn r2_a_recorded_proof_cannot_be_replaced() {
    let (mut w, _) = World::running();
    w.fund(40).unwrap();
    w.charge(1, 0).unwrap();
    reserve_contribution(&mut w, 1, L1, 0, 0).unwrap();
    w.receipt(1, L1, 1, L2).unwrap();
    let receipt = |digest| {
        let m = more_identity::receipt_message(&dom(), JOB, 1, L1, WT, 1, digest);
        LedgerOp::RecordReceipt {
            job: JOB,
            attempt: 1,
            producer: L1,
            wt: WT,
            upto: 1,
            digest,
            signature: key(L2).sign(&m),
        }
    };
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // The same recipient, validly signing other content for the same coverage: refused before
    // the payment as well as after it.
    bad_proof(w.run(receipt(77)));
    let item = contribution(0, 0);
    w.run(LedgerOp::PayLine {
        line: line(1, L1),
        item,
    })
    .unwrap();
    bad_proof(w.run(receipt(77)));
    assert!(
        w.run(receipt(0)).is_ok(),
        "the same receipt again is a no-op"
    );
    // A paid item is not refunded, paid again or voided with its output.
    for op in [
        LedgerOp::RefundLine {
            line: line(1, L1),
            item,
        },
        LedgerOp::PayLine {
            line: line(1, L1),
            item,
        },
        LedgerOp::VoidOutput {
            job: JOB,
            output: out(0),
            gen: 0,
        },
    ] {
        assert!(w.run(op.clone()).is_err(), "{op:?} after payment");
    }
    // Corroborations are written once.
    let a = resumed_uncorroborated(&mut w, 2, 20);
    w.corroborate_with(&restoration(&a, 0, 1, STATE), L2)
        .unwrap();
    assert!(w
        .corroborate_with(&restoration(&a, 0, 3, STATE), L2)
        .is_err());
    assert!(w
        .corroborate_with(&restoration(&a, 0, 1, STATE), L2)
        .is_err());
    let kept = w.escrow().attempts[&2].corroborated[0].clone();
    assert_eq!(kept.map(|c| c.segments), Some(vec![0]));
    // Nor can the lender sign a second, different readiness.
    assert!(w.ready(&a, 0, L1).is_err());
}

/// Verification 2, contests: a payment follows an explicit cycle on the ledger's own clock.
/// Held, it can be contested until the limit; it can be released only after the hold; once
/// released or contested, it is final. The orchestrator cannot move the clock.
#[test]
fn r2_contests_follow_a_bounded_cycle() {
    let (mut w, _) = World::running();
    let limits = w.ledger.limits().clone();
    for pos in 0..3 {
        w.charge(1, pos).unwrap();
        reserve_contribution(&mut w, 1, L1, pos, 0).unwrap();
        reserve_contribution(&mut w, 1, L2, pos, 1).unwrap();
    }
    w.receipt(1, L1, 3, L2).unwrap();
    w.receipt(1, L2, 3, WIT).unwrap();
    let pay = |w: &mut World, lender, pos, stage| {
        w.run(LedgerOp::PayLine {
            line: line(1, lender),
            item: contribution(pos, stage),
        })
        .unwrap()
    };
    let window = |r: Res| assert!(matches!(r, Err(LedgerApiError::OutOfWindow(_))), "{r:?}");
    let release = |lender| LedgerOp::ReleaseReward {
        line: line(1, lender),
    };
    let contest = |lender| LedgerOp::ContestReward {
        line: line(1, lender),
    };
    w.advance(100);
    pay(&mut w, L1, 0, 0);
    // Only the Clock service moves the ledger's time; time never goes back.
    let jump = LedgerOp::Advance {
        now: w.ledger.now() + limits.reward_hold,
    };
    assert!(matches!(w.run(jump), Err(LedgerApiError::Forbidden { .. })));
    let back = LedgerOp::Advance { now: 0 };
    assert!(w.ledger.execute(&w.clock.clone(), back).is_err());
    // Too early to release: the borrower still has its window.
    window(w.run(release(L1)));
    w.advance(limits.reward_hold - 1);
    window(w.run(release(L1)));
    // A later payment on the same line has its own window: it does not delay the first one and
    // does not leave with it.
    pay(&mut w, L1, 1, 0);
    w.advance(1);
    let one = LedgerOutcome::Released {
        to_lender: 6,
        commission: 0,
    };
    assert_eq!(w.run(release(L1)), Ok(one));
    window(w.run(release(L1)));
    w.advance(limits.reward_hold - 2);
    window(w.run(release(L1)));
    w.advance(1);
    assert_eq!(w.run(release(L1)), Ok(one));
    // Released is final: nothing left to contest or to release.
    assert!(w.run(contest(L1)).is_err());
    assert!(w.run(release(L1)).is_err());
    // L2's line: paid, contested inside the limit.
    pay(&mut w, L2, 0, 1);
    w.advance(limits.contest_limit - 1);
    assert_eq!(
        w.run(contest(L2)),
        Ok(LedgerOutcome::Contested {
            to_pool: 0,
            to_owner: 2
        })
    );
    assert!(w.run(release(L2)).is_err(), "contested is final");
    // Paid again, then left alone past the limit: it can no longer be contested, only released.
    pay(&mut w, L2, 1, 1);
    w.advance(limits.contest_limit);
    window(w.run(contest(L2)));
    assert!(w.run(release(L2)).is_ok());
    assert!(limits.reward_hold < limits.contest_limit);
}

const DAY: u64 = 24 * HOUR;

/// Job 1 with two outputs delivered. `L1` is paid for the first on day 0 and for the second on
/// day 6, on the same line. Returns the world on day 6, just after the second payment.
fn staggered() -> World {
    let (mut w, _) = World::running();
    for pos in 0..2 {
        w.charge(1, pos).unwrap();
        reserve_contribution(&mut w, 1, L1, pos, 0).unwrap();
    }
    w.receipt(1, L1, 2, L2).unwrap();
    for pos in 0..2 {
        w.run(LedgerOp::PayLine {
            line: line(1, L1),
            item: contribution(pos, 0),
        })
        .unwrap();
        if pos == 0 {
            w.advance(6 * DAY);
        }
    }
    w
}

fn held(w: &World) -> i128 {
    w.bal(line(1, L1).reward_account())
}

/// Third review, LEDGER-018. Two payments on the same line, six days apart. With one window per
/// line, on day 7 the line could be neither contested (oldest payment + 7 days) nor released
/// (latest payment + 48 h), and the second payment had one day of contest instead of its own
/// window. Each payment now has its own cycle.
#[test]
fn r3_staggered_payments_each_have_their_own_window() {
    let release = LedgerOp::ReleaseReward { line: line(1, L1) };
    let contest = LedgerOp::ContestReward { line: line(1, L1) };
    let first = Ok(LedgerOutcome::Released {
        to_lender: 6,
        commission: 0,
    });
    let second = Ok(LedgerOutcome::Contested {
        to_pool: 0,
        to_owner: 6,
    });
    let window = |r: Res| assert!(matches!(r, Err(LedgerApiError::OutOfWindow(_))), "{r:?}");

    // Day 7, release first: the day-0 payment leaves, the day-6 payment stays held and is still
    // contestable.
    let mut w = staggered();
    w.advance(DAY);
    assert_eq!(w.run(release.clone()), first);
    assert_eq!(held(&w), 6);
    window(w.run(release.clone()));
    assert_eq!(w.run(contest.clone()), second);
    assert_eq!(held(&w), 0);

    // Day 7, contest first: only the day-6 payment is taken back. The day-0 payment is past its
    // limit: it stays held and can only be released.
    let mut w = staggered();
    w.advance(DAY);
    assert_eq!(w.run(contest.clone()), second);
    assert_eq!(held(&w), 6);
    window(w.run(contest.clone()));
    assert_eq!(w.run(release.clone()), first);
    assert_eq!(held(&w), 0);
    assert_eq!(w.bal(Account::User(L1)), 6);

    // The day-6 payment is not releasable before day 8, and is from then on.
    let mut w = staggered();
    w.advance(2 * DAY - 1);
    assert_eq!(w.run(release.clone()), first);
    window(w.run(release.clone()));
    w.advance(1);
    assert_eq!(w.run(release.clone()), first);

    // It stays contestable until day 13, not a second longer.
    let mut w = staggered();
    w.advance(7 * DAY - 1);
    assert_eq!(w.run(contest.clone()), second);
    let mut w = staggered();
    w.advance(7 * DAY);
    window(w.run(contest.clone()));
    // Both payments released together: the commission is taken on what is released.
    let both = LedgerOutcome::Released {
        to_lender: 11,
        commission: 1,
    };
    assert_eq!(w.run(release.clone()), Ok(both));

    // At no hour from day 6 to day 14 is the line stuck: one of the two always applies.
    let mut w = staggered();
    for hour in 0..8 * 24 {
        let orch = w.orch.clone();
        let mut a = w.ledger.clone();
        let mut b = w.ledger.clone();
        let (r, c) = (
            a.execute(&orch, release.clone()),
            b.execute(&orch, contest.clone()),
        );
        assert!(
            r.is_ok() || c.is_ok(),
            "stuck at hour {hour}: {r:?} / {c:?}"
        );
        w.advance(HOUR);
    }
    let l = w.ledger.limits();
    assert!(l.reward_hold <= l.contest_limit);
}

/// Third review: a corroboration pays the segments it names, one by one. It cannot name a
/// segment the lender did not commit to, and the orchestrator cannot stretch it to another.
#[test]
fn r3_a_corroboration_pays_only_the_segments_it_names() {
    let (mut w, _) = World::running();
    w.fund(40).unwrap();
    let a = resumed_uncorroborated(&mut w, 2, 40);
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // The lender committed to segments 0, 1 and 2: there is no segment 3 to attest.
    bad_proof(w.corroborate_with(&restoration_of(&a, 0, &[0, 3], STATE), L2));
    // A segment is named once, in order.
    for named in [[1, 1], [2, 0]] {
        let r = restoration_of(&a, 0, &named, STATE);
        assert!(w.corroborate_with(&r, L2).is_err(), "{named:?}");
    }
    // The recipient signed for segments 0 and 2. Announcing anything else with that signature
    // is refused: the ledger rebuilds the statement from the announced list.
    let signed = restoration_of(&a, 0, &[0, 2], STATE);
    let signature = key(L2).sign(&more_identity::restore_message(&dom(), &signed));
    for announced in [vec![0, 1, 2], vec![0, 1], vec![0], vec![2], vec![1]] {
        bad_proof(w.run(LedgerOp::RecordRestore {
            job: JOB,
            attempt: 2,
            producer: L1,
            segments: announced,
            signature,
        }));
    }
    w.corroborate_with(&signed, L2).unwrap();
    for segment in 0..3 {
        reserve_recovery(&mut w, 2, L1, segment, 10).unwrap();
    }
    let pay = |w: &mut World, segment| {
        w.run(LedgerOp::PayLine {
            line: line(2, L1),
            item: ItemId::Recovery {
                attempt: 2,
                segment,
            },
        })
    };
    assert!(pay(&mut w, 0).is_ok());
    assert!(pay(&mut w, 2).is_ok());
    // Segment 1 sits between two attested segments and is still not covered.
    bad_proof(pay(&mut w, 1));
    assert_eq!(w.bal(line(2, L1).reward_account()), 20);
    // A lender that committed to no segment has nothing that can be corroborated.
    let b = assignment(3, &[L1, L2], &[3, 1], 0);
    w.place(&b);
    let mut none = readiness(&b, 0);
    none.segments.clear();
    w.ready_with(0, &none, L1).unwrap();
    bad_proof(w.corroborate_with(&restoration_of(&b, 0, &[0], STATE), L2));
    // The orchestrator cannot announce other commitments than the ones the lender signed.
    let signed = readiness(&b, 1);
    let swapped = LedgerOp::LeaseReady {
        job: JOB,
        attempt: 3,
        stage: 1,
        restored: signed.restored,
        state: signed.state,
        segments: vec![SEGS[0], SEGS[1], SEGS[2] + 1],
        signature: key(L2).sign(&more_identity::ready_message(&dom(), &signed)),
    };
    bad_proof(w.run(swapped));
    // Nor can it commit to more segments than the limit.
    let mut many = readiness(&b, 1);
    many.segments = vec![1; w.ledger.limits().max_segments + 1];
    let r = w.ready_with(1, &many, L2);
    assert!(matches!(r, Err(LedgerApiError::LimitExceeded(_))), "{r:?}");
}

/// Third review, CE-03 at the ledger: a proof counts only if it was on record before the
/// attempt's revocation. What was recorded before still pays; what comes after proves nothing,
/// even honestly signed by the right account.
#[test]
fn r3_no_proof_is_added_after_the_revocation() {
    let (mut w, _) = World::running();
    w.fund(40).unwrap();
    let a = resumed_uncorroborated(&mut w, 2, 40);
    w.corroborate(&a, 0, L2).unwrap();
    reserve_recovery(&mut w, 2, L1, 0, 10).unwrap();
    reserve_recovery(&mut w, 2, L2, 1, 10).unwrap();
    // Only the orchestrator records a revocation, once.
    let revoke = LedgerOp::RevokeAttempt {
        job: JOB,
        attempt: 2,
    };
    let r = w.ledger.execute(&w.clock.clone(), revoke);
    assert!(matches!(r, Err(LedgerApiError::Forbidden { .. })), "{r:?}");
    w.revoke(2).unwrap();
    assert!(w.revoke(2).is_err());
    assert!(w.revoke(9).is_err());
    // L2's restoration, attested by the witness after the revocation: refused, and it stays
    // refused. Its recovery is never paid.
    let late = w.corroborate(&a, 1, WIT);
    assert!(matches!(late, Err(LedgerApiError::BadProof(_))), "{late:?}");
    let pay = |w: &mut World, lender, segment| {
        w.run(LedgerOp::PayLine {
            line: line(2, lender),
            item: ItemId::Recovery {
                attempt: 2,
                segment,
            },
        })
    };
    let unpaid = pay(&mut w, L2, 1);
    assert!(
        matches!(unpaid, Err(LedgerApiError::BadProof(_))),
        "{unpaid:?}"
    );
    // L1's was on record before: the revocation does not undo it.
    assert!(pay(&mut w, L1, 0).is_ok());
    let rec = &w.escrow().attempts[&2];
    let before = rec.corroborated[0].as_ref().map(|c| c.seq);
    assert!(before < rec.revoked && before.is_some());
    assert_eq!(rec.corroborated[1], None);
    // No lease step is added to a revoked attempt either.
    let b = assignment(3, &[L1, L2], &[3, 1], 0);
    let register = LedgerOp::RegisterAttempt {
        assignment: b.clone(),
    };
    w.run(register).unwrap();
    w.accept(&b, 0, L1).unwrap();
    w.revoke(3).unwrap();
    assert!(w.accept(&b, 1, L2).is_err());
    assert!(w.ready(&b, 0, L1).is_err());
    let rec = &w.escrow().attempts[&3];
    assert_eq!(
        (&rec.accepted, &rec.ready),
        (&vec![true, false], &vec![false; 2])
    );
}

/// LEDGER-019: every statement is signed for one deployment. The same accounts signing the same
/// business content for another deployment prove nothing here, for each kind of statement.
#[test]
fn r3_statements_signed_for_another_deployment_are_refused() {
    use more_identity::{
        lease_message, mandate_message, ready_message, receipt_message, relay_message,
        restore_message, Domain, IdentityAuthority,
    };
    let other = IdentityAuthority::new([4; 32]).domain();
    assert_ne!(other, dom());
    let mut w = world();
    assert_eq!(w.ledger.domain(), dom());
    let bad_proof = |r: Res| assert!(matches!(r, Err(LedgerApiError::BadProof(_))), "{r:?}");
    // Each statement is tried for the other deployment first, then for this one.
    let t = terms(500);
    let open = |d: &Domain| LedgerOp::OpenEscrow {
        job: JOB,
        owner: ALICE,
        pool: POOL,
        terms: t,
        signature: key(ALICE).sign(&mandate_message(d, JOB, POOL, ALICE, &t)),
    };
    assert_eq!(w.run(open(&other)), Err(LedgerApiError::BadMandate));
    w.run(open(&dom())).unwrap();
    w.reserve(EscrowBucket::Work, 100).unwrap();
    w.reserve(EscrowBucket::Recovery, 20).unwrap();
    let relay = |d: &Domain| LedgerOp::FundRecovery {
        job: JOB,
        amount: 10,
        signature: key(ADMIN).sign(&relay_message(d, JOB, POOL, 10)),
    };
    bad_proof(w.run(relay(&other)));
    w.run(relay(&dom())).unwrap();
    let a = assignment(1, &[L1, L2], &[3, 1], 10);
    let register = LedgerOp::RegisterAttempt {
        assignment: a.clone(),
    };
    w.run(register).unwrap();
    for (stage, lender) in [(0, L1), (1, L2)] {
        let accept = |d: &Domain| LedgerOp::AcceptLease {
            job: JOB,
            attempt: 1,
            stage,
            signature: key(lender).sign(&lease_message(d, &a)),
        };
        bad_proof(w.run(accept(&other)));
        w.run(accept(&dom())).unwrap();
        let r = readiness(&a, stage);
        let ready = |d: &Domain| LedgerOp::LeaseReady {
            job: JOB,
            attempt: 1,
            stage,
            restored: r.restored,
            state: r.state,
            segments: r.segments.clone(),
            signature: key(lender).sign(&ready_message(d, &r)),
        };
        bad_proof(w.run(ready(&other)));
        w.run(ready(&dom())).unwrap();
    }
    let seen = restoration(&a, 0, SEGMENTS, STATE);
    let restore = |d: &Domain| LedgerOp::RecordRestore {
        job: JOB,
        attempt: 1,
        producer: L1,
        segments: (0..SEGMENTS).collect(),
        signature: key(L2).sign(&restore_message(d, &seen)),
    };
    bad_proof(w.run(restore(&other)));
    w.run(restore(&dom())).unwrap();
    let receipt = |d: &Domain| LedgerOp::RecordReceipt {
        job: JOB,
        attempt: 1,
        producer: L1,
        wt: WT,
        upto: 1,
        digest: 0,
        signature: key(L2).sign(&receipt_message(d, JOB, 1, L1, WT, 1, 0)),
    };
    bad_proof(w.run(receipt(&other)));
    w.run(receipt(&dom())).unwrap();
}
