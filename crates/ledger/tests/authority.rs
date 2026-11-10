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

/// A resumed attempt 2 on the same lenders with `earmark`, both ready.
fn resumed(w: &mut World, earmark: Amount) -> Assignment {
    let a = assignment(2, &[L1, L2], &[3, 1], earmark);
    w.place(&a);
    w.ready(&a, 0, L1).unwrap();
    w.ready(&a, 1, L2).unwrap();
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
            signature: key(ADMIN).sign(&more_identity::relay_message(JOB, POOL, 5)),
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
    for op in late {
        assert!(w.run(op.clone()).is_err(), "{op:?} accepted after closure");
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
        signature: key(L1).sign(&more_identity::lease_message(&other)),
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
    assert!(w.run(void.clone()).is_err(), "void with a live share");
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
    let consent = key(ADMIN).sign(&more_identity::relay_message(JOB, POOL, 30));
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
