//! Ledger API seen from outside the crate: who may request what, and what a compromised service
//! can still do.

// Test code: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gpu_ledger::*;
use more_identity::{mandate_message, IdentityAuthority, ServiceRole};

fn open_escrow(w: &mut World, job: u32, max: Amount) -> Res {
    w.open(job, max)
}

fn balances(w: &World) -> Vec<(Account, i128)> {
    w.balances()
}

#[test]
fn only_treasury_issues() {
    let mut w = world();
    let before = balances(&w);
    for role in [
        ServiceRole::Orchestrator,
        ServiceRole::Delivery,
        ServiceRole::Scheduler,
        ServiceRole::Auditor,
    ] {
        let cred = w.auth.issue(role);
        let e = w
            .ledger
            .execute(
                &cred,
                LedgerOp::Issue {
                    key: "x".into(),
                    to: IssueTo::User(BOB),
                    amount: 5,
                },
            )
            .unwrap_err();
        assert!(
            matches!(e, LedgerApiError::Forbidden { .. }),
            "{role:?}: {e:?}"
        );
    }
    assert_eq!(before, balances(&w));
}

#[test]
fn credential_from_another_authority_is_rejected() {
    let mut w = world();
    let mut rogue = IdentityAuthority::new([4; 32]);
    let fake_treasury = rogue.issue(ServiceRole::Treasury);
    let e = w
        .ledger
        .execute(
            &fake_treasury,
            LedgerOp::Issue {
                key: "x".into(),
                to: IssueTo::User(BOB),
                amount: 5,
            },
        )
        .unwrap_err();
    assert!(matches!(e, LedgerApiError::Unauthenticated(_)));
}

#[test]
fn revoked_credential_is_rejected() {
    let mut w = world();
    w.auth.revoke(w.treasury.id());
    let e = w
        .ledger
        .execute(
            &w.treasury.clone(),
            LedgerOp::Issue {
                key: "x".into(),
                to: IssueTo::User(BOB),
                amount: 5,
            },
        )
        .unwrap_err();
    assert!(matches!(e, LedgerApiError::Unauthenticated(_)));
}

#[test]
fn issuance_limits_hold_near_u64_max() {
    let mut w = world();
    for amount in [
        u64::MAX,
        u64::MAX / 2,
        LedgerLimits::default().max_issue + 1,
    ] {
        let e = w
            .ledger
            .execute(
                &w.treasury,
                LedgerOp::Issue {
                    key: format!("big{amount}"),
                    to: IssueTo::User(BOB),
                    amount,
                },
            )
            .unwrap_err();
        assert!(matches!(e, LedgerApiError::LimitExceeded(_)), "{e:?}");
    }
}

#[test]
fn escrow_needs_the_owners_signed_mandate() {
    let mut w = world();
    let t = terms(100);
    let signature = key(ALICE).sign(&mandate_message(&dom(), 1, POOL, ALICE, &t));
    let open = |job, owner, terms, signature| LedgerOp::OpenEscrow {
        job,
        owner,
        pool: POOL,
        terms,
        signature,
    };
    // More budget, a lower model size (bigger shares per layer) or another price than signed.
    for forged in [
        JobTerms {
            max_budget: 1_000,
            ..t
        },
        JobTerms { layers: 1, ..t },
        JobTerms {
            price: [0, 80, 0],
            ..t
        },
    ] {
        let e = w.run(open(1, ALICE, forged, signature)).unwrap_err();
        assert_eq!(e, LedgerApiError::BadMandate);
    }
    // Alice's signature used to open an escrow on Bob's account, or for another job.
    assert_eq!(
        w.run(open(1, BOB, t, signature)).unwrap_err(),
        LedgerApiError::BadMandate
    );
    assert_eq!(
        w.run(open(2, ALICE, t, signature)).unwrap_err(),
        LedgerApiError::BadMandate
    );
    w.run(open(1, ALICE, t, signature)).unwrap();
    assert_eq!(
        w.run(open(1, ALICE, t, signature)).unwrap_err(),
        LedgerApiError::EscrowExists(1)
    );
}

/// A compromised scheduler / orchestrator holds a valid Orchestrator credential. It still cannot
/// move credits between users, take more than the owner signed for, or reach another job's money.
#[test]
fn compromise_scheduler_cannot_move_arbitrary_balances() {
    let mut w = world();
    open_escrow(&mut w, 1, 100).unwrap();
    let before = balances(&w);
    let attempts = [
        // Beyond the mandate.
        LedgerOp::Reserve {
            job: 1,
            bucket: EscrowBucket::Work,
            key: "r".into(),
            amount: 101,
        },
        // A job with no escrow (no mandate from anyone).
        LedgerOp::Reserve {
            job: 9,
            bucket: EscrowBucket::Work,
            key: "r9".into(),
            amount: 1,
        },
        // Pool money into a job of another pool's... job 9 has no escrow either.
        LedgerOp::FundRecovery {
            job: 9,
            amount: 10,
            signature: [0; 64],
        },
        // Pool money into job 1 without its admin's signature.
        LedgerOp::FundRecovery {
            job: 1,
            amount: 10,
            signature: [0; 64],
        },
        // Settlement only follows the escrow record; there is no destination field to abuse.
        LedgerOp::SettleJob { job: 9 },
        // Issuance.
        LedgerOp::Issue {
            key: "i".into(),
            to: IssueTo::User(BOB),
            amount: 1,
        },
        // A held reward that does not exist.
        LedgerOp::ReleaseReward {
            line: LineRef {
                job: 1,
                attempt: 1,
                slice: 1,
                lender: BOB,
            },
        },
    ];
    for op in attempts {
        assert!(
            w.ledger.execute(&w.orch, op.clone()).is_err(),
            "{op:?} accepted"
        );
    }
    assert_eq!(before, balances(&w));
    // Within the mandate, cumulatively: 60 + 40 is fine, one more credit is not.
    w.ledger
        .execute(
            &w.orch,
            LedgerOp::Reserve {
                job: 1,
                bucket: EscrowBucket::Work,
                key: "a".into(),
                amount: 60,
            },
        )
        .unwrap();
    w.ledger
        .execute(
            &w.orch,
            LedgerOp::Reserve {
                job: 1,
                bucket: EscrowBucket::Recovery,
                key: "b".into(),
                amount: 40,
            },
        )
        .unwrap();
    let e = w
        .ledger
        .execute(
            &w.orch,
            LedgerOp::Reserve {
                job: 1,
                bucket: EscrowBucket::Work,
                key: "c".into(),
                amount: 1,
            },
        )
        .unwrap_err();
    assert!(matches!(e, LedgerApiError::MandateExceeded { .. }));
    // Settlement returns everything to the owner, not to whoever the caller would like.
    w.ledger
        .execute(&w.orch, LedgerOp::SettleJob { job: 1 })
        .unwrap();
    assert_eq!(before, balances(&w));
}

/// A compromised delivery service has its own credential, with no write right at all.
#[test]
fn compromise_delivery_cannot_issue_or_move_credits() {
    let mut w = world();
    open_escrow(&mut w, 1, 100).unwrap();
    w.ledger
        .execute(
            &w.orch,
            LedgerOp::Reserve {
                job: 1,
                bucket: EscrowBucket::Work,
                key: "a".into(),
                amount: 60,
            },
        )
        .unwrap();
    let delivery = w.auth.issue(ServiceRole::Delivery);
    let before = balances(&w);
    let ops = [
        LedgerOp::Issue {
            key: "i".into(),
            to: IssueTo::User(BOB),
            amount: 1,
        },
        LedgerOp::ChargeOutput {
            job: 1,
            attempt: 1,
            output: out(0),
            gen: 0,
        },
        LedgerOp::VoidOutput {
            job: 1,
            output: out(0),
            gen: 0,
        },
        LedgerOp::RegisterAttempt {
            assignment: assignment(1, &[L1, L2], &[3, 1], 0),
        },
        LedgerOp::SettleJob { job: 1 },
    ];
    for op in ops {
        let e = w.ledger.execute(&delivery, op).unwrap_err();
        assert!(matches!(
            e,
            LedgerApiError::Forbidden {
                role: ServiceRole::Delivery,
                ..
            }
        ));
    }
    assert!(w
        .ledger
        .job_balance(&delivery, Account::EscrowWork(1))
        .is_err());
    assert!(w.ledger.audit_view(&delivery).is_err());
    assert_eq!(before, balances(&w));
}

#[test]
fn only_orchestrator_reads_job_accounts_and_only_auditor_reads_all() {
    let w = world();
    assert!(w
        .ledger
        .job_balance(&w.orch, Account::EscrowWork(1))
        .is_ok());
    assert!(w.ledger.job_balance(&w.orch, Account::User(ALICE)).is_err());
    assert!(w.ledger.audit_view(&w.orch).is_err());
    assert!(w.ledger.audit_view(&w.treasury).is_err());
}
