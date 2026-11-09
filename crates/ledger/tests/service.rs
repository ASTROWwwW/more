//! Ledger API seen from outside the crate: who may request what, and what a compromised service
//! can still do.

// Test code: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gpu_ledger::*;
use more_identity::{mandate_message, IdentityAuthority, KeyDirectory, ServiceRole, UserKey};

struct World {
    auth: IdentityAuthority,
    ledger: LedgerService,
    treasury: more_identity::ServiceCredential,
    orch: more_identity::ServiceCredential,
    alice: UserKey,
}

const ALICE: u32 = 1;
const BOB: u32 = 2;
const POOL: u32 = 7;

fn world() -> World {
    let mut auth = IdentityAuthority::new([3; 32]);
    let keys = KeyDirectory::new();
    let alice = UserKey::from_seed([11; 32]);
    keys.register(ALICE, alice.public()).unwrap();
    keys.register(BOB, UserKey::from_seed([12; 32]).public())
        .unwrap();
    let mut ledger = LedgerService::new(auth.verifier(), keys, LedgerLimits::default());
    let treasury = auth.issue(ServiceRole::Treasury);
    let orch = auth.issue(ServiceRole::Orchestrator);
    for (k, to) in [
        ("i1", IssueTo::User(ALICE)),
        ("i2", IssueTo::User(BOB)),
        ("i3", IssueTo::Pool(POOL)),
    ] {
        ledger
            .execute(
                &treasury,
                LedgerOp::Issue {
                    key: k.into(),
                    to,
                    amount: 1_000,
                },
            )
            .unwrap();
    }
    World {
        auth,
        ledger,
        treasury,
        orch,
        alice,
    }
}

fn open_escrow(w: &mut World, job: u32, max: Amount) -> Result<LedgerOutcome, LedgerApiError> {
    let signature = w.alice.sign(&mandate_message(job, POOL, ALICE, max));
    w.ledger.execute(
        &w.orch,
        LedgerOp::OpenEscrow {
            job,
            owner: ALICE,
            pool: POOL,
            max_budget: max,
            signature,
        },
    )
}

fn balances(w: &World) -> Vec<(Account, i128)> {
    let auditor = {
        // A fresh auditor credential from the same authority.
        let mut a = IdentityAuthority::new([3; 32]);
        // Credentials are bound to the authority secret, not to the instance: same secret, same
        // verifier. Ids restart at 1, which is fine for a read-only role in a test.
        a.issue(ServiceRole::Auditor)
    };
    w.ledger
        .audit_view(&auditor)
        .unwrap()
        .accounts()
        .map(|(a, b)| (*a, *b))
        .collect()
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
    // Signed by Alice for job 1, presented for job 2: rejected.
    let signature = w.alice.sign(&mandate_message(1, POOL, ALICE, 100));
    let e = w
        .ledger
        .execute(
            &w.orch,
            LedgerOp::OpenEscrow {
                job: 2,
                owner: ALICE,
                pool: POOL,
                max_budget: 100,
                signature,
            },
        )
        .unwrap_err();
    assert_eq!(e, LedgerApiError::BadMandate);
    // Alice's mandate claimed for Bob's account: rejected.
    let e = w
        .ledger
        .execute(
            &w.orch,
            LedgerOp::OpenEscrow {
                job: 1,
                owner: BOB,
                pool: POOL,
                max_budget: 100,
                signature,
            },
        )
        .unwrap_err();
    assert_eq!(e, LedgerApiError::BadMandate);
    open_escrow(&mut w, 1, 100).unwrap();
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
            key: "f".into(),
            amount: 10,
        },
        // Settlement only follows the escrow record; there is no destination field to abuse.
        LedgerOp::SettleJob {
            job: 9,
            pool_unspent: 0,
        },
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
            key: "x".into(),
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
        .execute(
            &w.orch,
            LedgerOp::SettleJob {
                job: 1,
                pool_unspent: 0,
            },
        )
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
            key: "c".into(),
            amount: 10,
        },
        LedgerOp::VoidOutput {
            job: 1,
            key: "v".into(),
            amount: 10,
        },
        LedgerOp::SettleJob {
            job: 1,
            pool_unspent: 0,
        },
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

/// An operation with several entries is written entirely or not at all.
#[test]
fn failed_multi_entry_operation_writes_nothing() {
    let mut w = world();
    open_escrow(&mut w, 1, 500).unwrap();
    let ops = |key: &str, lender: u32| {
        let line = LineRef {
            job: 1,
            attempt: 1,
            slice: 1,
            lender,
        };
        vec![
            LedgerOp::ChargeOutput {
                job: 1,
                key: format!("{key}/charge"),
                amount: 10,
            },
            LedgerOp::ReserveLine {
                line,
                source: LineSource::OutputHold,
                key: format!("{key}/line"),
                amount: 10,
            },
            LedgerOp::PayLine {
                line,
                key: format!("{key}/pay"),
                amount: 10,
            },
        ]
    };
    w.ledger
        .execute(
            &w.orch,
            LedgerOp::Reserve {
                job: 1,
                bucket: EscrowBucket::Work,
                key: "r".into(),
                amount: 100,
            },
        )
        .unwrap();
    for op in ops("l10", 10).into_iter().chain(ops("l11", 11)) {
        w.ledger.execute(&w.orch, op).unwrap();
    }
    let line = |lender| LineRef {
        job: 1,
        attempt: 1,
        slice: 1,
        lender,
    };
    // Writes `contest/a/pool` and `contest/a`.
    w.ledger
        .execute(
            &w.orch,
            LedgerOp::ContestReward {
                line: line(10),
                key: "a".into(),
                pool_part: 3,
            },
        )
        .unwrap();
    let before = balances(&w);
    // First entry `contest/a/pool/pool` is new, the second `contest/a/pool` is taken: the first
    // one must be undone.
    let e = w
        .ledger
        .execute(
            &w.orch,
            LedgerOp::ContestReward {
                line: line(11),
                key: "a/pool".into(),
                pool_part: 3,
            },
        )
        .unwrap_err();
    assert!(
        matches!(e, LedgerApiError::Ledger(LedgerError::DuplicateKey(_))),
        "{e:?}"
    );
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
