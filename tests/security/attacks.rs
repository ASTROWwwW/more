//! The ten attacks of the code audit, each checked to leave the state untouched.

use super::*;

/// 1. Account A cancels account B's job.
#[test]
fn borrower_cannot_cancel_another_borrowers_job() {
    let mut e = Edge::running();
    e.refused(BORROWERS[1], Message::CancelJob { job: J1 }, "UNAUTHORIZED");
    e.refused(BORROWERS[1], Message::PauseJob { job: J1 }, "UNAUTHORIZED");
    assert_eq!(
        e.send(BORROWERS[0], Message::CancelJob { job: J1 }),
        Ok(Outcome::Applied)
    );
}

/// 2. Account A confirms account B's tokens.
#[test]
fn borrower_cannot_ack_or_confirm_another_borrowers_tokens() {
    let mut e = Edge::running();
    e.refused(
        BORROWERS[1],
        Message::TokenAck {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2,
        },
        "UNAUTHORIZED",
    );
    let digest = e.sim.coord.frame_digest(J1, GEN, 0);
    e.refused(
        BORROWERS[1],
        Message::DeliveryConfirm {
            job: J1,
            wt: GEN,
            confirmed: 0,
            digest,
        },
        "UNAUTHORIZED",
    );
    e.refused(
        LENDERS[2],
        Message::ClientHeartbeat { job: J1 },
        "UNAUTHORIZED",
    );
}

/// 3. A lender passes itself off as the witness.
#[test]
fn lender_cannot_act_as_witness() {
    let mut e = Edge::running();
    let digest = e.sim.coord.frame_digest(J1, GEN, 2);
    let attest = Message::DeliveryAttestation {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
        digest,
    };
    // Signed as itself: the attester is the signer, and it is not the assigned witness.
    e.refused(LENDERS[2], attest.clone(), "INADMISSIBLE_PROOF");
    // Claiming to be the witness without its key: the signature does not verify.
    let mut forged = e.envelope(WITNESS, attest);
    forged.signature = user_key(LENDERS[2]).sign(&forged.signing_bytes());
    let before = e.sim.coord.clone();
    assert_eq!(
        e.send_env(&forged).map_err(|x| x.code()),
        Err("BAD_SIGNATURE")
    );
    assert_eq!(before, e.sim.coord);
    // Reporting the witness's buffer lost, or committing for it.
    e.refused(
        LENDERS[0],
        Message::WitnessLost {
            job: J1,
            attempt: 1,
        },
        "UNAUTHORIZED",
    );
}

/// 4. A lender renews another node's lease.
#[test]
fn only_lenders_of_the_attempt_renew_its_lease() {
    let mut e = Edge::running();
    e.refused(
        LENDERS[3],
        Message::Heartbeat {
            job: J1,
            attempt: 1,
        },
        "UNAUTHORIZED",
    );
    e.refused(
        BORROWERS[0],
        Message::Heartbeat {
            job: J1,
            attempt: 1,
        },
        "UNAUTHORIZED",
    );
    e.refused(
        LENDERS[0],
        Message::Produced {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 3,
        },
        "UNAUTHORIZED",
    );
}

/// 5. A receipt commitment made in another lender's name, or by the producer itself.
#[test]
fn receipt_commitments_come_from_the_recipient_only() {
    let mut e = Edge::running();
    let commit = |e: &Edge, producer: AccountId, digest: Option<u64>| Message::ReceiptCommit {
        job: J1,
        attempt: 1,
        producer,
        wt: GEN,
        upto: 2,
        digest: digest.unwrap_or_else(|| e.sim.coord.receipt_digest(J1, 1, producer, GEN, 2)),
        signature: UNSIGNED,
    };
    // Self-commitment would let a lender skip the anti-collusion cap.
    let m = commit(&e, LENDERS[0], None);
    e.refused(LENDERS[0], m, "UNAUTHORIZED");
    // Lender 12 is not the recipient of lender 10 (lender 11 is).
    let m = commit(&e, LENDERS[0], None);
    e.refused(LENDERS[2], m, "UNAUTHORIZED");
    // The recipient with a digest that does not bind these receipts.
    let m = commit(&e, LENDERS[0], Some(7));
    e.refused(LENDERS[1], m, "INADMISSIBLE_PROOF");
    // The recipient, correctly bound but unsigned: the ledger keeps no receipt (LEDGER-016).
    let m = commit(&e, LENDERS[0], None);
    e.refused(LENDERS[1], m, "INADMISSIBLE_PROOF");
    // The recipient, correctly bound and signed.
    let signed = |e: &Edge, producer: AccountId, by: AccountId| {
        let Message::ReceiptCommit { digest, .. } = commit(e, producer, None) else {
            unreachable!()
        };
        let msg = more_identity::receipt_message(J1.0, 1, producer.0, GEN.idx() as u8, 2, digest);
        Message::ReceiptCommit {
            job: J1,
            attempt: 1,
            producer,
            wt: GEN,
            upto: 2,
            digest,
            signature: user_key(by).sign(&msg),
        }
    };
    let m = signed(&e, LENDERS[0], LENDERS[1]);
    assert_eq!(e.send(LENDERS[1], m), Ok(Outcome::Applied));
    // The output node's receipts are committed by the witness.
    let m = signed(&e, LENDERS[2], WITNESS);
    e.refused(LENDERS[2], m.clone(), "UNAUTHORIZED");
    assert_eq!(e.send(WITNESS, m), Ok(Outcome::Applied));
    // A receipt signed by someone other than the recipient proves nothing.
    let m = signed(&e, LENDERS[1], LENDERS[0]);
    e.refused(LENDERS[2], m, "INADMISSIBLE_PROOF");
}

/// 6. An expired or revoked attempt still sends work.
#[test]
fn expired_or_revoked_attempt_cannot_send_work() {
    let mut e = Edge::running();
    e.sim.exec(Command::Tick { dt: 46 }).unwrap();
    let produce = Message::Produced {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 3,
    };
    e.refused(LENDERS[2], produce.clone(), "LEASE_EXPIRED");
    e.refused(
        LENDERS[0],
        Message::Heartbeat {
            job: J1,
            attempt: 1,
        },
        "LEASE_EXPIRED",
    );
    e.sim.exec(Command::Reconcile).unwrap();
    e.refused(LENDERS[2], produce, "STALE_ATTEMPT");
}

/// 7. A job whose price was fraudulently set to zero.
#[test]
fn the_client_never_sets_the_price() {
    let mut e = Edge::running();
    let j = &e.sim.coord.jobs()[&J1];
    assert_eq!(j.price, catalog()[0].2.price, "price comes from the tariff");
    // The message has no price field. A budget below the tariff's cost is refused.
    let budget = 10;
    let m = Message::SubmitJob {
        job: JobId(7),
        pool: CREDIT_POOL,
        model: ModelId(1),
        outputs: [0, 12, 0],
        max_budget: budget,
        mandate: mandate(
            JobId(7),
            CREDIT_POOL,
            BORROWERS[0],
            ModelId(1),
            [0, 12, 0],
            budget,
        ),
    };
    e.refused(BORROWERS[0], m, "PRECONDITION_FAILED");
    // A free-sharing pool cannot be given a tariff, and a credit pool cannot price above the
    // bound.
    let mut s = catalog()[2].2;
    s.price = [0, 1, 0];
    e.refused(
        POOL_ADMIN,
        Message::RegisterModel {
            pool: FREE_POOL,
            model: ModelId(3),
            spec: s,
        },
        "INVALID_INPUT",
    );
    // Only the pool admin sets tariffs.
    e.refused(
        BORROWERS[0],
        Message::RegisterModel {
            pool: CREDIT_POOL,
            model: ModelId(9),
            spec: ModelSpec {
                layers: 1,
                price: [0; 3],
                max_outputs: [1; 3],
            },
        },
        "UNAUTHORIZED",
    );
}

/// 8. A borrower that is not a member of a private pool.
#[test]
fn non_member_cannot_use_a_private_pool() {
    let mut e = Edge::running();
    let submit = |job: u32, pool| Message::SubmitJob {
        job: JobId(job),
        pool,
        model: ModelId(1),
        outputs: [0, 1, 0],
        max_budget: 100,
        mandate: mandate(JobId(job), pool, STRANGER, ModelId(1), [0, 1, 0], 100),
    };
    e.refused(STRANGER, submit(7, CREDIT_POOL), "UNAUTHORIZED");
    e.refused(
        STRANGER,
        Message::JoinPool { pool: CREDIT_POOL },
        "PRECONDITION_FAILED",
    );
    e.refused(
        STRANGER,
        Message::SetRights {
            pool: CREDIT_POOL,
            account: STRANGER,
            rights: Rights {
                borrow: true,
                lend: true,
                witness: true,
            },
        },
        "UNAUTHORIZED",
    );
    // An open pool admits members by themselves, borrow and lend only.
    e.sim
        .exec_as(
            &e.sim.as_service(ServiceRole::PlatformAdmin),
            Command::CreatePool {
                pool: PoolId(5),
                mode: PoolMode::Credits,
                access: PoolAccess::Open,
                admin: POOL_ADMIN,
            },
        )
        .unwrap();
    assert_eq!(
        e.send(STRANGER, Message::JoinPool { pool: PoolId(5) }),
        Ok(Outcome::Applied)
    );
    let r = e.sim.coord.registry().pools()[&PoolId(5)].rights(STRANGER);
    assert!(r.borrow && r.lend && !r.witness);
}

/// 9. Monetary and numeric input close to `u64::MAX`, in debug and release builds alike.
#[test]
fn extreme_values_are_refused_without_panic() {
    let mut e = Edge::running();
    let before_balances = total_user_balances(&e.sim);
    let treasury = e.sim.as_service(ServiceRole::Treasury);
    for amount in [u64::MAX, u64::MAX / 2, 1 << 63] {
        let r = e.sim.exec_as(
            &treasury,
            Command::Issue {
                id: 77,
                to: IssueTarget::User(STRANGER),
                amount,
            },
        );
        assert_eq!(r.map_err(|x| x.code()), Err("LIMIT_EXCEEDED"));
    }
    let clock = e.sim.as_service(ServiceRole::Clock);
    assert_eq!(
        e.sim
            .exec_as(&clock, Command::Tick { dt: u64::MAX })
            .map_err(|x| x.code()),
        Err("ARITHMETIC_OVERFLOW")
    );
    // Each bound on its own, so that removing any one of them is noticed.
    let ok = ModelSpec {
        layers: 4,
        price: [1, 1, 1],
        max_outputs: [1, 1, 1],
    };
    for spec in [
        ModelSpec {
            layers: u32::MAX,
            ..ok
        },
        ModelSpec {
            price: [0, u64::MAX, 0],
            ..ok
        },
        ModelSpec {
            price: [0, 1_000_000_001, 0],
            ..ok
        },
        ModelSpec {
            max_outputs: [0, u32::MAX, 0],
            ..ok
        },
    ] {
        e.refused(
            POOL_ADMIN,
            Message::RegisterModel {
                pool: CREDIT_POOL,
                model: ModelId(9),
                spec,
            },
            "INVALID_INPUT",
        );
    }
    let m = Message::SubmitJob {
        job: JobId(7),
        pool: CREDIT_POOL,
        model: ModelId(1),
        outputs: [u32::MAX; 3],
        max_budget: u64::MAX,
        mandate: mandate(
            JobId(7),
            CREDIT_POOL,
            BORROWERS[0],
            ModelId(1),
            [u32::MAX; 3],
            u64::MAX,
        ),
    };
    e.refused(BORROWERS[0], m, "INVALID_INPUT");
    e.refused(
        POOL_ADMIN,
        Message::FundRecovery {
            job: J1,
            amount: u64::MAX,
            signature: UNSIGNED,
        },
        "ARITHMETIC_OVERFLOW",
    );
    // A recovery claim of u64::MAX is staged like any claim, then rejected at closure: it does not
    // fit in the attempt's earmark (JOB-S03), and nothing is reserved.
    let slice = SliceId {
        job: J1,
        attempt: 1,
        slice: 1,
    };
    let claim = Message::UsageReport {
        slice,
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: u64::MAX,
            evidence: Evidence::Committed,
        }],
    };
    assert_eq!(e.send(LENDERS[0], claim), Ok(Outcome::Applied));
    e.sim.exec(Command::CloseSlice { slice }).unwrap();
    let s = &e.sim.coord.slices()[&slice];
    assert_eq!(s.rejected_items, 1);
    assert!(s.lines.is_empty());
    assert!(e.sim.violations.is_empty(), "{:#?}", e.sim.violations);
    assert_eq!(before_balances, total_user_balances(&e.sim));
}

/// 10. A response lost, then the same message sent again.
#[test]
fn retransmission_gets_the_first_answer_and_runs_nothing() {
    let mut e = Edge::running();
    // Refused message, sent again verbatim: same answer, nothing run.
    let stale = e.envelope(
        LENDERS[0],
        Message::Heartbeat {
            job: J1,
            attempt: 9,
        },
    );
    let first = e.send_env(&stale);
    assert_eq!(first.clone().map_err(|x| x.code()), Err("STALE_ATTEMPT"));
    let before = e.sim.coord.clone();
    assert_eq!(e.send_env(&stale), first);
    assert_eq!(before, e.sim.coord);
    // Accepted ack whose answer was lost: verbatim retransmission returns the stored answer.
    let ack = e.envelope(
        BORROWERS[0],
        Message::TokenAck {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2,
        },
    );
    assert_eq!(e.send_env(&ack), Ok(Outcome::Applied));
    let after_first = e.sim.coord.clone();
    assert_eq!(e.send_env(&ack), Ok(Outcome::Applied));
    assert_eq!(
        after_first, e.sim.coord,
        "a retransmission ran the command again"
    );
    // The client did not keep the envelope and sends the same ack under a new number: the
    // business key (cumulative ack) makes it a no-op.
    let again = e.send(
        BORROWERS[0],
        Message::TokenAck {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2,
        },
    );
    assert_eq!(again, Ok(Outcome::AlreadyApplied));
    assert_eq!(after_first, e.sim.coord);
    // Same number, other content: replay.
    let mut altered = ack.clone();
    altered.body = Message::TokenAck {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 1,
    };
    altered.signature = user_key(BORROWERS[0]).sign(&altered.signing_bytes());
    assert_eq!(e.send_env(&altered), Err(ProtoError::Replay));
}
