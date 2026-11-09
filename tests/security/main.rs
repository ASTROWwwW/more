//! Security scenarios (SEC-001 to SEC-006, SAFE-001): attacks through the signed protocol edge and
//! from compromised services. Every refused attempt must leave the state exactly as it was.

use gpu_domain::*;
use gpu_protocol::*;
use gpu_simulation::*;
use more_identity::UserKey;

const J1: JobId = JobId(1);
const J2: JobId = JobId(2);
const GEN: WorkType = WorkType::Generate;

/// A simulated world plus the protocol edge (key directory, replay guard).
struct Edge {
    sim: Sim,
    guard: ReplayGuard,
    seq: u64,
}

impl Edge {
    /// Job 1 running on lenders 10, 11, 12 with two tokens produced.
    fn running() -> Self {
        let mut sim = Sim::default();
        for c in [
            Command::Reserve { job: J1 },
            Command::Place {
                job: J1,
                lenders: LENDERS[..3].to_vec(),
                layout: layout_of(J1),
                recovery_estimate: 0,
                witness: WITNESS,
                expected_version: None,
            },
            Command::AttemptReady {
                job: J1,
                attempt: 1,
                restored: [0; 3],
            },
            Command::Produce {
                job: J1,
                attempt: 1,
                wt: GEN,
                upto: 2,
            },
        ] {
            sim.exec(c).unwrap();
        }
        Edge {
            sim,
            guard: ReplayGuard::default(),
            seq: 0,
        }
    }

    fn envelope(&mut self, from: AccountId, body: Message) -> Envelope {
        self.seq += 1;
        Envelope::signed(from, 1, self.seq, body, &user_key(from))
    }

    fn send_env(&mut self, env: &Envelope) -> Answer {
        let keys = self.sim.ids.keys.clone();
        handle(&mut self.guard, &keys, &mut self.sim.coord, env)
    }

    fn send(&mut self, from: AccountId, body: Message) -> Answer {
        let env = self.envelope(from, body);
        self.send_env(&env)
    }

    /// Sends and expects a refusal with `code` that changes nothing.
    #[track_caller]
    fn refused(&mut self, from: AccountId, body: Message, code: &str) {
        let before = self.sim.coord.clone();
        let r = self.send(from, body.clone());
        assert_eq!(r.map_err(|e| e.code()), Err(code), "{from:?} {body:?}");
        assert_eq!(
            before, self.sim.coord,
            "a refused message changed the state"
        );
    }
}

fn total_user_balances(sim: &Sim) -> Vec<(Account, i128)> {
    sim.ledger().accounts().map(|(a, b)| (*a, *b)).collect()
}

// ------------------------------------------------------------------ the ten required cases

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
    // The recipient, correctly bound.
    let m = commit(&e, LENDERS[0], None);
    assert_eq!(e.send(LENDERS[1], m), Ok(Outcome::Applied));
    // The output node's receipts are committed by the witness.
    let m = commit(&e, LENDERS[2], None);
    e.refused(LENDERS[2], m.clone(), "UNAUTHORIZED");
    assert_eq!(e.send(WITNESS, m), Ok(Outcome::Applied));
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
        mandate: mandate(JobId(7), CREDIT_POOL, BORROWERS[0], budget),
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
        mandate: mandate(JobId(job), pool, STRANGER, 100),
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
    let huge = ModelSpec {
        layers: u32::MAX,
        price: [u64::MAX; 3],
        max_outputs: [u32::MAX; 3],
    };
    e.refused(
        POOL_ADMIN,
        Message::RegisterModel {
            pool: CREDIT_POOL,
            model: ModelId(9),
            spec: huge,
        },
        "INVALID_INPUT",
    );
    let m = Message::SubmitJob {
        job: JobId(7),
        pool: CREDIT_POOL,
        model: ModelId(1),
        outputs: [u32::MAX; 3],
        max_budget: u64::MAX,
        mandate: mandate(JobId(7), CREDIT_POOL, BORROWERS[0], u64::MAX),
    };
    e.refused(BORROWERS[0], m, "INVALID_INPUT");
    e.refused(
        POOL_ADMIN,
        Message::FundRecovery {
            job: J1,
            amount: u64::MAX,
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

// ------------------------------------------------------------------ simulated compromises

/// A compromised GPU agent holds a lender's key and a lease on job 1. It cannot touch job 2, act
/// for the borrower of job 1, or reach money.
#[test]
fn compromise_gpu_agent_cannot_cancel_other_jobs() {
    let mut e = Edge::running();
    let agent = LENDERS[0];
    let attacks = vec![
        Message::CancelJob { job: J2 },
        Message::CancelJob { job: J1 },
        Message::PauseJob { job: J1 },
        Message::ResumeJob { job: J1, topup: 1 },
        Message::TokenAck {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2,
        },
        Message::FundRecovery { job: J1, amount: 1 },
        Message::Arbitrate {
            slice: SliceId {
                job: J1,
                attempt: 1,
                slice: 1,
            },
            lender: agent,
            pay: true,
        },
        Message::SetRights {
            pool: CREDIT_POOL,
            account: agent,
            rights: Rights {
                borrow: true,
                lend: true,
                witness: true,
            },
        },
    ];
    for m in attacks {
        e.refused(agent, m, "UNAUTHORIZED");
    }
}

/// A compromised scheduler holds a valid Scheduler credential. Through the coordinator it cannot
/// issue, pay a disputed line, move pool money or speak for a borrower; through the ledger it has
/// no credential at all (the orchestrator's own credential is tested in `gpu-ledger`).
#[test]
fn compromise_scheduler_cannot_move_balances() {
    let mut e = Edge::running();
    let scheduler = e.sim.as_service(ServiceRole::Scheduler);
    let balances = total_user_balances(&e.sim);
    let slice = SliceId {
        job: J1,
        attempt: 1,
        slice: 1,
    };
    let attacks = [
        Command::Issue {
            id: 99,
            to: IssueTarget::User(STRANGER),
            amount: 10,
        },
        Command::FundRecovery { job: J1, amount: 5 },
        Command::Arbitrate {
            slice,
            lender: LENDERS[0],
            pay: true,
        },
        Command::ContestReward {
            slice,
            lender: LENDERS[0],
        },
        Command::Resume { job: J1, topup: 5 },
        Command::Submit {
            job: JobId(8),
            borrower: BORROWERS[0],
            pool: CREDIT_POOL,
            model: ModelId(1),
            outputs: [0, 1, 0],
            max_budget: 100,
            mandate: mandate(JobId(8), CREDIT_POOL, BORROWERS[0], 100),
        },
        Command::Reconcile,
    ];
    for cmd in attacks {
        let before = e.sim.coord.clone();
        let r = e.sim.exec_as(&scheduler, cmd.clone());
        assert_eq!(r.map_err(|x| x.code()), Err("UNAUTHORIZED"), "{cmd:?}");
        assert_eq!(before, e.sim.coord);
    }
    assert_eq!(balances, total_user_balances(&e.sim));
    assert!(e.sim.violations.is_empty(), "{:#?}", e.sim.violations);
}

/// A compromised delivery service (valid Delivery credential) can run no coordinator command.
#[test]
fn compromise_delivery_service_has_no_command() {
    let mut e = Edge::running();
    let delivery = e.sim.as_service(ServiceRole::Delivery);
    let digest = e.sim.coord.frame_digest(J1, GEN, 2);
    for cmd in [
        Command::Issue {
            id: 99,
            to: IssueTarget::User(STRANGER),
            amount: 10,
        },
        Command::Deliver {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 2,
            digest,
        },
        Command::Settle { job: J1 },
        Command::ExpireDeliveryWindow { job: J1 },
    ] {
        let before = e.sim.coord.clone();
        let r = e.sim.exec_as(&delivery, cmd);
        assert_eq!(r.map_err(|x| x.code()), Err("UNAUTHORIZED"));
        assert_eq!(before, e.sim.coord);
    }
}

/// A signature by a key that was never registered, or an envelope altered after signing.
#[test]
fn unsigned_or_altered_messages_are_refused() {
    let mut e = Edge::running();
    let mut env = e.envelope(BORROWERS[0], Message::CancelJob { job: J1 });
    env.signature = UserKey::from_seed([1; 32]).sign(&env.signing_bytes());
    assert_eq!(e.send_env(&env).map_err(|x| x.code()), Err("BAD_SIGNATURE"));
    let mut env = e.envelope(BORROWERS[0], Message::CancelJob { job: J1 });
    env.body = Message::CancelJob { job: J2 };
    assert_eq!(e.send_env(&env).map_err(|x| x.code()), Err("BAD_SIGNATURE"));
    let env = Envelope::signed(
        AccountId(4242),
        1,
        1,
        Message::CancelJob { job: J1 },
        &UserKey::from_seed([3; 32]),
    );
    assert_eq!(
        e.send_env(&env).map_err(|x| x.code()),
        Err("UNKNOWN_ACCOUNT")
    );
    assert_eq!(e.sim.coord.jobs()[&J1].exec, ExecStatus::Running);
}

/// SAFE-002: one account cannot hold two ranges of the same attempt (it would commit its own
/// receipts).
#[test]
fn one_lender_holds_one_range() {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    let r = sim.exec(Command::Place {
        job: J1,
        lenders: vec![LENDERS[0], LENDERS[0], LENDERS[1]],
        layout: layout_of(J1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    assert!(matches!(r, Err(DomainError::Precondition(_))));
    // Nor a layout that does not cover the model.
    let r = sim.exec(Command::Place {
        job: J1,
        lenders: LENDERS[..3].to_vec(),
        layout: vec![1, 1, 1],
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    assert!(matches!(r, Err(DomainError::Precondition(_))));
    assert!(sim.violations.is_empty());
}
