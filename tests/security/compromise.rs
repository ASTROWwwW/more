//! Simulated compromises: a GPU agent, the scheduler, the delivery service, a revoked or forged
//! credential, and the distinct-lender rule.

use super::*;

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
        Message::FundRecovery {
            job: J1,
            amount: 1,
            signature: UNSIGNED,
        },
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
        Command::FundRecovery {
            job: J1,
            amount: 5,
            signature: UNSIGNED,
        },
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
            mandate: mandate(
                JobId(8),
                CREDIT_POOL,
                BORROWERS[0],
                ModelId(1),
                [0, 1, 0],
                100,
            ),
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
        sim_domain(),
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
    // LEDGER-019: a message signed by the right account for another deployment is refused before
    // anything else; changing the field afterwards breaks the signature.
    let other = more_identity::IdentityAuthority::new([9; 32]).domain();
    let cancel = Message::CancelJob { job: J1 };
    let borrower = user_key(BORROWERS[0]);
    let elsewhere = Envelope::signed(other, BORROWERS[0], 1, 900, cancel.clone(), &borrower);
    assert_eq!(
        e.send_env(&elsewhere).map_err(|x| x.code()),
        Err("WRONG_DEPLOYMENT")
    );
    let mut moved = elsewhere.clone();
    moved.domain = sim_domain();
    assert_eq!(
        e.send_env(&moved).map_err(|x| x.code()),
        Err("BAD_SIGNATURE")
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
