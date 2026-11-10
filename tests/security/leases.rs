//! Second audit, findings 4 and 5: one answer must not start the cluster, and a live node must
//! not keep a silent one alive (JOB-R38, JOB-R39). Plus the proofs the ledger now asks for, seen
//! from the coordinator's commands.

use super::*;

const L: [AccountId; 3] = [LENDERS[0], LENDERS[1], LENDERS[2]];

fn placed() -> Sim {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    sim.exec(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim
}

fn accept(l: AccountId) -> Command {
    Command::AcceptLease {
        job: J1,
        attempt: 1,
        lender: l,
        signature: UNSIGNED,
    }
}

fn loaded(l: AccountId) -> Command {
    Command::LeaseLoaded {
        job: J1,
        attempt: 1,
        lender: l,
        config: UNSET_CONFIG,
    }
}

fn ready(l: AccountId) -> Command {
    Command::AttemptReady {
        job: J1,
        attempt: 1,
        lender: l,
        restored: [0; 3],
        state: UNSET_STATE,
        signature: UNSIGNED,
    }
}

#[track_caller]
fn clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

fn lease(sim: &Sim, k: usize) -> Lease {
    sim.coord.jobs()[&J1].attempts[&1].leases[k]
}

/// Finding 4: the attempt starts only when every lender has accepted, loaded and reported ready.
#[test]
fn r2_one_ready_lender_does_not_start_the_cluster() {
    let mut sim = placed();
    for cmd in [accept(L[0]), loaded(L[0]), ready(L[0])] {
        sim.exec(cmd).unwrap();
    }
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Placing);
    assert_eq!(lease(&sim, 0).state, LeaseState::Ready);
    assert_eq!(lease(&sim, 1).state, LeaseState::Assigned);
    // Nothing can be produced on a cluster that has not started.
    let produce = Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 1,
    };
    assert_eq!(sim.exec(produce), Err(DomainError::StaleAttempt));
    for l in [L[1], L[2]] {
        for cmd in [accept(l), loaded(l)] {
            sim.exec(cmd).unwrap();
        }
    }
    sim.exec(ready(L[1])).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Placing);
    sim.exec(ready(L[2])).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Running);
    clean(&sim);
}

/// A lease moves one state at a time, on its own lender's word and signature, with the right
/// configuration.
#[test]
fn r2_lease_steps_are_ordered_personal_and_signed() {
    let mut sim = placed();
    let refused = |sim: &mut Sim, ctx: &AuthContext, cmd: Command, code: &str| {
        let before = sim.coord.clone();
        let r = sim.exec_as(ctx, cmd.clone());
        assert_eq!(r.map_err(|e| e.code()), Err(code), "{cmd:?}");
        assert_eq!(before, sim.coord);
    };
    let me = |a: AccountId| more_identity::assume_account(a.0);
    // Skipping a step.
    refused(&mut sim, &me(L[0]), loaded(L[0]), "PRECONDITION_FAILED");
    refused(&mut sim, &me(L[0]), ready(L[0]), "PRECONDITION_FAILED");
    // Speaking for another lender, as a lender of the same attempt or as the scheduler.
    refused(&mut sim, &me(L[1]), accept(L[0]), "UNAUTHORIZED");
    let scheduler = sim.as_service(ServiceRole::Scheduler);
    refused(&mut sim, &scheduler, accept(L[0]), "UNAUTHORIZED");
    refused(&mut sim, &me(STRANGER), accept(STRANGER), "UNAUTHORIZED");
    // A lease signed with another key: the ledger refuses it, so does the coordinator.
    let a = sim.coord.jobs()[&J1].attempts[&1].clone();
    let msg = more_identity::lease_message(&assignment_of(J1, &a));
    let forged = Command::AcceptLease {
        job: J1,
        attempt: 1,
        lender: L[0],
        signature: user_key(L[1]).sign(&msg),
    };
    refused(&mut sim, &me(L[0]), forged, "INADMISSIBLE_PROOF");
    sim.exec(accept(L[0])).unwrap();
    // The wrong configuration is not a loaded stage.
    let wrong = Command::LeaseLoaded {
        job: J1,
        attempt: 1,
        lender: L[0],
        config: sim.coord.config_digest(J1, 1, 1).unwrap(),
    };
    refused(&mut sim, &me(L[0]), wrong, "INADMISSIBLE_PROOF");
    sim.exec(loaded(L[0])).unwrap();
    // Readiness signed by someone else.
    let forged = Command::AttemptReady {
        job: J1,
        attempt: 1,
        lender: L[0],
        restored: [0; 3],
        state: 7,
        signature: user_key(L[1]).sign(&more_identity::ready_message(J1.0, 1, L[0].0, [0; 3], 7)),
    };
    refused(&mut sim, &me(L[0]), forged, "INADMISSIBLE_PROOF");
    // A repeated step changes nothing.
    assert_eq!(sim.exec(accept(L[0])), Ok(Outcome::AlreadyApplied));
    clean(&sim);
}

/// Finding 5: a heartbeat renews the sender's lease only; the silent node's lease runs out and
/// the attempt is revoked for it.
#[test]
fn r2_a_heartbeat_renews_only_its_own_lease() {
    let mut sim = placed();
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    let ttl = sim.coord.config().lease_ttl;
    let hb = |l| Command::Heartbeat {
        job: J1,
        attempt: 1,
        lender: l,
    };
    let wit = Command::WitnessHeartbeat {
        job: J1,
        attempt: 1,
        witness: WITNESS,
    };
    sim.exec(Command::Tick { dt: ttl - 5 }).unwrap();
    // Lenders 0 and 1 and the witness speak; lender 2 is silent.
    for cmd in [hb(L[0]), hb(L[1]), wit.clone()] {
        sim.exec(cmd).unwrap();
    }
    assert_eq!(lease(&sim, 0).expires_at, sim.coord.now() + ttl);
    assert_eq!(lease(&sim, 2).expires_at, ttl, "untouched by the others");
    // Nobody renews for someone else.
    let other = more_identity::assume_account(L[0].0);
    assert!(matches!(
        sim.exec_as(&other, hb(L[2])),
        Err(DomainError::Unauthorized(_))
    ));
    sim.exec(Command::Tick { dt: 5 }).unwrap();
    // The pipeline has lost a node: nothing more is accepted, and the node cannot come back.
    let produce = Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 1,
    };
    assert_eq!(sim.exec(produce), Err(DomainError::LeaseExpired));
    assert_eq!(sim.exec(hb(L[2])), Err(DomainError::LeaseExpired));
    assert_eq!(sim.exec(hb(L[0])), Ok(Outcome::Applied));
    sim.exec(Command::Reconcile).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Recovering);
    let expired = sim.coord.audit_log().iter().find_map(|e| match e {
        AuditEvent::LeasesExpired { nodes, .. } => Some(nodes.clone()),
        _ => None,
    });
    assert_eq!(expired, Some(vec![L[2]]), "detected for that node alone");
    clean(&sim);
}

/// The witness holds its own lease: lenders cannot renew it, and without it nothing is attested.
#[test]
fn r2_the_witness_lease_is_its_own() {
    let mut sim = placed();
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    let ttl = sim.coord.config().lease_ttl;
    sim.exec(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Tick { dt: ttl - 1 }).unwrap();
    for l in L {
        sim.exec(Command::Heartbeat {
            job: J1,
            attempt: 1,
            lender: l,
        })
        .unwrap();
    }
    let wit = |w| Command::WitnessHeartbeat {
        job: J1,
        attempt: 1,
        witness: w,
    };
    let lender = more_identity::assume_account(L[0].0);
    assert!(matches!(
        sim.exec_as(&lender, wit(WITNESS)),
        Err(DomainError::Unauthorized(_))
    ));
    assert!(matches!(
        sim.exec_as(&lender, wit(L[0])),
        Err(DomainError::Unauthorized(_))
    ));
    sim.exec(Command::Tick { dt: 1 }).unwrap();
    let deliver = Command::Deliver {
        job: J1,
        attempt: 1,
        witness: WITNESS,
        wt: GEN,
        upto: 1,
        digest: sim.coord.frame_digest(J1, GEN, 1),
    };
    assert_eq!(sim.exec(deliver), Err(DomainError::LeaseExpired));
    assert_eq!(sim.exec(wit(WITNESS)), Err(DomainError::LeaseExpired));
    sim.exec(Command::Reconcile).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Recovering);
    clean(&sim);
}

/// An uncommitted claim is paid only if the recipient's receipt was presented; a receipt the
/// recipient did not sign is refused.
#[test]
fn r2_an_uncommitted_claim_needs_the_recipients_receipt() {
    let mut e = Edge::running();
    let sim = &mut e.sim;
    let ack = Command::Ack {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    };
    sim.exec(ack).unwrap();
    let slice = SliceId {
        job: J1,
        attempt: 1,
        slice: 1,
    };
    let item = |pos, stage| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos,
        },
        stage,
        evidence: Evidence::Uncommitted,
    };
    let digest = sim.coord.receipt_digest(J1, 1, L[2], GEN, 1);
    let present = |signature| Command::PresentReceipt {
        job: J1,
        attempt: 1,
        lender: L[2],
        wt: GEN,
        upto: 1,
        digest,
        signature,
    };
    // Signed by the producer itself instead of its recipient (the witness).
    let msg = more_identity::receipt_message(J1.0, 1, L[2].0, GEN.idx() as u8, 1, digest);
    assert_eq!(
        sim.exec(present(user_key(L[2]).sign(&msg))),
        Err(DomainError::InadmissibleProof)
    );
    sim.exec(present(UNSIGNED)).unwrap();
    // Lender 2 presented a receipt for output 0; lender 1 claims without any.
    for (l, stage) in [(L[2], 2), (L[1], 1)] {
        sim.exec(Command::Claim {
            slice,
            lender: l,
            items: vec![item(0, stage)],
        })
        .unwrap();
    }
    sim.exec(Command::CloseSlice { slice }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice }).unwrap();
    let lines = &sim.coord.slices()[&slice].lines;
    assert_eq!(lines[&L[2]].paid, 2);
    assert_eq!((lines[&L[1]].paid, lines[&L[1]].refunded), (0, 4));
    clean(sim);
}

/// The pool's relay needs its admin's signature, checked by the ledger: the scheduler cannot
/// order it, and a consent signed by someone else is refused.
#[test]
fn r2_pool_relay_needs_its_admins_signature() {
    let mut e = Edge::running();
    let sim = &mut e.sim;
    let pool = sim.balance(Account::PoolReserve(CREDIT_POOL.0));
    let msg = more_identity::relay_message(J1.0, CREDIT_POOL.0, 10);
    let fund = |signature| Command::FundRecovery {
        job: J1,
        amount: 10,
        signature,
    };
    assert_eq!(
        sim.exec(fund(user_key(BORROWERS[0]).sign(&msg))),
        Err(DomainError::InadmissibleProof)
    );
    let scheduler = sim.as_service(ServiceRole::Scheduler);
    assert!(matches!(
        sim.exec_as(&scheduler, fund(user_key(POOL_ADMIN).sign(&msg))),
        Err(DomainError::Unauthorized(_))
    ));
    assert_eq!(sim.balance(Account::PoolReserve(CREDIT_POOL.0)), pool);
    sim.exec(fund(UNSIGNED)).unwrap();
    assert_eq!(sim.balance(Account::PoolReserve(CREDIT_POOL.0)), pool - 10);
    clean(sim);
}
