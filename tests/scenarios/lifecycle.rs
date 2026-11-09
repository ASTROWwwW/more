//! JOB-F01 to JOB-F14: transitions, retries, races, revocation, malformed input.

use super::*;

#[test]
fn f01_partial_transition_leaves_no_trace() {
    // A two-entry transition whose second entry fails writes nothing (JOB-R01).
    let mut t = T::new();
    t.sim.register(AccountId(3));
    t.ok(Command::SetRights {
        pool: CREDIT_POOL,
        account: AccountId(3),
        rights: Rights {
            borrow: true,
            ..Rights::NONE
        },
    });
    t.ok(Command::Issue {
        id: 50,
        to: IssueTarget::User(AccountId(3)),
        amount: 177,
    });
    t.ok(Command::Submit {
        job: JobId(4),
        borrower: AccountId(3),
        pool: CREDIT_POOL,
        model: ModelId(1),
        outputs: [4, 12, 3],
        max_budget: 1_000,
        mandate: mandate(JobId(4), CREDIT_POOL, AccountId(3), 1_000),
    });
    // Enough for the work part (177), not for the recovery budget (17).
    let e = t.err(Command::Reserve { job: JobId(4) });
    assert!(matches!(e, DomainError::Ledger(_)));
    assert_eq!(t.bal(Account::User(3)), 177);
    assert_eq!(t.bal(Account::EscrowWork(4)), 0);
    t.finish();
}

#[test]
fn f02_redelivered_assignments_are_harmless() {
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    let place = Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    };
    t.ok(place.clone());
    t.err(place); // replayed from the outbox: rejected, no new attempt
    assert_eq!(t.attempt(J1), 1);
    // Placement timeout meanwhile: JOB-T06 goes back to `reserved`.
    t.ok(Command::Tick { dt: 61 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Reserved);
    t.err(Command::AttemptReady {
        job: J1,
        attempt: 1,
        restored: [0; 3],
    });
    t.finish();
}

#[test]
fn f03_work_after_revocation_rejected_prior_receipts_paid() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 3
        }),
        DomainError::StaleAttempt
    );
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 2 * 6);
    t.finish();
}

#[test]
fn f04_duplicate_report_after_settlement_pays_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    let before = t.bal(Account::PendingReward {
        job: 1,
        attempt: 1,
        slice: s.slice,
        lender: 10,
    });
    t.err(Command::Evaluate { slice: s });
    t.err(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Committed,
        }],
    });
    // The lender resends its report on the next slice: the contribution is already taken.
    let s2 = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices()[&s2].rejected_items, 1);
    assert_eq!(
        t.bal(Account::PendingReward {
            job: 1,
            attempt: 1,
            slice: s.slice,
            lender: 10
        }),
        before
    );
    t.finish();
}

#[test]
fn f05_returning_node_is_ignored_but_keeps_prior_pay() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 2); // attempt 2
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2
        }),
        DomainError::StaleAttempt
    );
    assert_eq!(
        t.err(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1
        }),
        DomainError::StaleAttempt
    );
    t.claim_all(s1, Evidence::Committed);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[2]).paid, 2);
    t.finish();
}

#[test]
fn f06_duplicate_ack_charges_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    t.ok(Command::Ack {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    assert_eq!(
        t.ok(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2
        }),
        Outcome::AlreadyApplied
    );
    assert_eq!(
        t.ok(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1
        }),
        Outcome::AlreadyApplied
    );
    assert_eq!(t.bal(Account::OutputHold(1)), 24);
    t.finish();
}

#[test]
fn f07_client_disconnect_stops_after_k_then_pauses() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 6,
    }); // K = 4
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 7
        }),
        DomainError::FlowBudgetExceeded
    );
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Paused);
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    assert_eq!(
        t.job(J1).validated[GEN.idx()],
        2,
        "unacknowledged window never charged"
    );
    // Resume: generation restarts at the last validated position.
    t.ok(Command::Resume { job: J1, topup: 0 });
    t.start(J1, 3);
    assert_eq!(t.job(J1).current().unwrap().produced[GEN.idx()], 2);
    t.finish();
}

#[test]
fn f08_lost_contact_revocation_stops_payment() {
    // Contact lost: modeled by revocation (JOB-T08); see JOB-F29 for real lease expiry. Nothing
    // after revocation is paid.
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    t.commit_all(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.err(Command::Ack {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    assert!(!t.c().delivery().outputs().contains_key(&OutputId {
        job: J1,
        wt: GEN,
        pos: 1
    }));
    t.finish();
}

#[test]
fn f09_cancel_and_finish_race() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    let v = Some(t.job(J1).version);
    t.ok(Command::Finish {
        job: J1,
        expected_version: v,
    });
    assert!(matches!(
        t.err(Command::Cancel {
            job: J1,
            expected_version: v
        }),
        DomainError::VersionConflict { .. }
    ));
    // Re-reading the version: cancel is refused while `settling`.
    let v2 = Some(t.job(J1).version);
    assert_eq!(
        t.err(Command::Cancel {
            job: J1,
            expected_version: v2
        }),
        DomainError::JobSettling
    );
    assert_eq!(t.err(Command::Fail { job: J1 }), DomainError::JobSettling);
    t.finish();
}

#[test]
fn f10_low_escrow_blocks_window_then_pause_and_topup() {
    let mut t = T::with(Config {
        initial_reserve_max: 26,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 2); // 24 charged, 2 left
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 3
        }),
        DomainError::WindowNotCovered
    );
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::LowEscrow,
        expected_version: None,
    });
    // 2 credits cover no remaining output (the cheapest costs 3).
    t.err(Command::Resume { job: J1, topup: 0 });
    t.ok(Command::Resume { job: J1, topup: 60 });
    t.start(J1, 2);
    t.gen(J1, 3);
    t.finish();
}

#[test]
fn f11_identical_reports_counted_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![item],
    });
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![item],
    });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 6);
    assert_eq!(t.c().slices()[&s].rejected_items, 1);
    t.finish();
}

#[test]
fn f12_oversized_frame_rejected_before_decoding() {
    use gpu_protocol::*;
    assert_eq!(
        check_frame(MessageKind::TokenAck, 10_000),
        Err(ProtoError::FrameTooLarge)
    );
    assert_eq!(ProtoError::FrameTooLarge.code(), "FRAME_TOO_LARGE");
}

#[test]
fn f13_scheduler_restart_replays_nothing() {
    // The scheduler has no state of its own: replaying its decisions does nothing.
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    let place = Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    };
    t.ok(place.clone());
    let snapshot = t.c().clone();
    t.err(place);
    assert_eq!(&snapshot, t.c());
    t.finish();
}

#[test]
fn f14_preemption_settles_slice_then_resumes() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Preempted,
        expected_version: None,
    });
    assert_eq!(t.c().slices()[&s].status, SliceStatus::Draining);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[1]).paid, 2 * 4);
    t.ok(Command::Resume { job: J1, topup: 0 });
    t.start(J1, 3);
    t.gen(J1, 1);
    t.finish();
}
