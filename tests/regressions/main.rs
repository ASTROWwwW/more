//! Regression tests: each counterexample found by proptest is kept here in reduced, readable form,
//! with the spec rule it fixed. Never delete these. Raw seeds are also kept in
//! `tests/properties/proptest-regressions.txt`.

use gpu_domain::*;
use gpu_simulation::*;

fn run(ops: &[Op]) -> Sim {
    let mut sim = Sim::default();
    for op in ops {
        sim.run_op(op);
    }
    sim.drain();
    sim
}

#[track_caller]
fn assert_clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-01, found by `invariants_hold_under_heavy_faults` (TEST-P13), reduced to `[Fund { job: 132,
/// amount: 0 }]`. The pool funded recovery for a job still `queued`; rejecting the job left those
/// credits with no owner. Fix (JOB-R18): the pool relay requires `settlement_status = active`.
#[test]
fn ce01_pool_cannot_fund_a_job_without_active_escrow() {
    let sim = run(&[Op::Fund {
        job: 132,
        amount: 0,
    }]);
    assert_clean(&sim);

    let mut sim = Sim::default();
    let r = sim.exec(Command::FundRecovery {
        job: JobId(1),
        amount: 1,
    });
    assert_eq!(
        r,
        Err(DomainError::Precondition("JOB-R18: settlement not active"))
    );
    sim.exec(Command::Reserve { job: JobId(1) }).unwrap();
    sim.exec(Command::FundRecovery {
        job: JobId(1),
        amount: 1,
    })
    .unwrap();
    sim.exec(Command::Cancel {
        job: JobId(1),
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::Settle { job: JobId(1) }).unwrap();
    assert_clean(&sim);
    assert_eq!(sim.balance(Account::EscrowRecovery(1)), 0);
    // (Before CE-02, this pool credit went to the borrower.)
    assert_eq!(
        sim.balance(Account::PoolReserve(1)),
        300,
        "unused pool relay returns to the pool"
    );
}

/// CE-02, found while writing CE-01. Settlement returned all unused recovery budget to the
/// borrower, including the pool's share. Fix: borrower budget first, then pool relay; on close or
/// contest each payer gets its own share back (TEST-P17).
#[test]
fn ce02_pool_relay_never_benefits_the_borrower() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let lenders = vec![AccountId(10), AccountId(11), AccountId(12)];
    let ready = |sim: &mut Sim| {
        let (a, v) = (sim.coord.jobs[&j1].attempt, sim.coord.jobs[&j1].validated);
        sim.exec(Command::AttemptReady {
            job: j1,
            attempt: a,
            restored: v,
        })
        .unwrap();
    };
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: lenders.clone(),
        layout: layout_of(j1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    ready(&mut sim);
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::NodeLost {
        job: j1,
        expected_version: None,
    })
    .unwrap();
    // Borrower budget = 17. The pool adds 10. Resume estimated at 20: 17 + 3 from the pool.
    sim.exec(Command::FundRecovery {
        job: j1,
        amount: 10,
    })
    .unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: lenders.clone(),
        layout: layout_of(j1),
        recovery_estimate: 20,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    ready(&mut sim);
    let s = *sim.coord.slices.keys().rfind(|s| s.attempt == 2).unwrap();
    sim.exec(Command::Claim {
        slice: s,
        lender: lenders[0],
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: 20,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    assert_eq!(
        (
            sim.coord.jobs[&j1].recovery_paid_borrower,
            sim.coord.jobs[&j1].recovery_paid_pool
        ),
        (17, 3)
    );
    // Fraud: the recovery is contested. The pool gets its 3 back, the borrower its 17.
    let pool_before = sim.balance(Account::PoolReserve(1));
    sim.exec(Command::ContestReward {
        slice: s,
        lender: lenders[0],
    })
    .unwrap();
    assert_eq!(sim.balance(Account::PoolReserve(1)), pool_before + 3);
    sim.drain();
    assert_clean(&sim);
    // The pool got its 10 back (7 unused + 3 contested).
    assert_eq!(sim.balance(Account::PoolReserve(1)), 300);
}

/// CE-03, found by `invariants_hold_under_heavy_faults` (TEST-P08) once the checker stopped relying
/// on the domain. Reduced to 8 operations: a commitment recorded after the slice closed was
/// accepted as proof. Fix (JOB-R12, JOB-R15): order is judged by the coordinator log, before the
/// earlier of revocation and closure.
#[test]
fn ce03_commitment_after_slice_closure_proves_nothing() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let l = AccountId(10);
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: vec![l, AccountId(11), AccountId(12)],
        layout: layout_of(j1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::AttemptReady {
        job: j1,
        attempt: 1,
        restored: [0; 3],
    })
    .unwrap();
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    let s = SliceId {
        job: j1,
        attempt: 1,
        slice: 1,
    };
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: j1,
            wt: WorkType::Generate,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: l,
        items: vec![item],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    // Commitment AFTER closure, then revocation in the same second.
    sim.exec(Command::CommitReceipts {
        job: j1,
        attempt: 1,
        lender: l,
        wt: WorkType::Generate,
        upto: 1,
        digest: sim.coord.receipt_digest(j1, 1, l, WorkType::Generate, 1),
    })
    .unwrap();
    sim.exec(Command::Cancel {
        job: j1,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    let line = &sim.coord.slices[&s].lines[&l];
    assert_eq!(
        (line.paid, line.pending),
        (0, 6),
        "a commitment recorded after closure is not proof: never paid"
    );
    // JOB-R35: the refund for missing proof only becomes final at the evaluation deadline.
    sim.exec(Command::Tick { dt: 600 }).unwrap();
    sim.exec(Command::Reconcile).unwrap();
    let line = &sim.coord.slices[&s].lines[&l];
    assert_eq!(
        (line.paid, line.refunded),
        (0, 6),
        "a commitment recorded after closure is not proof"
    );
    sim.drain();
    assert_clean(&sim);
}

/// CE-03, mirror case: a commitment recorded BEFORE closure is still proof.
#[test]
fn ce03_commitment_before_closure_still_counts() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let l = AccountId(10);
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: vec![l, AccountId(11), AccountId(12)],
        layout: layout_of(j1),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::AttemptReady {
        job: j1,
        attempt: 1,
        restored: [0; 3],
    })
    .unwrap();
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::CommitReceipts {
        job: j1,
        attempt: 1,
        lender: l,
        wt: WorkType::Generate,
        upto: 1,
        digest: sim.coord.receipt_digest(j1, 1, l, WorkType::Generate, 1),
    })
    .unwrap();
    let s = SliceId {
        job: j1,
        attempt: 1,
        slice: 1,
    };
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: j1,
            wt: WorkType::Generate,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: l,
        items: vec![item],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    assert_eq!(sim.coord.slices[&s].lines[&l].paid, 6);
    sim.drain();
    assert_clean(&sim);
}

/// CE-04, found by proptest (TEST-P06, delivery generator), reduced to 16 operations. The slice was
/// closed (contribution reserved, not evaluated) when the client reported an output as not received
/// and its buffer was lost; the output was voided and the contribution refunded. Evaluation then
/// tried to decide that item again, failed, the error was swallowed by reconciliation and the job
/// got stuck.
#[test]
fn ce04_voided_output_after_closure_does_not_block_evaluation() {
    let mut sim = Sim::default();
    let j = JobId(1);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11), AccountId(12)],
            layout: layout_of(j),
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 2,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::Deliver {
            job: j,
            attempt: 1,
            witness: WITNESS,
            wt: gen,
            upto: 2,
            digest: sim.coord.frame_digest(j, gen, 2),
        },
        Command::CommitReceipts {
            job: j,
            attempt: 1,
            lender: AccountId(10),
            wt: gen,
            upto: 2,
            digest: sim.coord.receipt_digest(j, 1, AccountId(10), gen, 2),
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(10),
        items: (0..2)
            .map(|pos| ClaimItem::Contribution {
                output: OutputId {
                    job: j,
                    wt: gen,
                    pos,
                },
                stage: 0,
                evidence: Evidence::Committed,
            })
            .collect(),
    })
    .unwrap();
    sim.exec(Command::WitnessLost { job: j, attempt: 1 })
        .unwrap();
    sim.exec(Command::NodeLost {
        job: j,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::Tick { dt: 121 }).unwrap();
    sim.exec(Command::Reconcile).unwrap(); // closure: both contributions reserved
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Closed);
    // The client never got position 1, and the witness can no longer replay it.
    sim.exec(Command::ConfirmDelivery {
        job: j,
        wt: gen,
        confirmed: 1,
        digest: sim.coord.frame_digest(j, gen, 1),
    })
    .unwrap();
    assert!(!sim.coord.outputs.contains_key(&OutputId {
        job: j,
        wt: gen,
        pos: 1
    }));
    sim.exec(Command::Tick { dt: 601 }).unwrap();
    sim.exec(Command::Reconcile).unwrap(); // evaluation must not fail anymore
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Final);
    let line = &sim.coord.slices[&s].lines[&AccountId(10)];
    assert_eq!((line.paid, line.refunded), (6, 6));
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-05, found by proptest (TEST-P23) in all four generators. In a free pool a paid contribution
/// is worth 0, so nothing is held or released and the item stayed "neither released nor contested"
/// forever. A zero reward is complete once paid.
#[test]
fn ce05_zero_reward_in_free_pool_completes_at_payment() {
    let mut sim = Sim::default();
    let j = JobId(3);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11)],
            layout: layout_of(j),
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::CommitReceipts {
            job: j,
            attempt: 1,
            lender: AccountId(11),
            wt: gen,
            upto: 1,
            digest: sim.coord.receipt_digest(j, 1, AccountId(11), gen, 1),
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(11),
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j,
                wt: gen,
                pos: 0,
            },
            stage: 1,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    let it = &sim.coord.slices[&s].lines[&AccountId(11)].items[0];
    assert_eq!((it.status, it.amount), (ItemStatus::Paid, 0));
    assert!(it.reward_done, "a zero reward has nothing to hold");
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-06, found by proptest (TEST-P12). A slice finished evaluating before the deadline while a
/// contribution was still waiting for its output. When the output became definitive, the
/// contribution had no proof and went back to pending inside an already evaluated slice. Fix:
/// before the deadline, a slice does not finish while a contribution waits for its output.
#[test]
fn ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open() {
    let mut sim = Sim::default();
    let j = JobId(1);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11), AccountId(12)],
            layout: layout_of(j),
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 2,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let digest = sim.coord.frame_digest(j, gen, 2);
    sim.exec(Command::Deliver {
        job: j,
        attempt: 1,
        witness: WITNESS,
        wt: gen,
        upto: 2,
        digest,
    })
    .unwrap();
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(10),
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j,
                wt: gen,
                pos: 1,
            },
            stage: 0,
            evidence: Evidence::None,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap(); // provisional output: pending
    assert_eq!(
        sim.coord.slices[&s].status,
        SliceStatus::Closed,
        "not finished before deadline"
    );
    // The client signs: the output becomes definitive before the deadline.
    sim.exec(Command::Ack {
        job: j,
        attempt: 1,
        wt: gen,
        upto: 2,
    })
    .unwrap();
    let line = &sim.coord.slices[&s].lines[&AccountId(10)];
    assert_eq!(
        line.pending, 6,
        "back to pending evaluation, slice still open"
    );
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
    sim.exec(Command::Tick { dt: 600 }).unwrap();
    sim.exec(Command::Reconcile).unwrap();
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Final);
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-07, found by `invariants_hold_under_delivery_adversaries` once impersonation entered the
/// generator (seed `59d2ec9c…`): a `Reconcile` sent by the auditor was refused, as it should, but
/// the checker still ran its post-reconciliation checks (TEST-P24, P27) on the unchanged state.
/// Two fixes: those checks only follow a reconciliation that ran, and only the reconciler may
/// reconcile. A scheduler running it would be refused some due transitions (silent client pause,
/// default rulings, releases) and leave them due; inside reconciliation such a refusal is now an
/// internal error instead of being skipped.
#[test]
fn ce07_only_the_reconciler_reconciles() {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: JobId(1) }).unwrap();
    for role in [ServiceRole::Scheduler, ServiceRole::Auditor, ServiceRole::Clock] {
        let ctx = sim.as_service(role);
        let before = sim.coord.clone();
        assert!(matches!(
            sim.exec_as(&ctx, Command::Reconcile),
            Err(DomainError::Unauthorized(_))
        ));
        assert_eq!(before, sim.coord);
    }
    let ctx = sim.as_service(ServiceRole::Reconciler);
    assert!(sim.exec_as(&ctx, Command::Reconcile).is_ok());
    assert_clean(&sim);
}
