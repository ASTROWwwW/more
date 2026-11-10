//! Checks asked before validating the change: a corroboration covers what was restored and
//! nothing else, proofs and payments are final and contests bounded, and a fault anywhere in a
//! reconciliation that settles several jobs leaves nothing half applied.

use super::*;

const L: [AccountId; 3] = [LENDERS[0], LENDERS[1], LENDERS[2]];

#[track_caller]
fn clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

fn place(sim: &mut Sim, job: JobId, lenders: &[AccountId], estimate: Amount) {
    sim.exec(Command::Place {
        job,
        lenders: lenders.to_vec(),
        layout: layout_of(job),
        recovery_estimate: estimate,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
}

/// Job 1 on its second attempt (earmark 6), every lender ready, nothing corroborated.
fn resumed() -> Sim {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    place(&mut sim, J1, &L, 0);
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    sim.exec(Command::NodeLost {
        job: J1,
        expected_version: None,
    })
    .unwrap();
    place(&mut sim, J1, &L, 6);
    for cmd in bring_up(J1, 2, &L, [0; 3]) {
        sim.exec(cmd).unwrap();
    }
    sim
}

const SLICE: SliceId = SliceId {
    job: J1,
    attempt: 2,
    slice: 1,
};

fn recovery(segment: u32, amount: Amount) -> ClaimItem {
    ClaimItem::Recovery {
        segment,
        amount,
        evidence: Evidence::Committed,
    }
}

fn corroboration(lender: AccountId, segments: &[u32], signature: [u8; 64]) -> Command {
    Command::CorroborateRestore {
        job: J1,
        attempt: 2,
        lender,
        segments: segments.to_vec(),
        signature,
    }
}

/// Verification 1. The recipient signs the restoration itself: job, attempt, lender, layer
/// range, positions, the lender's state commitment and each segment with its own commitment.
/// Any other content is refused; the corroboration pays the segments it names and no other; it
/// is written once.
#[test]
fn r2_a_corroboration_covers_what_was_restored_and_nothing_else() {
    let mut sim = resumed();
    let attempt = sim.coord.jobs()[&J1].attempts[&2].clone();
    let said = restoration_of(J1, &attempt, L[0], &[0]).unwrap();
    assert_eq!(said.layers, (0, 3), "stage 0 of job 1 holds layers 0..3");
    // L1 is L0's recipient. It signs a restoration that is not the one L0 committed to.
    let sign = |r: &more_identity::Restoration| {
        user_key(L[1]).sign(&more_identity::restore_message(&sim_domain(), r))
    };
    for altered in [
        more_identity::Restoration {
            state: said.state ^ 1,
            ..said.clone()
        },
        more_identity::Restoration {
            layers: (0, 6),
            ..said.clone()
        },
        more_identity::Restoration {
            restored: [0, 1, 0],
            ..said.clone()
        },
        more_identity::Restoration {
            attempt: 1,
            ..said.clone()
        },
        more_identity::Restoration {
            producer: L[2].0,
            ..said.clone()
        },
        // Every segment, another segment, or another content for the same segment.
        restoration_of(J1, &attempt, L[0], &all_segments()).unwrap(),
        restoration_of(J1, &attempt, L[0], &[1]).unwrap(),
        more_identity::Restoration {
            segments: vec![(0, said.segments[0].1 ^ 1)],
            ..said.clone()
        },
    ] {
        assert_eq!(
            sim.exec(corroboration(L[0], &[0], sign(&altered))),
            Err(DomainError::InadmissibleProof),
            "{altered:?}"
        );
    }
    // The true one: one segment received.
    sim.exec(corroboration(L[0], &[0], sign(&said))).unwrap();
    // Final: the same again changes nothing, a wider one is refused.
    assert_eq!(
        sim.exec(corroboration(L[0], &[0], UNSIGNED)),
        Ok(Outcome::AlreadyApplied)
    );
    assert!(matches!(
        sim.exec(corroboration(L[0], &all_segments(), UNSIGNED)),
        Err(DomainError::Precondition(_))
    ));
    // L0 claims two segments; L2, whose restoration nobody attested, claims one.
    sim.exec(Command::Claim {
        slice: SLICE,
        lender: L[0],
        items: vec![recovery(0, 2), recovery(1, 2)],
    })
    .unwrap();
    sim.exec(Command::Claim {
        slice: SLICE,
        lender: L[2],
        items: vec![recovery(2, 2)],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    let lines = &sim.coord.slices()[&SLICE].lines;
    assert_eq!((lines[&L[0]].paid, lines[&L[0]].disputed), (2, 2));
    assert_eq!((lines[&L[2]].paid, lines[&L[2]].disputed), (0, 2));
    // A ruling cannot stretch the corroboration to the segment it does not name.
    let ruling = Command::Arbitrate {
        slice: SLICE,
        lender: L[0],
        pay: true,
    };
    assert_eq!(sim.exec(ruling), Err(DomainError::InadmissibleProof));
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 2);
    assert_eq!(sim.balance(Account::User(L[2].0)), 0);
}

/// Verification 2. A payment follows a bounded cycle: contestable from the payment until the
/// ledger's limit even if the slice never becomes final, releasable only after the window, and
/// final once released or contested.
#[test]
fn r2_a_payment_is_contestable_for_a_bounded_time_then_final() {
    let mut sim = resumed();
    sim.exec(corroborate(J1, 2, &L[..1]).remove(0)).unwrap();
    // L0's recovery is corroborated and will be paid; L2's is not and keeps the slice disputed.
    for (l, segment) in [(L[0], 0), (L[2], 1)] {
        sim.exec(Command::Claim {
            slice: SLICE,
            lender: l,
            items: vec![recovery(segment, 3)],
        })
        .unwrap();
    }
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    assert_eq!(sim.coord.slices()[&SLICE].status, SliceStatus::Disputed);
    let release = Command::ReleaseReward {
        slice: SLICE,
        lender: L[0],
    };
    let contest = Command::ContestReward {
        slice: SLICE,
        lender: L[0],
    };
    // Not releasable while the borrower can still contest.
    assert!(matches!(
        sim.exec(release.clone()),
        Err(DomainError::Precondition(_))
    ));
    // Inside the limit the borrower's contest works (tried on a copy).
    assert_eq!(sim.try_on_copy(&contest), Ok(Outcome::Applied));
    // Nobody reconciles for more than the ledger's limit: the slice is still not final, and the
    // payment can no longer be contested.
    let limit = sim
        .coord
        .ledger_service()
        .expect("ledger in this process")
        .limits()
        .contest_limit;
    sim.exec(Command::Tick { dt: limit }).unwrap();
    assert_eq!(
        sim.exec(contest.clone()),
        Err(DomainError::Precondition("JOB-R22: contest limit reached"))
    );
    // Reconciliation rules on the disputed line, the slice becomes final, and after the window
    // the reward is released. Then nothing can reopen it.
    sim.exec(Command::Reconcile).unwrap();
    assert_eq!(sim.coord.slices()[&SLICE].status, SliceStatus::Final);
    let window = sim.coord.config().reward_window;
    sim.exec(Command::Tick { dt: window }).unwrap();
    sim.exec(release.clone()).unwrap();
    assert!(sim.exec(contest).is_err());
    assert!(sim.exec(release).is_err());
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 3);
}

/// Third review: the corroboration names segments 0 and 2. Segment 1, between them, is not
/// covered: it is held, and neither evaluation nor a ruling pays it.
#[test]
fn r3_a_segment_the_recipient_did_not_name_is_not_paid() {
    let mut sim = resumed();
    // Out of order, twice the same or none at all: not a list of segments.
    for bad in [&[2, 0][..], &[1, 1], &[]] {
        assert!(
            matches!(
                sim.exec(corroboration(L[0], bad, UNSIGNED)),
                Err(DomainError::InvalidInput(_))
            ),
            "{bad:?}"
        );
    }
    // A segment the lender never committed to cannot be attested.
    assert_eq!(
        sim.exec(corroboration(L[0], &[0, SEGMENTS], UNSIGNED)),
        Err(DomainError::InadmissibleProof)
    );
    sim.exec(corroboration(L[0], &[0, 2], UNSIGNED)).unwrap();
    sim.exec(Command::Claim {
        slice: SLICE,
        lender: L[0],
        items: vec![recovery(0, 2), recovery(1, 2), recovery(2, 2)],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    let l = sim.coord.slices()[&SLICE].lines[&L[0]].clone();
    assert_eq!((l.paid, l.disputed), (4, 2));
    let ruling = Command::Arbitrate {
        slice: SLICE,
        lender: L[0],
        pay: true,
    };
    assert_eq!(sim.exec(ruling), Err(DomainError::InadmissibleProof));
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 4);
}

/// Two jobs with everything due at once: an evaluation that pays recovery from the borrower's
/// budget and the pool's relay, five reward releases, and two settlements, one of which returns
/// credits to the pool. Ready for one reconciliation.
fn two_jobs_due() -> Sim {
    let mut sim = Sim::default();
    let run = |sim: &mut Sim, cmd: Command| {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    };
    let work = |sim: &mut Sim, job: JobId, lenders: &[AccountId], upto: u32| {
        let slice = SliceId {
            job,
            attempt: 1,
            slice: 1,
        };
        let mut cmds = vec![
            Command::Produce {
                job,
                attempt: 1,
                wt: GEN,
                upto,
            },
            Command::Ack {
                job,
                attempt: 1,
                wt: GEN,
                upto,
            },
        ];
        for (stage, l) in lenders.iter().enumerate() {
            cmds.push(Command::CommitReceipts {
                job,
                attempt: 1,
                lender: *l,
                wt: GEN,
                upto,
                digest: sim.coord.receipt_digest(job, 1, *l, GEN, upto),
                signature: UNSIGNED,
            });
            cmds.push(Command::Claim {
                slice,
                lender: *l,
                items: (0..upto)
                    .map(|pos| ClaimItem::Contribution {
                        output: OutputId { job, wt: GEN, pos },
                        stage: stage as u32,
                        evidence: Evidence::Committed,
                    })
                    .collect(),
            });
        }
        cmds.push(Command::CloseSlice { slice });
        cmds.push(Command::Evaluate { slice });
        for cmd in cmds {
            sim.exec(cmd.clone())
                .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
        }
    };
    // Job 1: two outputs paid to three lenders, rewards held.
    run(&mut sim, Command::Reserve { job: J1 });
    place(&mut sim, J1, &L, 0);
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    work(&mut sim, J1, &L, 2);
    // Job 2: one output paid to two lenders, then a node is lost.
    run(&mut sim, Command::Reserve { job: J2 });
    place(&mut sim, J2, &L[..2], 0);
    sim.start_cluster(J2, 1, [0; 3]).unwrap();
    work(&mut sim, J2, &L[..2], 1);
    run(
        &mut sim,
        Command::NodeLost {
            job: J2,
            expected_version: None,
        },
    );
    // The pool relays 10 credits; the resumed attempt earmarks 12 (6 from the borrower's budget).
    run(
        &mut sim,
        Command::FundRecovery {
            job: J2,
            amount: 10,
            signature: UNSIGNED,
        },
    );
    place(&mut sim, J2, &L[..2], 12);
    sim.start_cluster(J2, 2, [0, 1, 0]).unwrap();
    let resumed = SliceId {
        job: J2,
        attempt: 2,
        slice: 1,
    };
    run(
        &mut sim,
        Command::Claim {
            slice: resumed,
            lender: L[0],
            items: vec![recovery(0, 12)],
        },
    );
    run(&mut sim, Command::CloseSlice { slice: resumed });
    // Both borrowers cancel; the last slices drain and close.
    for job in [J1, J2] {
        run(
            &mut sim,
            Command::Cancel {
                job,
                expected_version: None,
            },
        );
    }
    let drain = sim.coord.config().drain_window;
    run(&mut sim, Command::Tick { dt: drain });
    run(&mut sim, Command::Reconcile);
    // Two days later everything is due.
    run(&mut sim, Command::Tick { dt: 49 * 3600 });
    clean(&sim);
    sim
}

fn balances(c: &Coordinator, auditor: &ServiceCredential) -> Vec<(Account, i128)> {
    let ledger = c.audit_ledger(auditor).unwrap();
    ledger.accounts().map(|(a, b)| (*a, *b)).collect()
}

/// Verification 3 (CE-08 with several financial operations). The journal is made to fail at
/// every entry of that reconciliation in turn. Each time: the reconciliation reports the error,
/// not one entry of it remains (no payment, no release, no partial settlement, no credit moved
/// to or from the pool), and after a restart the same reconciliation completes with the result
/// of a run without fault.
#[test]
fn r2_a_fault_at_any_entry_of_a_multi_job_reconciliation_leaves_nothing_half_done() {
    let sim = two_jobs_due();
    let auditor = sim.ids.auditor.clone();
    let reconciler = sim.as_service(ServiceRole::Reconciler);
    let base = sim.coord.clone();
    let before = balances(&base, &auditor);
    let journal = |c: &Coordinator| c.audit_ledger(&auditor).unwrap().entries().len();

    // Reference: no fault.
    let mut reference = base.clone();
    reference.execute(&reconciler, &Command::Reconcile).unwrap();
    let expected = balances(&reference, &auditor);
    let written = journal(&reference) - journal(&base);
    // It really is a multi-job financial reconciliation.
    let reasons: Vec<&str> = reference.audit_ledger(&auditor).unwrap().entries()[journal(&base)..]
        .iter()
        .map(|e| e.reason)
        .collect();
    for needed in [
        "JOB-S04 held payment",
        "JOB-R22 release",
        "JOB-S12 return to pool",
        "JOB-S12 return",
    ] {
        assert!(
            reasons.contains(&needed),
            "{needed} missing from {reasons:?}"
        );
    }
    for job in [J1, J2] {
        assert_eq!(reference.jobs()[&job].settle, SettleStatus::Closed);
    }
    assert!(written >= 12, "only {written} entries");

    for k in 0..written as u64 {
        let mut c = base.clone();
        c.inject_ledger_fault(Some(k));
        let faulty = c.clone();
        let r = c.execute(&reconciler, &Command::Reconcile);
        assert!(
            matches!(r, Err(DomainError::Internal(_))),
            "fault at entry {k}: {r:?}"
        );
        // Nothing of the reconciliation remains: same state, same journal, same balances.
        assert!(c == faulty, "fault at entry {k} left a trace in the state");
        assert_eq!(journal(&c), journal(&base), "fault at entry {k}");
        assert_eq!(balances(&c, &auditor), before, "fault at entry {k}");
        for job in [J1, J2] {
            assert_eq!(
                c.jobs()[&job].settle,
                SettleStatus::Finalizing,
                "fault at entry {k}"
            );
        }
        // Restart on the same state, without the fault.
        c.inject_ledger_fault(None);
        c.execute(&reconciler, &Command::Reconcile).unwrap();
        assert_eq!(
            balances(&c, &auditor),
            expected,
            "after restart, fault at entry {k}"
        );
        assert!(c == reference, "after restart, fault at entry {k}");
    }
    // One entry later there is no fault left to hit.
    let mut c = base.clone();
    c.inject_ledger_fault(Some(written as u64));
    c.execute(&reconciler, &Command::Reconcile).unwrap();
    assert_eq!(balances(&c, &auditor), expected);

    // And the whole run, checked command by command, ends clean.
    let mut sim = sim;
    sim.exec(Command::Reconcile).unwrap();
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::PoolReserve(CREDIT_POOL.0)), 300 - 6);
}

/// LEDGER-018, LEDGER-019: a coordinator does not start on limits that could strand a payment
/// (contest limit before the hold), nor on the ledger of another deployment.
#[test]
fn r3_a_coordinator_refuses_a_ledger_it_cannot_rely_on() {
    use gpu_ledger::{LedgerLimits, LedgerService};
    use more_identity::{IdentityAuthority, KeyDirectory, ServiceRole};
    let mut auth = IdentityAuthority::new([5; 32]);
    let cred = auth.issue(ServiceRole::Orchestrator);
    let start = |ledger: LedgerService| {
        Coordinator::new(sim_config(), ledger, cred.clone(), auth.verifier()).map(|_| ())
    };
    let ledger = |limits| LedgerService::new(auth.verifier(), KeyDirectory::new(), limits);
    let hold = LedgerLimits::default().reward_hold;
    let stuck = LedgerLimits {
        contest_limit: hold - 1,
        ..LedgerLimits::default()
    };
    assert_eq!(
        start(ledger(stuck)),
        Err(DomainError::InvalidInput(
            "contest limit shorter than the reward hold"
        ))
    );
    let edge = LedgerLimits {
        contest_limit: hold,
        ..LedgerLimits::default()
    };
    assert_eq!(start(ledger(edge)), Ok(()));
    let elsewhere = IdentityAuthority::new([6; 32]).verifier();
    let foreign = LedgerService::new(elsewhere, KeyDirectory::new(), LedgerLimits::default());
    assert_eq!(
        start(foreign),
        Err(DomainError::InvalidInput(
            "ledger and coordinator of different deployments"
        ))
    );
    assert_eq!(start(ledger(LedgerLimits::default())), Ok(()));
}
