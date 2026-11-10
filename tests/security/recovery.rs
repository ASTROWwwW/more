//! JOB-R18 after the second audit: recovery is reserved before the work, attested by the lender
//! and by its recipient, and settled only on that. Plus what was asked before the merge: a
//! colluding lender, an honest restoration cut short, a ready lease next to an expired one, a
//! replayed receipt, and a fault in the middle of a settlement followed by a restart.

use super::*;

const L: [AccountId; 3] = [LENDERS[0], LENDERS[1], LENDERS[2]];
const EARMARK: Amount = 5;

#[track_caller]
fn clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

fn place(sim: &mut Sim, estimate: Amount) {
    sim.exec(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: estimate,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
}

/// Job 1 lost its first cluster and is placed again (attempt 2) with a recovery earmark; every
/// lender of the new cluster reports ready. Nobody has corroborated anything yet.
fn resumed() -> Sim {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    place(&mut sim, 0);
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    sim.exec(Command::NodeLost {
        job: J1,
        expected_version: None,
    })
    .unwrap();
    place(&mut sim, EARMARK);
    for cmd in bring_up(J1, 2, &L, [0; 3]) {
        sim.exec(cmd).unwrap();
    }
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Running);
    sim
}

const SLICE: SliceId = SliceId {
    job: J1,
    attempt: 2,
    slice: 1,
};

fn claim_recovery(sim: &mut Sim, lender: AccountId) {
    sim.exec(Command::Claim {
        slice: SLICE,
        lender,
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: EARMARK,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
}

fn line(sim: &Sim, lender: AccountId) -> Line {
    sim.coord.slices()[&SLICE].lines[&lender].clone()
}

/// A compromised orchestrator placed an accomplice (lender 0) in the cluster. It signs ready
/// without restoring anything; its recipient, honest, received nothing and attests nothing.
/// The claim is reserved, held, and finally refunded: never paid, by evaluation or by ruling.
#[test]
fn r2_an_accomplice_cannot_collect_recovery_without_corroboration() {
    let mut sim = resumed();
    let accomplice = L[0];
    claim_recovery(&mut sim, accomplice);
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    // 1. Reserved before anything is settled, within the earmark.
    assert_eq!(line(&sim, accomplice).pending, EARMARK);
    // 2. Nobody but the stage's recipient can corroborate: not the accomplice, not a service.
    let said = restoration_of(
        J1,
        &sim.coord.jobs()[&J1].attempts[&2],
        accomplice,
        &all_segments(),
    )
    .expect("the accomplice reported ready");
    let vouch = Command::CorroborateRestore {
        job: J1,
        attempt: 2,
        lender: accomplice,
        segments: all_segments(),
        signature: user_key(accomplice).sign(&more_identity::restore_message(&sim_domain(), &said)),
    };
    for ctx in [
        more_identity::assume_account(accomplice.0),
        more_identity::assume_account(L[2].0),
        sim.as_service(ServiceRole::Scheduler),
        sim.as_service(ServiceRole::Reconciler),
    ] {
        assert!(matches!(
            sim.exec_as(&ctx, vouch.clone()),
            Err(DomainError::Unauthorized(_))
        ));
    }
    // The recipient's envelope carrying the accomplice's signature: the ledger refuses it.
    let recipient = more_identity::assume_account(L[1].0);
    assert_eq!(
        sim.exec_as(&recipient, vouch),
        Err(DomainError::InadmissibleProof)
    );
    // 3. At the evaluation deadline the amount is held, not paid and not yet refunded.
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    let l = line(&sim, accomplice);
    assert_eq!((l.paid, l.disputed, l.refunded), (0, EARMARK, 0));
    // A ruling cannot pay it either.
    let ruling = |pay| Command::Arbitrate {
        slice: SLICE,
        lender: accomplice,
        pay,
    };
    assert_eq!(sim.exec(ruling(true)), Err(DomainError::InadmissibleProof));
    // At the dispute deadline the default ruling refunds it.
    let dispute = sim.coord.config().dispute_deadline;
    sim.exec(Command::Tick { dt: dispute }).unwrap();
    sim.exec(Command::Reconcile).unwrap();
    let l = line(&sim, accomplice);
    assert_eq!((l.paid, l.disputed, l.refunded), (0, 0, EARMARK));
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(accomplice.0)), 0);
    assert_eq!(sim.balance(Account::User(BORROWERS[0].0)), 2_000);
}

/// A node really restored its state, its recipient attested it, and the cluster was lost before
/// any new output. The restoration is paid: no output is required, only the corroboration.
#[test]
fn r2_an_honest_restoration_is_paid_even_if_no_output_follows() {
    let mut sim = resumed();
    for cmd in corroborate(J1, 2, &L) {
        sim.exec(cmd).unwrap();
    }
    sim.exec(Command::NodeLost {
        job: J1,
        expected_version: None,
    })
    .unwrap();
    // The lender still presents its claim while its slice drains.
    claim_recovery(&mut sim, L[0]);
    let drain = sim.coord.config().drain_window;
    sim.exec(Command::Tick { dt: drain }).unwrap();
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    assert_eq!(line(&sim, L[0]).paid, EARMARK);
    let produced = sim
        .coord
        .audit_log()
        .iter()
        .any(|e| matches!(e, AuditEvent::Produced { attempt: 2, .. }));
    assert!(!produced, "no output was produced on the resumed attempt");
    sim.drain();
    clean(&sim);
    // 5 held, 10 % commission rounded down to 0.
    assert_eq!(sim.balance(Account::User(L[0].0)), EARMARK as i128);
}

/// Time passes on a healthy cluster: every node keeps renewing its own lease.
fn wait_alive(sim: &mut Sim, total: u64) {
    let step = sim.coord.config().lease_ttl - 1;
    let mut left = total;
    while left > 0 {
        let dt = left.min(step);
        sim.exec(Command::Tick { dt }).unwrap();
        for cmd in sim.renew_all(J1) {
            sim.exec(cmd).unwrap();
        }
        left -= dt;
    }
}

/// A corroboration that comes after the item was held, on an attempt that is still alive, lets
/// a ruling pay it; without one the same ruling is refused (see above). After the third review
/// the cluster has to be kept alive for this: a corroboration recorded after the revocation or
/// on an expired lease no longer counts (see the `r3_` tests below).
#[test]
fn r2_a_late_corroboration_lets_a_ruling_pay() {
    let mut sim = resumed();
    claim_recovery(&mut sim, L[0]);
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    wait_alive(&mut sim, deadline);
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    assert_eq!(line(&sim, L[0]).disputed, EARMARK);
    sim.exec(corroborate(J1, 2, &L[..1]).remove(0)).unwrap();
    sim.exec(Command::Arbitrate {
        slice: SLICE,
        lender: L[0],
        pay: true,
    })
    .unwrap();
    assert_eq!(line(&sim, L[0]).paid, EARMARK);
    sim.drain();
    clean(&sim);
}

/// One lender is ready and keeps renewing; two others never answer and their leases run out.
/// The ready lease does not carry the cluster: placement fails, nothing runs, nothing is paid.
#[test]
fn r2_a_ready_lease_does_not_outlive_another_nodes_expiry() {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    place(&mut sim, 0);
    for cmd in bring_up(J1, 1, &L[..1], [0; 3]) {
        sim.exec(cmd).unwrap();
    }
    let ttl = sim.coord.config().lease_ttl;
    let alive = [
        Command::Heartbeat {
            job: J1,
            attempt: 1,
            lender: L[0],
        },
        Command::WitnessHeartbeat {
            job: J1,
            attempt: 1,
            witness: WITNESS,
        },
    ];
    for dt in [ttl - 1, 1] {
        sim.exec(Command::Tick { dt }).unwrap();
        if dt > 1 {
            for cmd in &alive {
                sim.exec(cmd.clone()).unwrap();
            }
        }
    }
    let a = sim.coord.jobs()[&J1].attempts[&1].clone();
    assert_eq!(a.leases[0].state, LeaseState::Ready);
    assert!(
        a.leases[0].expires_at > sim.coord.now(),
        "its own lease is valid"
    );
    assert!(!a.ready, "the attempt never started");
    // The silent lenders cannot join any more, and the ready one cannot run alone.
    let late = Command::AcceptLease {
        job: J1,
        attempt: 1,
        lender: L[1],
        signature: UNSIGNED,
    };
    assert_eq!(sim.exec(late), Err(DomainError::LeaseExpired));
    let produce = Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 1,
    };
    assert_eq!(sim.exec(produce), Err(DomainError::StaleAttempt));
    // Nothing to corroborate for a lender that never reported ready.
    let vouch = corroborate(J1, 1, &L[1..2]).remove(0);
    assert!(matches!(sim.exec(vouch), Err(DomainError::Precondition(_))));
    sim.exec(Command::Reconcile).unwrap();
    let j = &sim.coord.jobs()[&J1];
    assert_eq!(j.exec, ExecStatus::Reserved, "JOB-T06");
    assert!(j.attempts[&1].revoked_at.is_some());
    let expired = sim.coord.audit_log().iter().find_map(|e| match e {
        AuditEvent::LeasesExpired { nodes, .. } => Some(nodes.clone()),
        _ => None,
    });
    assert_eq!(expired, Some(vec![L[1], L[2]]));
    assert!(
        sim.coord.slices().is_empty(),
        "no slice, so nothing to claim"
    );
    // The job is placed again on a new attempt.
    place(&mut sim, 0);
    sim.start_cluster(J1, 2, [0; 3]).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].exec, ExecStatus::Running);
    sim.drain();
    clean(&sim);
}

/// A valid receipt is presented twice and its contribution claimed twice: one payment. The same
/// receipt does not verify on another attempt.
#[test]
fn r2_a_replayed_receipt_pays_once() {
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    place(&mut sim, 0);
    sim.start_cluster(J1, 1, [0; 3]).unwrap();
    for cmd in [
        Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1,
        },
        Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1,
        },
    ] {
        sim.exec(cmd).unwrap();
    }
    let digest = sim.coord.receipt_digest(J1, 1, L[2], GEN, 1);
    let msg =
        more_identity::receipt_message(&sim_domain(), J1.0, 1, L[2].0, GEN.idx() as u8, 1, digest);
    let signature = user_key(WITNESS).sign(&msg);
    let present = |attempt| Command::PresentReceipt {
        job: J1,
        attempt,
        lender: L[2],
        wt: GEN,
        upto: 1,
        digest,
        signature,
    };
    assert_eq!(sim.exec(present(1)), Ok(Outcome::Applied));
    assert_eq!(sim.exec(present(1)), Ok(Outcome::AlreadyApplied));
    let slice = SliceId {
        job: J1,
        attempt: 1,
        slice: 1,
    };
    let claim = Command::Claim {
        slice,
        lender: L[2],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 2,
            evidence: Evidence::Uncommitted,
        }],
    };
    sim.exec(claim.clone()).unwrap();
    sim.exec(claim.clone()).unwrap();
    sim.exec(Command::CloseSlice { slice }).unwrap();
    sim.exec(Command::Evaluate { slice }).unwrap();
    let l = &sim.coord.slices()[&slice].lines[&L[2]];
    assert_eq!((l.items.len(), l.paid), (1, 2), "reserved and paid once");
    assert_eq!(sim.coord.slices()[&slice].rejected_items, 1);
    // Claimed again on the next slice of the same attempt: rejected at closure.
    let next = SliceId { slice: 2, ..slice };
    let Command::Claim { items, .. } = claim else {
        unreachable!()
    };
    sim.exec(Command::Claim {
        slice: next,
        lender: L[2],
        items,
    })
    .unwrap();
    // The same signed receipt on a new attempt of the same job.
    sim.exec(Command::NodeLost {
        job: J1,
        expected_version: None,
    })
    .unwrap();
    place(&mut sim, 0);
    sim.start_cluster(J1, 2, [0, 1, 0]).unwrap();
    assert_eq!(sim.exec(present(2)), Err(DomainError::InadmissibleProof));
    sim.drain();
    clean(&sim);
    assert_eq!(sim.coord.slices()[&next].rejected_items, 1);
    // One share of 2 credits, released whole (commission rounds down to 0).
    assert_eq!(sim.balance(Account::User(L[2].0)), 2);
}

/// The journal fails in the middle of a settlement: first while an evaluation pays several
/// lines, then while the job's escrow is returned. Each time the transition is refused and
/// leaves nothing behind; reconciliation reports the error instead of skipping the transition;
/// after a restart on the same state it completes, and the result is the one of a run without
/// any fault.
#[test]
fn r2_a_fault_during_a_partial_settlement_then_restart_and_reconciliation() {
    fn build() -> (Sim, SliceId) {
        let mut sim = Sim::default();
        sim.exec(Command::Reserve { job: J1 }).unwrap();
        place(&mut sim, 0);
        sim.start_cluster(J1, 1, [0; 3]).unwrap();
        let slice = SliceId {
            job: J1,
            attempt: 1,
            slice: 1,
        };
        let mut cmds = vec![
            Command::Produce {
                job: J1,
                attempt: 1,
                wt: GEN,
                upto: 2,
            },
            Command::Ack {
                job: J1,
                attempt: 1,
                wt: GEN,
                upto: 2,
            },
        ];
        for l in L {
            cmds.push(Command::CommitReceipts {
                job: J1,
                attempt: 1,
                lender: l,
                wt: GEN,
                upto: 2,
                digest: sim.coord.receipt_digest(J1, 1, l, GEN, 2),
                signature: UNSIGNED,
            });
        }
        for (stage, l) in L.iter().enumerate() {
            cmds.push(Command::Claim {
                slice,
                lender: *l,
                items: (0..2)
                    .map(|pos| ClaimItem::Contribution {
                        output: OutputId {
                            job: J1,
                            wt: GEN,
                            pos,
                        },
                        stage: stage as u32,
                        evidence: Evidence::Committed,
                    })
                    .collect(),
            });
        }
        for cmd in cmds {
            sim.exec(cmd.clone())
                .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
        }
        (sim, slice)
    }
    // Reference: the same job with no fault.
    let (mut reference, _) = build();
    reference.drain();
    clean(&reference);

    let (mut sim, slice) = build();
    let scheduler = sim.as_service(ServiceRole::Scheduler);
    let reconciler = sim.as_service(ServiceRole::Reconciler);
    let clock = sim.as_service(ServiceRole::Clock);
    let run = |sim: &mut Sim, ctx: &AuthContext, cmd: Command| sim.coord.execute(ctx, &cmd);
    run(&mut sim, &scheduler, Command::CloseSlice { slice }).unwrap();

    // Fault 1: the evaluation pays six items; the journal fails after the first two entries.
    sim.coord.inject_ledger_fault(Some(2));
    let before = sim.coord.clone();
    let r = run(&mut sim, &scheduler, Command::Evaluate { slice });
    assert!(matches!(r, Err(DomainError::Ledger(_))), "{r:?}");
    assert!(sim.coord == before, "a half-paid evaluation left a trace");
    assert_eq!(sim.coord.slices()[&slice].status, SliceStatus::Closed);
    // Reconciliation meets the same fault once the evaluation is due, and reports it instead of
    // skipping the transition (CE-04).
    let deadline = sim.coord.config().evaluation_deadline;
    run(&mut sim, &clock, Command::Tick { dt: deadline }).unwrap();
    let before = sim.coord.clone();
    let r = run(&mut sim, &reconciler, Command::Reconcile);
    assert!(matches!(r, Err(DomainError::Internal(_))), "{r:?}");
    assert!(sim.coord == before);
    // Restart: same durable state, the fault is gone. Reconciliation finishes the evaluation.
    sim.coord.inject_ledger_fault(None);
    run(&mut sim, &reconciler, Command::Reconcile).unwrap();
    assert_eq!(sim.coord.slices()[&slice].status, SliceStatus::Final);
    let paid: Amount = sim.coord.slices()[&slice]
        .lines
        .values()
        .map(|l| l.paid)
        .sum();
    assert_eq!(paid, 24, "two outputs of 12, split among the three lenders");

    // Fault 2: the borrower cancels; closing the job returns the work escrow, then the recovery
    // escrow. The journal fails on the second entry.
    let borrower = more_identity::assume_account(BORROWERS[0].0);
    let cancel = Command::Cancel {
        job: J1,
        expected_version: None,
    };
    run(&mut sim, &borrower, cancel).unwrap();
    // Its last slice drains, closes, and becomes due for evaluation; then the job can be settled.
    let drain_window = sim.coord.config().drain_window;
    run(&mut sim, &clock, Command::Tick { dt: drain_window }).unwrap();
    run(&mut sim, &reconciler, Command::Reconcile).unwrap();
    run(&mut sim, &clock, Command::Tick { dt: deadline }).unwrap();
    sim.coord.inject_ledger_fault(Some(1));
    let before = sim.coord.clone();
    let r = run(&mut sim, &reconciler, Command::Reconcile);
    assert!(matches!(r, Err(DomainError::Internal(_))), "{r:?}");
    assert!(sim.coord == before, "a half-settled job left a trace");
    assert_eq!(sim.coord.jobs()[&J1].settle, SettleStatus::Finalizing);
    assert!(
        sim.balance(Account::EscrowWork(J1.0)) > 0
            && sim.balance(Account::EscrowRecovery(J1.0)) > 0,
        "nothing was returned"
    );
    sim.coord.inject_ledger_fault(None);
    run(&mut sim, &reconciler, Command::Reconcile).unwrap();
    assert_eq!(sim.coord.jobs()[&J1].settle, SettleStatus::Closed);
    for a in [
        Account::EscrowWork(J1.0),
        Account::EscrowRecovery(J1.0),
        Account::OutputHold(J1.0),
    ] {
        assert_eq!(sim.balance(a), 0);
    }

    // From here on, every command is checked again, and the job ends as in the reference run.
    sim.drain();
    clean(&sim);
    let balances = |s: &Sim| -> Vec<(Account, i128)> {
        s.ledger()
            .accounts()
            .filter(|(a, _)| !matches!(a, Account::Issuance))
            .map(|(a, b)| (*a, *b))
            .collect()
    };
    assert_eq!(balances(&sim), balances(&reference));
    assert!(sim.ledger().check_invariants().is_empty());
}

/// What the ledger holds about attempt 2 of job 1.
fn ledger_attempt(sim: &Sim) -> gpu_ledger::AttemptRec {
    let escrows = sim
        .coord
        .ledger_service()
        .audit_escrows(&sim.ids.auditor)
        .unwrap();
    escrows[&J1.0].attempts[&2].clone()
}

fn claim(sim: &mut Sim, lender: AccountId, segment: u32, amount: Amount) {
    sim.exec(Command::Claim {
        slice: SLICE,
        lender,
        items: vec![ClaimItem::Recovery {
            segment,
            amount,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
}

/// The slice is closed and evaluated once its claims had their evaluation deadline.
fn close_and_evaluate(sim: &mut Sim) {
    if sim.coord.slices()[&SLICE].status == SliceStatus::Draining {
        let drain = sim.coord.config().drain_window;
        sim.exec(Command::Tick { dt: drain }).unwrap();
    }
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
}

/// Third review. The lender signed its restoration, then its node is revoked before its
/// recipient corroborates. The recipient's statement, honestly signed, comes after the
/// revocation in the log: it proves nothing (CE-03), on the coordinator and on the ledger, and
/// the recovery is never paid.
#[test]
fn r3_a_corroboration_after_the_lender_is_revoked_proves_nothing() {
    let mut sim = resumed();
    // L1's restoration is attested by L2 while the attempt is alive.
    sim.exec(corroborate(J1, 2, &L[1..2]).remove(0)).unwrap();
    claim(&mut sim, L[0], 0, 2);
    claim(&mut sim, L[1], 1, 2);
    sim.exec(Command::NodeLost {
        job: J1,
        expected_version: None,
    })
    .unwrap();
    let vouch = corroborate(J1, 2, &L[..1]).remove(0);
    let denied = |sim: &Sim| {
        let ledger = sim.coord.ledger_service();
        ledger.audit_denials(&sim.ids.auditor).unwrap().1
    };
    let asked = denied(&sim);
    assert_eq!(sim.exec(vouch.clone()), Err(DomainError::InadmissibleProof));
    assert_eq!(denied(&sim), asked, "refused on the coordinator's own log");
    // The ledger closed the attempt's proofs at the revocation: L1's corroboration is on record
    // before it, L0's is not on record at all.
    let rec = ledger_attempt(&sim);
    let before = rec.corroborated[1].as_ref().map(|c| c.seq);
    assert!(before.is_some() && before < rec.revoked);
    assert_eq!(rec.corroborated[0], None);
    let a = sim.coord.jobs()[&J1].attempts[&2].clone();
    assert!(a.leases[1].corroborated.as_ref().map(|c| c.seq) < a.revoked_seq);
    // Evaluation pays what was corroborated in time and holds the rest; a ruling cannot pay it,
    // and the late statement stays refused.
    close_and_evaluate(&mut sim);
    assert_eq!(line(&sim, L[1]).paid, 2);
    assert_eq!(line(&sim, L[0]).disputed, 2);
    let ruling = Command::Arbitrate {
        slice: SLICE,
        lender: L[0],
        pay: true,
    };
    assert_eq!(sim.exec(ruling), Err(DomainError::InadmissibleProof));
    assert_eq!(sim.exec(vouch), Err(DomainError::InadmissibleProof));
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 0);
    assert_eq!(sim.balance(Account::User(L[1].0)), 2);
}

/// Third review, the recipient's side. L1 goes silent after the restorations were signed: its
/// own lease runs out while the others keep renewing. What L1 would attest for L0, and what L2
/// would attest for L1, is refused on the recorded expiry, before reconciliation even notices.
/// L2's restoration, attested by the witness while both are alive, counts. Once the attempt is
/// revoked for the expired node, the refusal is final.
#[test]
fn r3_a_corroboration_after_the_recipient_lease_expired_proves_nothing() {
    let mut sim = resumed();
    let ttl = sim.coord.config().lease_ttl;
    sim.exec(Command::Tick { dt: ttl - 1 }).unwrap();
    for cmd in sim.renew_all(J1) {
        let silent = matches!(cmd, Command::Heartbeat { lender, .. } if lender == L[1]);
        if !silent {
            sim.exec(cmd).unwrap();
        }
    }
    sim.exec(Command::Tick { dt: 1 }).unwrap();
    let vouch = |k: usize| corroborate(J1, 2, &L[k..=k]).remove(0);
    // L1 is the recipient of L0 and the producer attested by L2.
    assert_eq!(sim.exec(vouch(0)), Err(DomainError::LeaseExpired));
    assert_eq!(sim.exec(vouch(1)), Err(DomainError::LeaseExpired));
    sim.exec(vouch(2)).unwrap();
    claim(&mut sim, L[0], 0, 2);
    claim(&mut sim, L[2], 1, 2);
    // Reconciliation revokes the attempt for the expired node.
    sim.exec(Command::Reconcile).unwrap();
    let a = sim.coord.jobs()[&J1].attempts[&2].clone();
    assert!(a.revoked_seq.is_some());
    assert_eq!(sim.exec(vouch(0)), Err(DomainError::InadmissibleProof));
    assert_eq!(sim.exec(vouch(1)), Err(DomainError::InadmissibleProof));
    close_and_evaluate(&mut sim);
    assert_eq!(line(&sim, L[2]).paid, 2);
    assert_eq!(line(&sim, L[0]).disputed, 2);
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 0);
    assert_eq!(sim.balance(Account::User(L[2].0)), 2);
}

/// Third review, the witness as recipient. The witness stops renewing: what it would attest for
/// the last stage is refused, while the lenders' corroborations of each other still count.
#[test]
fn r3_a_corroboration_by_an_expired_witness_proves_nothing() {
    let mut sim = resumed();
    let ttl = sim.coord.config().lease_ttl;
    sim.exec(Command::Tick { dt: ttl - 1 }).unwrap();
    for cmd in sim.renew_all(J1) {
        if !matches!(cmd, Command::WitnessHeartbeat { .. }) {
            sim.exec(cmd).unwrap();
        }
    }
    sim.exec(Command::Tick { dt: 1 }).unwrap();
    let vouch = |k: usize| corroborate(J1, 2, &L[k..=k]).remove(0);
    assert_eq!(sim.exec(vouch(2)), Err(DomainError::LeaseExpired));
    sim.exec(vouch(0)).unwrap();
    sim.exec(vouch(1)).unwrap();
    assert_eq!(ledger_attempt(&sim).corroborated[2], None);
    sim.drain();
    clean(&sim);
}

/// Third review, rights. The pool's admin withdraws a right between the restoration signature
/// and the corroboration: the lender's right to lend, or the witness's right to witness. The
/// corroboration is refused on the recorded withdrawal, and granting the right again later does
/// not make it admissible. A lender that lost nothing is not affected.
#[test]
fn r3_a_right_withdrawn_before_the_corroboration_voids_it() {
    let mut sim = resumed();
    let rights_of = |sim: &Sim, who| {
        let pool = sim.coord.registry().pool(CREDIT_POOL).unwrap();
        pool.rights(who)
    };
    let set = |account, rights| Command::SetRights {
        pool: CREDIT_POOL,
        account,
        rights,
    };
    let vouch = |k: usize| corroborate(J1, 2, &L[k..=k]).remove(0);
    // L0 may lend and witness. Losing the right to witness, which its stage does not rely on,
    // changes nothing (tried on a copy).
    let had = rights_of(&sim, L[0]);
    assert!(had.lend && had.witness);
    let lend_only = Rights {
        witness: false,
        ..had
    };
    sim.exec(set(L[0], lend_only)).unwrap();
    assert_eq!(sim.try_on_copy(&vouch(0)), Ok(Outcome::Applied));
    // Losing the right to lend does, and getting it back does not undo it.
    sim.exec(set(L[0], Rights::NONE)).unwrap();
    assert_eq!(sim.exec(vouch(0)), Err(DomainError::InadmissibleProof));
    sim.exec(set(L[0], had)).unwrap();
    assert_eq!(sim.exec(vouch(0)), Err(DomainError::InadmissibleProof));
    // L1 and its recipient L2 lost nothing: that corroboration counts.
    sim.exec(vouch(1)).unwrap();
    // The witness, recipient of the last stage, loses its right to witness.
    let had = rights_of(&sim, WITNESS);
    assert!(had.witness);
    sim.exec(set(WITNESS, Rights::NONE)).unwrap();
    assert_eq!(sim.exec(vouch(2)), Err(DomainError::InadmissibleProof));
    sim.exec(set(WITNESS, had)).unwrap();
    assert_eq!(sim.exec(vouch(2)), Err(DomainError::InadmissibleProof));
    let rec = ledger_attempt(&sim);
    assert_eq!((&rec.corroborated[0], &rec.corroborated[2]), (&None, &None));
    assert!(rec.corroborated[1].is_some());
    // Only L1's recovery is ever paid.
    for (k, segment) in [(0, 0), (1, 1), (2, 2)] {
        claim(&mut sim, L[k], segment, 1);
    }
    wait_alive(&mut sim, 1);
    sim.exec(Command::CloseSlice { slice: SLICE }).unwrap();
    let deadline = sim.coord.config().evaluation_deadline;
    sim.exec(Command::Tick { dt: deadline }).unwrap();
    sim.exec(Command::Evaluate { slice: SLICE }).unwrap();
    assert_eq!(line(&sim, L[1]).paid, 1);
    assert_eq!(line(&sim, L[0]).disputed + line(&sim, L[2]).disputed, 2);
    sim.drain();
    clean(&sim);
    assert_eq!(sim.balance(Account::User(L[0].0)), 0);
    assert_eq!(sim.balance(Account::User(L[1].0)), 1);
    assert_eq!(sim.balance(Account::User(L[2].0)), 0);
}

/// LEDGER-019 through the coordinator: a lender's readiness and a recipient's corroboration
/// signed for another deployment are refused, with the same keys and the same content.
#[test]
fn r3_statements_for_another_deployment_are_refused_by_the_coordinator() {
    let other = more_identity::IdentityAuthority::new([9; 32]).domain();
    assert_ne!(other, sim_domain());
    let mut sim = Sim::default();
    sim.exec(Command::Reserve { job: J1 }).unwrap();
    place(&mut sim, 0);
    let mut cmds = bring_up(J1, 1, &L, [0; 3]);
    let ready = cmds.split_off(cmds.len() - L.len());
    for cmd in cmds {
        sim.exec(cmd).unwrap();
    }
    for (cmd, l) in ready.into_iter().zip(L) {
        let r = readiness_of(J1, 1, l, [0; 3]);
        let elsewhere = Command::AttemptReady {
            job: J1,
            attempt: 1,
            lender: l,
            restored: r.restored,
            state: r.state,
            segments: r.segments.clone(),
            signature: user_key(l).sign(&more_identity::ready_message(&other, &r)),
        };
        assert_eq!(sim.exec(elsewhere), Err(DomainError::InadmissibleProof));
        sim.exec(cmd).unwrap();
    }
    let a = sim.coord.jobs()[&J1].attempts[&1].clone();
    let said = restoration_of(J1, &a, L[0], &all_segments()).unwrap();
    let elsewhere = Command::CorroborateRestore {
        job: J1,
        attempt: 1,
        lender: L[0],
        segments: all_segments(),
        signature: user_key(L[1]).sign(&more_identity::restore_message(&other, &said)),
    };
    assert_eq!(sim.exec(elsewhere), Err(DomainError::InadmissibleProof));
    sim.exec(corroborate(J1, 1, &L[..1]).remove(0)).unwrap();
    clean(&sim);
}
