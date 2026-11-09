//! JOB-F15 to JOB-F23 and the targeted JOB-R21, JOB-R22, JOB-R24 tests: claims, disputes, recovery
//! budget, settlement.

use super::*;

#[test]
fn f15_withheld_acks_bound_loss_to_k() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 5,
    }); // 4 delivered, never acked
    t.commit_all(J1);
    let s = t.open_slice(J1);
    // Lenders also claim the unacked window: rejected (output not validated).
    let items = (0..5)
        .map(|p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage: 0,
            evidence: Evidence::Committed,
        })
        .collect();
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items,
    });
    t.wait(60);
    t.ok(Command::Reconcile); // pause, client silent
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile); // end of draining: closure
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile); // evaluation deadline
    assert_eq!(t.line(s, L[0]).paid, 6, "only the validated output is paid");
    assert_eq!(
        t.c().slices()[&s].rejected_items,
        4,
        "loss bounded by K = 4 unacknowledged outputs"
    );
    t.finish();
}

#[test]
fn f16_survivor_paid_after_other_gpu_fails() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 3);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Only the stage 0 lender claims, while draining.
    let items = (0..3)
        .map(|p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage: 0,
            evidence: Evidence::Committed,
        })
        .collect();
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items,
    });
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 18);
    t.finish();
}

#[test]
fn f17_receipts_fabricated_after_revocation() {
    // Written for an 8-credit cap (the simulation uses 4).
    let mut t = T::with(Config {
        uncommitted_cap: 8,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 4);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Commitment sent AFTER revocation: stamped too late.
    t.ok(Command::Tick { dt: 5 });
    t.ok(Command::CommitReceipts {
        job: J1,
        attempt: 1,
        lender: L[0],
        wt: GEN,
        upto: 4,
        digest: t.c().receipt_digest(J1, 1, L[0], GEN, 4),
    });
    let ev = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![ev(0), ev(1)],
    });
    // Uncommitted receipts: at most K = 4 per type while draining.
    let un = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 1,
        evidence: Evidence::Uncommitted,
    };
    assert_eq!(
        t.err(Command::Claim {
            slice: s,
            lender: L[1],
            items: (0..5).map(un).collect()
        }),
        DomainError::FlowBudgetExceeded
    );
    t.ok(Command::Claim {
        slice: s,
        lender: L[1],
        items: (0..4).map(un).collect(),
    });
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 0, "late commitment proves nothing");
    // JOB-R35: refund for missing proof only at the evaluation deadline.
    assert_eq!(t.line(s, L[0]).pending, 12);
    t.ok(Command::Tick { dt: 600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.line(s, L[0]).refunded, 12);
    // 4 x 4 = 16 > cap 8: 2 paid, 2 disputed.
    assert_eq!(t.line(s, L[1]).paid, 8);
    assert_eq!(t.line(s, L[1]).disputed, 8);
    assert_eq!(t.c().slices()[&s].status, SliceStatus::Disputed);
    t.finish();
}

#[test]
fn f18_new_attempt_runs_while_old_slice_drains() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 4);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    assert_eq!(t.c().slices()[&s1].status, SliceStatus::Draining);
    t.claim_all(s1, Evidence::Committed);
    t.claim_all(s2, Evidence::Committed);
    t.close_eval(s2);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[0]).paid, 12);
    assert_eq!(t.line(s2, L[0]).paid, 12);
    t.finish();
}

#[test]
fn f18b_free_pool_resume_uses_quota_not_credits() {
    let mut t = T::new();
    t.start(J3, 0);
    t.gen(J3, 2);
    t.ok(Command::Pause {
        job: J3,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.err(Command::Resume { job: J3, topup: 10 });
    t.ok(Command::Resume { job: J3, topup: 0 });
    t.start(J3, 0);
    t.gen(J3, 1);
    t.finish();
}

#[test]
fn f19_resume_after_pause_keeps_intent() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 3);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Resume { job: J1, topup: 0 });
    assert_eq!(t.job(J1).intent, Intent::Resume);
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    assert_eq!(
        t.job(J1).intent,
        Intent::Resume,
        "JOB-T04 does not reset the intent"
    );
    t.err(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0; 3],
    });
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 3, 0],
    });
    t.finish();
}

#[test]
fn f20_unvalidated_positions_are_wasted_not_billed() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2); // positions 0-1 validated
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 5,
    }); // 2-4 produced
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 6);
    assert_eq!(
        t.job(J1).current().unwrap().produced[GEN.idx()],
        2,
        "attempt 2 resumes at 2"
    );
    t.gen(J1, 3); // positions 2-4 validated on attempt 2
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    // Attempt 1 claims 0..5; only 0-1 belong to it.
    let all = |stage| {
        (0..5).map(move |p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage,
            evidence: Evidence::Committed,
        })
    };
    t.ok(Command::Claim {
        slice: s1,
        lender: L[0],
        items: all(0).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: all(0).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: 6,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[0]).paid, 12, "attempt 1: positions 0-1");
    assert_eq!(
        t.line(s2, L[0]).paid,
        18 + 6,
        "attempt 2: positions 2-4 + recovery"
    );
    for p in 0..5 {
        let o = OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        };
        assert_eq!(t.c().delivery().outputs()[&o], if p < 2 { 1 } else { 2 });
    }
    t.finish();
}

#[test]
fn f21_dispute_isolated_to_one_lender_line() {
    // Written for an 8-credit cap (the simulation uses 4).
    let mut t = T::with(Config {
        uncommitted_cap: 8,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 3);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    let item = |p, stage, evidence| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage,
        evidence,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: (0..3).map(|p| item(p, 0, Evidence::Committed)).collect(),
    });
    t.ok(Command::Claim {
        slice: s,
        lender: L[1],
        items: (0..3).map(|p| item(p, 1, Evidence::Committed)).collect(),
    });
    // Stage 2 (2 credits per output) on uncommitted receipts: 6 <= 8, paid.
    t.ok(Command::Claim {
        slice: s,
        lender: L[2],
        items: (0..3).map(|p| item(p, 2, Evidence::Uncommitted)).collect(),
    });
    t.close_eval(s);
    assert_eq!(t.c().slices()[&s].status, SliceStatus::Final);
    // Second slice: lender 12 goes over the cap, only its line is disputed.
    t.gen(J1, 3);
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: (3..6).map(|p| item(p, 0, Evidence::Committed)).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[2],
        items: (3..6).map(|p| item(p, 2, Evidence::Uncommitted)).collect(),
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices()[&s2].status, SliceStatus::Disputed);
    assert_eq!(t.line(s2, L[0]).paid, 18);
    assert_eq!(t.line(s2, L[0]).disputed, 0);
    assert_eq!(t.line(s2, L[2]).paid, 2);
    assert_eq!(t.line(s2, L[2]).disputed, 4);
    t.ok(Command::Arbitrate {
        slice: s2,
        lender: L[2],
        pay: true,
    });
    assert_eq!(t.c().slices()[&s2].status, SliceStatus::Final);
    t.finish();
}

#[test]
fn f22_cancel_while_draining_settles_everything() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Cancel {
        job: J1,
        expected_version: None,
    });
    assert_eq!(t.job(J1).exec, ExecStatus::Cancelled);
    assert_eq!(t.job(J1).settle, SettleStatus::Finalizing);
    t.err(Command::Settle { job: J1 }); // slice still draining
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).settle, SettleStatus::Closed);
    assert_eq!(t.bal(Account::EscrowWork(1)), 0);
    assert_eq!(t.bal(Account::OutputHold(1)), 0);
    // Borrower: 2,000 - 24 (2 outputs). The 24 are held for lenders.
    assert_eq!(t.bal(Account::User(1)), 2_000 - 24);
    t.finish();
}

#[test]
fn f23_recovery_budget_exhausted_then_pool_relay() {
    let mut t = T::new();
    assert_eq!(t.job(J1).recovery_budget, 17);
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 17); // whole budget
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert_eq!(
        t.err(Command::Place {
            job: J1,
            lenders: L.to_vec(),
            layout: layout_of(J1),
            recovery_estimate: 1,
            witness: WITNESS,
            expected_version: None
        }),
        DomainError::RecoveryBudget
    );
    // The pool locks 10 credits before the resume.
    t.ok(Command::FundRecovery {
        job: J1,
        amount: 10,
    });
    t.start(J1, 10);
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Nothing left: no unfunded resume, pause at the deadline.
    t.err(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 1,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Paused);
    t.finish();
}

// ------------------------------------------------- targeted tests

#[test]
fn r21_every_stage_paid_once_and_sum_le_price() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    let paid: Amount = L.iter().map(|l| t.line(s, *l).paid).sum();
    assert_eq!(
        [
            t.line(s, L[0]).paid,
            t.line(s, L[1]).paid,
            t.line(s, L[2]).paid
        ],
        [6, 4, 2]
    );
    assert_eq!(paid, 12, "three contributions, one output, sum = price");
    // A lender cannot claim another lender's range.
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
            stage: 1,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices()[&s2].rejected_items, 1);
    t.finish();
}

#[test]
fn r21_rounding_never_exceeds_price() {
    // Job 2: 2 equal stages, price 7, so shares 3 + 3 = 6 <= 7; the rest goes back to the borrower.
    let mut t = T::new();
    let j2 = JobId(2);
    t.ok(Command::Reserve { job: j2 });
    t.ok(Command::Place {
        job: j2,
        lenders: L[..2].to_vec(),
        layout: layout_of(j2),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::AttemptReady {
        job: j2,
        attempt: 1,
        restored: [0; 3],
    });
    t.gen(j2, 1);
    t.commit_all(j2);
    let s = t.open_slice(j2);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid + t.line(s, L[1]).paid, 6);
    t.finish();
}

#[test]
fn r24_pending_evaluation_balances_line_between_close_and_evaluate() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::CloseSlice { slice: s });
    let l = t.line(s, L[0]);
    assert_eq!(
        (l.claimed, l.pending, l.paid, l.refunded, l.disputed),
        (12, 12, 0, 0, 0)
    );
    // Atomic reservation: the money already moved from OutputHold to the line.
    assert_eq!(
        t.bal(Account::SliceLine {
            job: 1,
            attempt: 1,
            slice: s.slice,
            lender: 10
        }),
        12
    );
    t.ok(Command::Evaluate { slice: s });
    let l = t.line(s, L[0]);
    assert_eq!((l.pending, l.paid), (0, 12));
    t.finish();
}

#[test]
fn r22_contest_after_job_closed_refunds_from_held_rewards() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    t.ok(Command::Finish {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).settle,
        SettleStatus::Closed,
        "job financially closed"
    );
    let circulating = t.sim.ledger().circulating();
    let borrower = t.bal(Account::User(1));
    // Fraud found: lender 11's line is contested within the window.
    t.ok(Command::ContestReward {
        slice: s,
        lender: L[1],
    });
    assert_eq!(
        t.bal(Account::User(1)),
        borrower + 8,
        "refund comes from held rewards"
    );
    assert_eq!(
        t.sim.ledger().circulating(),
        circulating,
        "no credit created"
    );
    // After the window: release is final, no more contest.
    t.ok(Command::Tick { dt: 48 * 3600 });
    t.ok(Command::ReleaseReward {
        slice: s,
        lender: L[0],
    });
    t.err(Command::ContestReward {
        slice: s,
        lender: L[0],
    });
    t.err(Command::ContestReward {
        slice: s,
        lender: L[2],
    }); // window closed
    t.ok(Command::ReleaseReward {
        slice: s,
        lender: L[2],
    });
    assert_eq!(
        t.bal(Account::User(10)),
        12 - 1,
        "lender gets 12 minus 10 % commission"
    );
    t.finish();
}

// ------------------------------------------------- JOB-F24 to F32 (delivery)
