//! Deterministic failure scenarios JOB-F01 to JOB-F41 (spec section 4) and targeted tests for
//! JOB-R21, JOB-R22 and JOB-R24. Every command goes through the full checker, and every scenario
//! ends with the drain (liveness, settled escrow, fairness).

use gpu_domain::*;
use gpu_simulation::*;

const J1: JobId = JobId(1); // 3 stages (3, 2, 1 layers), generation at 12 credits
const J3: JobId = JobId(3); // open-sharing pool
const L: [AccountId; 3] = [AccountId(10), AccountId(11), AccountId(12)];
const GEN: WorkType = WorkType::Generate;

struct T {
    sim: Sim,
}

impl T {
    fn new() -> Self {
        T {
            sim: Sim::new(sim_config()),
        }
    }

    fn with(cfg: Config) -> Self {
        T { sim: Sim::new(cfg) }
    }

    fn c(&self) -> &Coordinator {
        &self.sim.coord
    }

    fn job(&self, j: JobId) -> &Job {
        &self.c().jobs[&j]
    }

    fn assert_clean(&self) {
        assert!(
            self.sim.violations.is_empty(),
            "violations: {:#?}",
            self.sim.violations
        );
    }

    #[track_caller]
    fn ok(&mut self, cmd: Command) -> Outcome {
        let r = self.sim.exec(cmd.clone());
        self.assert_clean();
        r.unwrap_or_else(|e| panic!("{cmd:?} refused: {e:?}"))
    }

    #[track_caller]
    fn err(&mut self, cmd: Command) -> DomainError {
        let before = self.c().clone();
        let r = self.sim.exec(cmd.clone());
        self.assert_clean();
        let e = r.expect_err(&format!("{cmd:?} should be refused"));
        assert_eq!(&before, self.c(), "a refused command changed the state");
        e
    }

    fn bal(&self, a: Account) -> i128 {
        self.c().ledger.balance(a)
    }

    fn attempt(&self, j: JobId) -> u32 {
        self.job(j).attempt
    }

    /// Reserve, place, start.
    fn start(&mut self, j: JobId, est: Amount) {
        if self.job(j).exec == ExecStatus::Queued {
            self.ok(Command::Reserve { job: j });
        }
        let n = self.job(j).layout.len();
        self.ok(Command::Place {
            job: j,
            lenders: L[..n].to_vec(),
            recovery_estimate: est,
            witness: WITNESS,
            expected_version: None,
        });
        let (attempt, restored) = (self.attempt(j), self.job(j).delivered);
        self.ok(Command::AttemptReady {
            job: j,
            attempt,
            restored,
        });
    }

    /// Produces and acks `n` generation tokens, one by one.
    fn gen(&mut self, j: JobId, n: u32) {
        for _ in 0..n {
            let a = self.attempt(j);
            let p = self.job(j).current().unwrap().produced[GEN.idx()];
            self.ok(Command::Produce {
                job: j,
                attempt: a,
                wt: GEN,
                upto: p + 1,
            });
            self.ok(Command::Ack {
                job: j,
                attempt: a,
                wt: GEN,
                upto: p + 1,
            });
        }
    }

    fn commit_all(&mut self, j: JobId) {
        let a = self.attempt(j);
        let att = self.job(j).current().unwrap().clone();
        for l in &att.lenders {
            self.ok(Command::CommitReceipts {
                job: j,
                attempt: a,
                lender: *l,
                wt: GEN,
                upto: att.produced[GEN.idx()],
            });
        }
    }

    fn open_slice(&self, j: JobId) -> SliceId {
        *self
            .c()
            .slices
            .keys()
            .rfind(|s| s.job == j && self.c().slices[s].status == SliceStatus::Open)
            .expect("open slice")
    }

    /// Each lender claims its range for every output of the slice's attempt.
    fn claim_all(&mut self, s: SliceId, ev: Evidence) {
        let outs: Vec<OutputId> = self
            .c()
            .outputs
            .iter()
            .filter(|(o, a)| o.job == s.job && **a == s.attempt)
            .map(|(o, _)| *o)
            .collect();
        let lenders = self.job(s.job).attempts[&s.attempt].lenders.clone();
        for (stage, l) in lenders.iter().enumerate() {
            let items = outs
                .iter()
                .map(|o| ClaimItem::Contribution {
                    output: *o,
                    stage: stage as u32,
                    evidence: ev,
                })
                .collect();
            self.ok(Command::Claim {
                slice: s,
                lender: *l,
                items,
            });
        }
    }

    /// Time passes on a healthy cluster that keeps renewing its leases (JOB-R31). Use `Tick` for a
    /// silent cluster.
    fn wait(&mut self, dt: Time) {
        let mut left = dt;
        while left > 0 {
            let step = left.min(15);
            let live: Vec<(JobId, u32)> = self
                .c()
                .jobs
                .values()
                .filter(|j| matches!(j.exec, ExecStatus::Running | ExecStatus::Placing))
                .filter(|j| j.current().is_some_and(|a| a.revoked_at.is_none()))
                .map(|j| (j.id, j.attempt))
                .collect();
            for (job, attempt) in live {
                self.ok(Command::Heartbeat { job, attempt });
            }
            self.ok(Command::Tick { dt: step });
            left -= step;
        }
    }

    /// The witness attests delivery up to `upto` (JOB-R26).
    fn deliver(&mut self, j: JobId, upto: u32) {
        let a = self.attempt(j);
        self.ok(Command::Deliver {
            job: j,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto,
            digest: self.c().frame_digest(j, GEN, upto),
        });
    }

    /// Signed client statement bound to the stream (JOB-R28, JOB-R34).
    fn confirm(&mut self, j: JobId, confirmed: u32) -> Outcome {
        let digest = self.c().frame_digest(j, GEN, confirmed);
        self.ok(Command::ConfirmDelivery {
            job: j,
            wt: GEN,
            confirmed,
            digest,
        })
    }

    fn produce(&mut self, j: JobId, upto: u32) {
        let a = self.attempt(j);
        self.ok(Command::Produce {
            job: j,
            attempt: a,
            wt: GEN,
            upto,
        });
    }

    fn charge(&self, j: JobId, pos: u32) -> Option<OutputCharge> {
        self.c()
            .charges
            .get(&OutputId {
                job: j,
                wt: GEN,
                pos,
            })
            .copied()
    }

    /// Net number of charges of an output, from the log.
    fn net_charges(&self, j: JobId, pos: u32) -> i64 {
        let o = OutputId {
            job: j,
            wt: GEN,
            pos,
        };
        self.c()
            .audit
            .iter()
            .map(|e| match e {
                AuditEvent::OutputCharged { output, .. } if *output == o => 1,
                AuditEvent::OutputVoided { output, .. } if *output == o => -1,
                _ => 0,
            })
            .sum()
    }

    fn close_eval(&mut self, s: SliceId) {
        self.ok(Command::CloseSlice { slice: s });
        self.ok(Command::Evaluate { slice: s });
    }

    fn line(&self, s: SliceId, l: AccountId) -> Line {
        self.c().slices[&s]
            .lines
            .get(&l)
            .cloned()
            .unwrap_or_default()
    }

    fn finish(mut self) {
        self.sim.drain();
        self.assert_clean();
        for j in self.c().jobs.values() {
            assert_eq!(j.settle, SettleStatus::Closed, "{:?}", j.id);
        }
    }
}

// ---------------------------------------------------------------- JOB-F01 to F23

#[test]
fn f01_partial_transition_leaves_no_trace() {
    // A two-entry transition whose second entry fails writes nothing (JOB-R01).
    let mut t = T::new();
    t.ok(Command::Issue {
        id: 50,
        to: IssueTarget::User(AccountId(3)),
        amount: 177,
    });
    t.ok(Command::Submit {
        job: JobId(4),
        borrower: AccountId(3),
        pool: CREDIT_POOL,
        layout: vec![3, 2, 1],
        price: [6, 12, 3],
        max_outputs: [4, 12, 3],
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
    assert_eq!(t.c().slices[&s2].rejected_items, 1);
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
    assert!(!t.c().outputs.contains_key(&OutputId {
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
    assert_eq!(t.c().slices[&s].rejected_items, 1);
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
    assert_eq!(t.c().slices[&s].status, SliceStatus::Draining);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[1]).paid, 2 * 4);
    t.ok(Command::Resume { job: J1, topup: 0 });
    t.start(J1, 3);
    t.gen(J1, 1);
    t.finish();
}

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
        t.c().slices[&s].rejected_items,
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
    assert_eq!(t.c().slices[&s].status, SliceStatus::Disputed);
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
    assert_eq!(t.c().slices[&s1].status, SliceStatus::Draining);
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
        assert_eq!(t.c().outputs[&o], if p < 2 { 1 } else { 2 });
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
    assert_eq!(t.c().slices[&s].status, SliceStatus::Final);
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
    assert_eq!(t.c().slices[&s2].status, SliceStatus::Disputed);
    assert_eq!(t.line(s2, L[0]).paid, 18);
    assert_eq!(t.line(s2, L[0]).disputed, 0);
    assert_eq!(t.line(s2, L[2]).paid, 2);
    assert_eq!(t.line(s2, L[2]).disputed, 4);
    t.ok(Command::Arbitrate {
        slice: s2,
        lender: L[2],
        pay: true,
    });
    assert_eq!(t.c().slices[&s2].status, SliceStatus::Final);
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
    assert_eq!(t.c().slices[&s2].rejected_items, 1);
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
    let circulating = t.c().ledger.circulating();
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
    assert_eq!(t.c().ledger.circulating(), circulating, "no credit created");
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

#[test]
fn f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    let escrow0 = t.bal(Account::EscrowWork(1));
    t.produce(J1, 5);
    t.deliver(J1, 5); // the witness sees 4 tokens go by; the client never acks
    assert_eq!(t.job(J1).validated[GEN.idx()], 1);
    assert_eq!(t.job(J1).delivered[GEN.idx()], 5);
    assert!(!t.charge(J1, 4).unwrap().definitive);
    assert_eq!(
        escrow0 - t.bal(Account::EscrowWork(1)),
        4 * 12,
        "billed provisionally"
    );
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    // End of draining, then of the 24 h delivery window and of evaluation.
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 24 * 3600 });
    t.ok(Command::Reconcile);
    assert!(t.charge(J1, 4).unwrap().definitive);
    assert_eq!(t.charge(J1, 4).unwrap().basis, ChargeBasis::WindowExpired);
    assert_eq!(
        t.line(s, L[0]).paid,
        5 * 6,
        "the witnessed window is paid to lenders"
    );
    assert_eq!(t.line(s, L[2]).paid, 5 * 2);
    // The client contests too late: free retransmission, no refund.
    let before = t.c().ledger.entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    assert_eq!(
        t.c().ledger.entries().len(),
        before,
        "replay moves no credits"
    );
    t.finish();
}

#[test]
fn f25_lender_cannot_attest_its_own_delivery() {
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    // A lender cannot be the witness of its own cluster (JOB-R26).
    assert!(matches!(
        t.err(Command::Place {
            job: J1,
            lenders: L.to_vec(),
            recovery_estimate: 0,
            witness: L[2],
            expected_version: None,
        }),
        DomainError::Precondition(_)
    ));
    t.start(J1, 0);
    t.produce(J1, 3);
    // The output node "attests" itself: no proof.
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: L[2],
            wt: GEN,
            upto: 3,
            digest: t.c().frame_digest(J1, GEN, 3)
        }),
        DomainError::InadmissibleProof
    );
    assert!(t.c().charges.is_empty());
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).delivered[GEN.idx()],
        0,
        "nothing billed without proof"
    );
    t.finish();
}

#[test]
fn f26_lost_ack_then_resume_replays_without_double_billing() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.produce(J1, 6);
    t.deliver(J1, 6); // positions 2..6 delivered; the client's ack is lost
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // The client reports its last received position: 2 and 3 received, 4 and 5 not.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 4,
        digest: t.c().frame_digest(J1, GEN, 4),
    });
    assert_eq!(t.job(J1).validated[GEN.idx()], 4);
    assert_eq!(t.charge(J1, 3).unwrap().basis, ChargeBasis::ClientSigned);
    // 4 and 5: contested, replayed, still provisional (JOB-R33).
    let c5 = t.charge(J1, 5).unwrap();
    assert!(!c5.definitive && c5.contest.is_some());
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    // The resume starts from delivered positions, not validated ones.
    assert!(matches!(
        t.err(Command::AttemptReady {
            job: J1,
            attempt: 2,
            restored: [0, 4, 0],
        }),
        DomainError::Precondition(_)
    ));
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 6, 0],
    });
    t.gen(J1, 1); // cumulative ack up to 7, also covers the replay of 4 and 5
    assert_eq!(t.charge(J1, 5).unwrap().basis, ChargeBasis::ClientSigned);
    assert!(t.charge(J1, 5).unwrap().contest.is_none());
    for pos in 0..7 {
        assert_eq!(t.net_charges(J1, pos), 1, "position {pos} billed once");
    }
    assert_eq!(
        t.c().outputs[&OutputId {
            job: J1,
            wt: GEN,
            pos: 5
        }],
        1,
        "replayed, not regenerated"
    );
    assert_eq!(
        t.c().outputs[&OutputId {
            job: J1,
            wt: GEN,
            pos: 6
        }],
        2
    );
    t.finish();
}

#[test]
fn f27_lost_replay_buffer_contest_refunds_and_rewinds() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 5);
    t.deliver(J1, 5);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    // Contributions to provisional outputs: reserved and waiting (JOB-R30); the slice stays closed
    // until the deadline (CE-06).
    assert_eq!(t.c().slices[&s].status, SliceStatus::Closed);
    assert_eq!(t.line(s, L[0]).paid, 6);
    assert_eq!(t.line(s, L[0]).disputed, 4 * 6);
    assert!(
        t.sim
            .coord
            .clone()
            .apply(&Command::Arbitrate {
                slice: s,
                lender: L[0],
                pay: true,
            })
            .is_err(),
        "awaiting contributions are never arbitrated on their own"
    );
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    let escrow = t.bal(Account::EscrowWork(1));
    // The client got 1 and 2, not 3 or 4; the buffer is lost.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 3,
        digest: t.c().frame_digest(J1, GEN, 3),
    });
    assert_eq!(
        t.job(J1).delivered[GEN.idx()],
        3,
        "rewound to the first lost position"
    );
    assert_eq!(
        t.bal(Account::EscrowWork(1)) - escrow,
        2 * 12,
        "voided outputs refunded"
    );
    assert!(t.charge(J1, 3).is_none());
    // 1 and 2 signed by the client are paid; 3 and 4 voided are refunded.
    assert_eq!(t.line(s, L[0]).paid, 3 * 6);
    assert_eq!(t.line(s, L[0]).refunded, 2 * 6);
    assert_eq!(t.line(s, L[0]).disputed + t.line(s, L[0]).pending, 0);
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 3, 0],
    });
    t.gen(J1, 2); // positions 3 and 4 produced again and charged again
    assert_eq!(t.net_charges(J1, 3), 1);
    assert_eq!(t.charge(J1, 3).unwrap().gen, 1);
    assert_eq!(
        t.c().outputs[&OutputId {
            job: J1,
            wt: GEN,
            pos: 3
        }],
        2
    );
    t.finish();
}

#[test]
fn f28_simultaneous_client_silence_and_lease_expiry() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    // No ack and no heartbeat: both deadlines hit together.
    t.ok(Command::Tick { dt: 60 });
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).exec,
        ExecStatus::Recovering,
        "one transition wins"
    );
    let revocations = t
        .c()
        .audit
        .iter()
        .filter(|e| {
            matches!(
                e,
                AuditEvent::Exec {
                    from: Some(ExecStatus::Running),
                    ..
                }
            )
        })
        .count();
    assert_eq!(revocations, 1);
    // Node and witness lost in the same second, on the resume.
    t.start(J1, 2);
    t.produce(J1, 3);
    t.deliver(J1, 3);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 2,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert!(!t.charge(J1, 2).unwrap().replayable);
    t.finish();
}

#[test]
fn f29_expired_lease_rejects_work_until_reconciliation_revokes() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.wait(300); // healthy cluster: the lease is renewed
    t.gen(J1, 1);
    t.ok(Command::Tick { dt: 45 }); // silent cluster
    let a = t.attempt(J1);
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: a,
            wt: GEN,
            upto: 3,
        }),
        DomainError::LeaseExpired
    );
    assert_eq!(
        t.err(Command::Heartbeat {
            job: J1,
            attempt: a
        }),
        DomainError::LeaseExpired,
        "an expired lease is never renewed"
    );
    assert_eq!(t.job(J1).exec, ExecStatus::Running);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Recovering);
    t.finish();
}

#[test]
fn f30_client_cannot_overstate_or_unconfirm_or_contest_live_output() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 5);
    t.deliver(J1, 3);
    // Output of the live attempt: retransmit, don't contest.
    assert!(matches!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 1,
            digest: t.c().frame_digest(J1, GEN, 1)
        }),
        DomainError::Precondition(_)
    ));
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    for confirmed in [0, 4] {
        assert!(matches!(
            t.err(Command::ConfirmDelivery {
                job: J1,
                wt: GEN,
                confirmed,
                digest: t.c().frame_digest(J1, GEN, confirmed)
            }),
            DomainError::Precondition(_)
        ));
    }
    t.finish();
}

#[test]
fn f31_contest_after_window_replays_but_never_refunds() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 24 * 3600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.charge(J1, 3).unwrap().basis, ChargeBasis::WindowExpired);
    let entries = t.c().ledger.entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    // Window over: plain retransmission, no contest, no ledger entry.
    assert!(t.charge(J1, 3).unwrap().contest.is_none());
    assert_eq!(t.c().ledger.entries().len(), entries);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    // Buffer lost after the window: the output stays due, no replay possible.
    assert!(matches!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 1,
            digest: t.c().frame_digest(J1, GEN, 1)
        }),
        DomainError::Precondition(_)
    ));
    t.finish();
}

#[test]
fn f32_rewind_revokes_live_attempt_built_on_voided_outputs() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 2); // the resume starts at position 4 without waiting for the client
                    // Flow budget measured from the client's signature: only 1 more unit.
    t.produce(J1, 5);
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 2,
            wt: GEN,
            upto: 6,
        }),
        DomainError::FlowBudgetExceeded
    );
    assert_eq!(t.job(J1).exec, ExecStatus::Running);
    // The client comes back: it got nothing after position 1.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    assert_eq!(t.job(J1).delivered[GEN.idx()], 1);
    assert_eq!(
        t.job(J1).exec,
        ExecStatus::Recovering,
        "attempt 2 was built on voided outputs"
    );
    assert!(t.job(J1).attempts[&2].revoked_at.is_some());
    t.start(J1, 2);
    assert_eq!(t.job(J1).current().unwrap().produced[GEN.idx()], 1);
    t.gen(J1, 1);
    assert_eq!(t.net_charges(J1, 1), 1);
    t.finish();
}

// ------------------------------------------------ JOB-F33 to F41 (contests, proofs, cap)

/// Attested tail (positions 1 to 3), node lost.
fn provisional_tail(t: &mut T) {
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
}

#[test]
fn f33_signed_heartbeat_without_replay_receipt_is_refunded() {
    let mut t = T::new();
    provisional_tail(&mut t);
    let escrow = t.bal(Account::EscrowWork(1));
    t.confirm(J1, 1); // "nothing after position 1": contest and replay
    assert!(t.charge(J1, 3).unwrap().contest.is_some());
    // The client sends a signed keepalive, but no ack covering the replay.
    assert_eq!(
        t.ok(Command::ClientHeartbeat { job: J1 }),
        Outcome::AlreadyApplied
    );
    t.ok(Command::Tick { dt: 3600 });
    t.ok(Command::Reconcile);
    assert!(t.charge(J1, 1).is_none(), "unconfirmed replay is refunded");
    assert_eq!(t.job(J1).delivered[GEN.idx()], 1);
    assert_eq!(t.bal(Account::EscrowWork(1)) - escrow, 3 * 12);
    t.finish();
}

#[test]
fn f34_cumulative_ack_covering_the_replay_bills_definitively() {
    let mut t = T::new();
    provisional_tail(&mut t);
    t.confirm(J1, 1);
    // The replay arrives: signed cumulative ack, bound to the stream, covering 1 to 3.
    t.confirm(J1, 4);
    for pos in 1..4 {
        let ch = t.charge(J1, pos).unwrap();
        assert!(ch.definitive && ch.contest.is_none());
        assert_eq!(ch.basis, ChargeBasis::ClientSigned);
    }
    t.ok(Command::Tick { dt: 3600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.net_charges(J1, 3), 1, "nothing refunded at the deadline");
    t.finish();
}

#[test]
fn f35_declaration_or_attestation_from_another_session_is_rejected() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    let j2 = JobId(2);
    t.start(j2, 0);
    let a = t.attempt(J1);
    // Frames from another stream presented for this job.
    let foreign = t.c().frame_digest(j2, GEN, 3);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto: 3,
            digest: foreign,
        }),
        DomainError::InadmissibleProof
    );
    t.deliver(J1, 3);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Statement signed in another session: rejected, nothing changes.
    let foreign = t.c().frame_digest(j2, GEN, 3);
    assert_eq!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 3,
            digest: foreign,
        }),
        DomainError::InadmissibleProof
    );
    assert!(!t.charge(J1, 2).unwrap().definitive);
    t.finish();
}

#[test]
fn f36_frame_different_from_the_signed_digest_is_rejected() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    let a = t.attempt(J1);
    let substituted = t.c().frame_digest(J1, GEN, 3) ^ 1;
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto: 3,
            digest: substituted,
        }),
        DomainError::InadmissibleProof
    );
    assert!(
        t.charge(J1, 1).is_none(),
        "nothing billed on a substituted frame"
    );
    t.finish();
}

#[test]
fn f37_commitment_before_revocation_makes_late_attestation_admissible() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::WitnessCommit {
        job: J1,
        attempt: 1,
        witness: WITNESS,
        wt: GEN,
        upto: 4,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 30 }); // the full attestation arrives while draining
    t.deliver(J1, 4);
    assert!(t
        .c()
        .audit
        .iter()
        .any(|e| matches!(e, AuditEvent::LateDelivery { to: 4, .. })));
    assert!(!t.charge(J1, 3).unwrap().definitive, "billed provisionally");
    t.finish();
}

#[test]
fn f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Commitment forged after revocation: rejected.
    assert_eq!(
        t.err(Command::WitnessCommit {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
        }),
        DomainError::StaleAttempt
    );
    let d = t.c().frame_digest(J1, GEN, 4);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
            digest: d,
        }),
        DomainError::InadmissibleProof
    );
    // Even with an earlier commitment, an attestation after draining is rejected.
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::WitnessCommit {
        job: J1,
        attempt: 1,
        witness: WITNESS,
        wt: GEN,
        upto: 4,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    let d = t.c().frame_digest(J1, GEN, 4);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
            digest: d,
        }),
        DomainError::StaleAttempt
    );
    t.finish();
}

#[test]
fn f39_contest_just_before_window_end_keeps_the_buffer() {
    let mut t = T::new();
    provisional_tail(&mut t);
    t.ok(Command::Tick { dt: 24 * 3600 - 60 }); // 23:59
    t.confirm(J1, 1);
    t.ok(Command::Tick { dt: 120 }); // the 24 h window is over
    t.ok(Command::Reconcile);
    assert!(
        !t.charge(J1, 3).unwrap().definitive,
        "positions after a contested one wait for it"
    );
    assert!(matches!(
        t.err(Command::PurgeBuffer {
            job: J1,
            attempt: 1
        }),
        DomainError::Precondition(_)
    ));
    t.confirm(J1, 4); // the replay is received and acked
    t.ok(Command::PurgeBuffer {
        job: J1,
        attempt: 1,
    });
    t.finish();
}

#[test]
fn f40_sliding_cap_holds_across_midnight_and_after_refunds() {
    let mut t = T::new();
    t.ok(Command::Tick {
        dt: 24 * 3600 - 300,
    }); // 23:55
    t.start(J1, 0);
    t.gen(J1, 3);
    let un = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 2,
        evidence: Evidence::Uncommitted,
    };
    // Two uncommitted receipts of 2 credits before midnight: 4 = cap.
    let mut slices = Vec::new();
    for p in 0..2 {
        let s = t.open_slice(J1);
        t.ok(Command::Claim {
            slice: s,
            lender: L[2],
            items: vec![un(p)],
        });
        t.close_eval(s);
        assert_eq!(t.line(s, L[2]).paid, 2);
        slices.push(s);
    }
    // A contest returns 2 credits to the borrower; the quota is not restored.
    t.ok(Command::ContestReward {
        slice: slices[0],
        lender: L[2],
    });
    t.wait(360); // 00:01: new calendar day, same sliding window
    let s = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s,
        lender: L[2],
        items: vec![un(2)],
    });
    t.close_eval(s);
    assert_eq!(
        t.line(s, L[2]).disputed,
        2,
        "6 > 4 within 24 h: disputed despite midnight and the refund"
    );
    // 24 h after the first payments, the quota is available again.
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 24 * 3600 });
    let j2 = JobId(2);
    t.ok(Command::Reserve { job: j2 });
    t.ok(Command::Place {
        job: j2,
        lenders: vec![L[2], L[0]],
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
    let s2 = t.open_slice(j2);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[2],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j2,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Uncommitted,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.line(s2, L[2]).paid, 3);
    t.finish();
}

#[test]
fn f41_supplementary_proof_before_deadline_is_paid_after_is_refused() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::None); // claims sent before the proof came back
    t.close_eval(s);
    assert_eq!(t.c().slices[&s].status, SliceStatus::Closed);
    assert_eq!(
        t.line(s, L[0]).pending,
        2 * 6,
        "nothing refunded before the deadline"
    );
    t.ok(Command::SupplementEvidence {
        slice: s,
        lender: L[0],
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 0,
        },
        evidence: Evidence::Committed,
    });
    t.ok(Command::Tick { dt: 600 });
    // Deadline reached, slice not evaluated yet: a proof sent now is too late.
    let late = Command::SupplementEvidence {
        slice: s,
        lender: L[0],
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 1,
        },
        evidence: Evidence::Committed,
    };
    assert!(matches!(t.err(late), DomainError::Precondition(_)));
    t.ok(Command::Reconcile);
    assert_eq!(t.line(s, L[0]).paid, 6, "supplemented proof is paid");
    assert_eq!(
        t.line(s, L[0]).refunded,
        6,
        "the other one is refunded at the deadline"
    );
    assert!(matches!(
        t.err(Command::SupplementEvidence {
            slice: s,
            lender: L[0],
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 1,
            },
            evidence: Evidence::Committed,
        }),
        DomainError::Precondition(_)
    ));
    t.finish();
}
