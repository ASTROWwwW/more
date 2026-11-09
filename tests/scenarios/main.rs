//! Deterministic failure scenarios JOB-F01 to JOB-F41 (spec section 4) and targeted tests for
//! JOB-R21, JOB-R22 and JOB-R24, one file per group. This file holds the shared harness. Every command goes through the full checker, and every scenario
//! ends with the drain (liveness, settled escrow, fairness).

use gpu_domain::*;
use gpu_simulation::*;

mod contests;
mod delivery;
mod lifecycle;
mod settlement;

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
        &self.c().jobs()[&j]
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
        self.sim.balance(a)
    }

    fn attempt(&self, j: JobId) -> u32 {
        self.job(j).attempt
    }

    /// Reserve, place, start.
    fn start(&mut self, j: JobId, est: Amount) {
        if self.job(j).exec == ExecStatus::Queued {
            self.ok(Command::Reserve { job: j });
        }
        let n = layout_of(j).len();
        self.ok(Command::Place {
            job: j,
            lenders: L[..n].to_vec(),
            layout: layout_of(j),
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
                digest: self
                    .c()
                    .receipt_digest(j, a, *l, GEN, att.produced[GEN.idx()]),
            });
        }
    }

    fn open_slice(&self, j: JobId) -> SliceId {
        *self
            .c()
            .slices()
            .keys()
            .rfind(|s| s.job == j && self.c().slices()[s].status == SliceStatus::Open)
            .expect("open slice")
    }

    /// Each lender claims its range for every output of the slice's attempt.
    fn claim_all(&mut self, s: SliceId, ev: Evidence) {
        let outs: Vec<OutputId> = self
            .c()
            .delivery()
            .outputs()
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
                .jobs()
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
            .delivery()
            .charges()
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
            .audit_log()
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
        self.c().slices()[&s]
            .lines
            .get(&l)
            .cloned()
            .unwrap_or_default()
    }

    fn finish(mut self) {
        self.sim.drain();
        self.assert_clean();
        for j in self.c().jobs().values() {
            assert_eq!(j.settle, SettleStatus::Closed, "{:?}", j.id);
        }
    }
}
