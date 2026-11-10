//! Resolution of abstract operations against the current state.

use super::*;

impl Sim {
    pub fn resolve(&self, op: &Op) -> Vec<Command> {
        let c = &self.coord;
        match *op {
            // Needs a sender other than the honest one: see `run_op`.
            Op::Impersonate { job, sel, .. } => self.impersonated(job, sel).into_iter().collect(),
            Op::Tick(s) => {
                // Mostly small steps, sometimes a jump past the deadlines.
                let dt = match s % 8 {
                    0 => 3 * 24 * 3600,
                    1 => 700,
                    2 => 130,
                    _ => u64::from(s % 40) + 1,
                };
                vec![Command::Tick { dt }]
            }
            Op::Reserve(j) => vec![Command::Reserve { job: self.job(j) }],
            Op::Place { job, rot, est } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let lenders = (0..layout_of(id).len())
                    .map(|k| LENDERS[(k + rot as usize) % LENDERS.len()])
                    .collect();
                let recovery_estimate = if j.intent == Intent::Resume {
                    u64::from(est % 12)
                } else {
                    0
                };
                // Sometimes a non-independent witness (a lender), which must be rejected.
                let witness = if est % 9 == 0 {
                    LENDERS[rot as usize % LENDERS.len()]
                } else {
                    WITNESS
                };
                vec![Command::Place {
                    job: id,
                    lenders,
                    layout: layout_of(id),
                    recovery_estimate,
                    witness,
                    expected_version: None,
                }]
            }
            Op::PlacementFailed(j) => vec![Command::PlacementFailed { job: self.job(j) }],
            Op::Ready { job, correct } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let mut restored = j.delivered;
                if !correct {
                    restored[1] = restored[1].saturating_add(1);
                }
                let Some(a) = j.current() else { return vec![] };
                let mut v = bring_up(id, j.attempt, &a.lenders, restored);
                v.extend(corroborate(id, j.attempt, &a.lenders));
                v
            }
            Op::Corroborate { job, stage, forged } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                let lender = pick(&a.lenders, stage);
                // Sometimes the recipient only received the first segment, or all but one.
                let segments = match stage % 5 {
                    4 => vec![0],
                    3 => vec![0, 2, 3],
                    _ => all_segments(),
                };
                // Forged: the producer vouches for itself, under its own key.
                let signature = match restoration_of(id, a, lender, &segments) {
                    Some(r) if forged => user_key(lender).sign(&restore_message(&sim_domain(), &r)),
                    _ => UNSIGNED,
                };
                vec![Command::CorroborateRestore {
                    job: id,
                    attempt: j.attempt,
                    lender,
                    segments,
                    signature,
                }]
            }
            Op::SilentNode { job, node } => self.silent_node(self.job(job), node),
            Op::LeaseStep { job, stage, step } => self.lease_step(self.job(job), stage, step),
            Op::NodeHeartbeat { job, node } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                let k = usize::from(node) % (a.lenders.len() + 1);
                vec![match a.lenders.get(k) {
                    Some(l) => Command::Heartbeat {
                        job: id,
                        attempt: j.attempt,
                        lender: *l,
                    },
                    None => Command::WitnessHeartbeat {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                    },
                }]
            }
            Op::Produce { job, wt, n } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = wt_of(wt);
                let Some(a) = j.current() else { return vec![] };
                let upto = a.produced[wt.idx()] + 1 + u32::from(n % 5);
                vec![Command::Produce {
                    job: id,
                    attempt: j.attempt,
                    wt,
                    upto,
                }]
            }
            Op::Ack { job, wt, n } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = wt_of(wt);
                let Some(a) = j.current() else { return vec![] };
                let lo = j.validated[wt.idx()];
                let hi = a.produced[wt.idx()];
                let upto = if hi > lo {
                    lo + 1 + u32::from(n) % (hi - lo)
                } else {
                    lo + u32::from(n % 2)
                };
                vec![Command::Ack {
                    job: id,
                    attempt: j.attempt,
                    wt,
                    upto,
                }]
            }
            Op::Commit {
                job,
                stage,
                wt,
                partial,
            } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                // Commitment on the current or previous attempt (late commitment).
                let attempt = if partial && j.attempt > 1 {
                    j.attempt - 1
                } else {
                    j.attempt
                };
                let Some(a) = j.attempts.get(&attempt) else {
                    return vec![];
                };
                let lender = pick(&a.lenders, stage);
                let wt = wt_of(wt);
                vec![Command::CommitReceipts {
                    job: id,
                    attempt,
                    lender,
                    wt,
                    upto: a.produced[wt.idx()],
                    digest: c.receipt_digest(id, attempt, lender, wt, a.produced[wt.idx()]),
                    signature: UNSIGNED,
                }]
            }
            Op::Claim {
                job,
                slice,
                stage,
                wt,
                pos,
                ev,
                honest,
            } => {
                let id = self.job(job);
                let Some(sid) = self.slice_of(id, slice) else {
                    return vec![];
                };
                let Ok(j) = c.job(id) else { return vec![] };
                let a = &j.attempts[&sid.attempt];
                let wt = wt_of(wt);
                let st = stage as usize % a.lenders.len();
                // Honest lender claims its own range; otherwise a random one.
                let lender = if honest {
                    a.lenders[st]
                } else {
                    pick(&LENDERS, stage.wrapping_add(pos))
                };
                let evidence = match ev % 4 {
                    0 | 1 => Evidence::Committed,
                    2 => Evidence::Uncommitted,
                    _ => Evidence::None,
                };
                // Honest: outputs actually validated on this attempt. Otherwise any position.
                let positions: Vec<u32> = if honest {
                    let mine: Vec<u32> = c
                        .delivery()
                        .outputs()
                        .iter()
                        .filter(|(o, at)| o.job == id && o.wt == wt && **at == sid.attempt)
                        .map(|(o, _)| o.pos)
                        .collect();
                    if mine.is_empty() {
                        return vec![];
                    }
                    (0..1 + usize::from(pos % 3))
                        .map(|k| mine[(usize::from(pos) + k) % mine.len()])
                        .collect()
                } else {
                    let max = j.max_outputs[wt.idx()].max(1);
                    (0..1 + u32::from(pos % 3))
                        .map(|k| (u32::from(pos) + k) % max)
                        .collect()
                };
                let items = positions
                    .into_iter()
                    .map(|p| ClaimItem::Contribution {
                        output: OutputId {
                            job: id,
                            wt,
                            pos: p,
                        },
                        stage: st as u32,
                        evidence,
                    })
                    .collect();
                let claim = Command::Claim {
                    slice: sid,
                    lender,
                    items,
                };
                // An honest lender has its uncommitted receipts co-signed; a dishonest one claims
                // without them.
                if honest {
                    self.presenting(claim)
                } else {
                    vec![claim]
                }
            }
            Op::ClaimRecovery {
                job,
                slice,
                stage,
                amount,
                ev,
            } => {
                let id = self.job(job);
                let Some(sid) = self.slice_of(id, slice) else {
                    return vec![];
                };
                let a = &c.jobs()[&id].attempts[&sid.attempt];
                let lender = pick(&a.lenders, stage);
                let evidence = if ev % 3 == 0 {
                    Evidence::Uncommitted
                } else {
                    Evidence::Committed
                };
                vec![Command::Claim {
                    slice: sid,
                    lender,
                    items: vec![ClaimItem::Recovery {
                        segment: u32::from(stage % 3),
                        amount: u64::from(amount % 9),
                        evidence,
                    }],
                }]
            }
            Op::StaleProduce { job } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                if j.attempt < 2 {
                    return vec![];
                }
                let old = j.attempt - 1;
                let p = j.attempts[&old].produced[1];
                vec![
                    Command::Produce {
                        job: id,
                        attempt: old,
                        wt: WorkType::Generate,
                        upto: p + 1,
                    },
                    Command::Ack {
                        job: id,
                        attempt: old,
                        wt: WorkType::Generate,
                        upto: p + 1,
                    },
                ]
            }
            Op::Close { job, slice } => self
                .slice_of(self.job(job), slice)
                .map(|s| vec![Command::CloseSlice { slice: s }])
                .unwrap_or_default(),
            Op::Evaluate { job, slice } => self
                .slice_of(self.job(job), slice)
                .map(|s| vec![Command::Evaluate { slice: s }])
                .unwrap_or_default(),
            Op::Arbitrate {
                job,
                slice,
                lender,
                pay,
            } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::Arbitrate {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                        pay,
                    }]
                })
                .unwrap_or_default(),
            Op::NodeLost(j) => vec![Command::NodeLost {
                job: self.job(j),
                expected_version: None,
            }],
            Op::Pause(j) => vec![Command::Pause {
                job: self.job(j),
                reason: PauseReason::Requested,
                expected_version: None,
            }],
            Op::Resume { job, topup } => {
                let id = self.job(job);
                let topup = if c.job(id).is_ok_and(|j| j.pool == CREDIT_POOL) {
                    u64::from(topup % 60)
                } else {
                    0
                };
                vec![Command::Resume { job: id, topup }]
            }
            Op::RecoveryTimeout(j) => vec![Command::RecoveryTimeout { job: self.job(j) }],
            Op::Fund { job, amount } => vec![Command::FundRecovery {
                job: self.job(job),
                amount: u64::from(amount % 20) + 1,
                signature: UNSIGNED,
            }],
            Op::Finish(j) => vec![Command::Finish {
                job: self.job(j),
                expected_version: None,
            }],
            Op::CompleteSettling(j) => vec![Command::CompleteSettling { job: self.job(j) }],
            Op::Cancel(j) => vec![Command::Cancel {
                job: self.job(j),
                expected_version: None,
            }],
            Op::Fail(j) => vec![Command::Fail { job: self.job(j) }],
            Op::Settle(j) => vec![Command::Settle { job: self.job(j) }],
            Op::Release { job, slice, lender } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::ReleaseReward {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                    }]
                })
                .unwrap_or_default(),
            Op::Contest { job, slice, lender } => self
                .slice_of(self.job(job), slice)
                .map(|s| {
                    vec![Command::ContestReward {
                        slice: s,
                        lender: pick(&LENDERS, lender),
                    }]
                })
                .unwrap_or_default(),
            Op::Reconcile => vec![Command::Reconcile],
            Op::Duplicate(i) => {
                // Duplicate delivery of a past command (retry, replayed outbox).
                let n = self.history.len();
                if n == 0 {
                    vec![]
                } else {
                    vec![self.history[i as usize % n].clone()]
                }
            }
            Op::Concurrent { job, pair } => {
                // Two commands computed from the same job version (JOB-R03).
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let ver = Some(j.version);
                let cancel = Command::Cancel {
                    job: id,
                    expected_version: ver,
                };
                let finish = Command::Finish {
                    job: id,
                    expected_version: ver,
                };
                let lost = Command::NodeLost {
                    job: id,
                    expected_version: ver,
                };
                let pause = Command::Pause {
                    job: id,
                    reason: PauseReason::Requested,
                    expected_version: ver,
                };
                match pair % 4 {
                    0 => vec![cancel, finish],
                    1 => vec![finish, cancel],
                    2 => vec![lost, pause],
                    _ => vec![cancel, lost],
                }
            }
            Op::Drive { job, sel } => self.drive(self.job(job), sel),
            Op::Heartbeat(j) => self.renew_all(self.job(j)),
            Op::Deliver { job, wt, n, forged } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let Some(a) = j.current() else { return vec![] };
                let wt = wt_of(wt);
                let t = wt.idx();
                // Sometimes beyond what was produced (rejected), mostly within the window.
                let upto = j.delivered[t] + 1 + u32::from(n % 4);
                let witness = if forged {
                    pick(&a.lenders, n)
                } else {
                    a.witness
                };
                // Substituted frame, or a valid frame from another session (JOB-R34).
                let digest = match n % 7 {
                    0 => c.frame_digest(id, wt, upto) ^ 1,
                    1 => c.frame_digest(pick(&JOBS, n.wrapping_add(1)), wt, upto),
                    _ => c.frame_digest(id, wt, upto),
                };
                vec![Command::Deliver {
                    job: id,
                    attempt: j.attempt,
                    witness,
                    wt,
                    upto,
                    digest,
                }]
            }
            Op::Confirm { job, wt, sel } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let wt = WorkType::ALL
                    .into_iter()
                    .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
                    .unwrap_or_else(|| wt_of(wt));
                let t = wt.idx();
                let (v, d) = (j.validated[t], j.delivered[t]);
                let confirmed = match sel % 4 {
                    0 => d,
                    1 => v,
                    2 => v + (d - v) / 2,
                    // Lie: the client claims more than was delivered.
                    _ => d + 1,
                };
                // Sometimes a statement signed in another session (JOB-R34).
                let digest = if (sel / 4) % 5 == 0 {
                    c.frame_digest(pick(&JOBS, sel.wrapping_add(1)), wt, confirmed)
                } else {
                    c.frame_digest(id, wt, confirmed)
                };
                vec![Command::ConfirmDelivery {
                    job: id,
                    wt,
                    confirmed,
                    digest,
                }]
            }
            Op::WitnessLost { job, prev } => {
                let id = self.job(job);
                let Ok(j) = c.job(id) else { return vec![] };
                let attempt = if prev && j.attempt > 1 {
                    j.attempt - 1
                } else {
                    j.attempt
                };
                if attempt == 0 {
                    return vec![];
                }
                vec![Command::WitnessLost { job: id, attempt }]
            }
            Op::DeliverAndSettle { job, sel } => self.deliver_and_settle(job, sel),
            Op::UncommittedBurst { job, sel } => self.uncommitted_burst(job, sel),
            Op::ContestUnderLiveResume { job } => self.contest_under_live_resume(job),
            Op::LateDeliver { job, commit_first } => self.late_deliver(job, commit_first),
            Op::ClientHeartbeat(j) => vec![Command::ClientHeartbeat { job: self.job(j) }],
            Op::ContestAtWindowEnd { job } => self.contest_at_window_end(job),
            Op::BoundaryBurst { job, sel } => self.boundary_burst(self.job(job), sel),
            Op::ContestReplay { job, sel } => self.contest_replay(job, sel),
            Op::PurgeBuffer { job, prev } => self.purge_buffer(job, prev),
            Op::Supplement { job, sel, honest } => self.supplement(job, sel, honest),
            Op::ArbitrateDisputed { job, sel } => self.arbitrate_disputed(job, sel),
            Op::DoubleFault { job, kind } => self.double_fault(job, kind),
            Op::CrossAttemptClaim {
                job,
                slice,
                stage,
                pos,
            } => self.cross_attempt_claim(job, slice, stage, pos),
        }
    }
}
