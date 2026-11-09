//! Multi-step operations on the normal path: drive a job forward, honest claims, client
//! statements, impersonation candidates.

use super::*;

impl Sim {
    /// Next normal step for a job, given its state.
    pub(super) fn drive(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        // Advance slices first, whatever the job state.
        let mut slice_work = Vec::new();
        for s in c.slices().values().filter(|s| s.id.job == id) {
            match s.status {
                SliceStatus::Closed => slice_work.push(Command::Evaluate { slice: s.id }),
                SliceStatus::Disputed => {
                    let arbitrable = s.lines.iter().find(|(_, l)| {
                        l.items
                            .iter()
                            .any(|i| i.status == ItemStatus::Disputed && !i.awaiting_delivery)
                    });
                    if let Some((l, _)) = arbitrable {
                        // A human arbiter rules before the deadline (JOB-S06).
                        return vec![Command::Arbitrate {
                            slice: s.id,
                            lender: *l,
                            pay: sel.is_multiple_of(2),
                        }];
                    }
                }
                SliceStatus::Final => {
                    if let Some((l, _)) = s.lines.iter().find(|(_, l)| l.held > 0) {
                        let open = s
                            .final_at
                            .is_some_and(|f| c.now() < f + c.config().reward_window);
                        if !open {
                            slice_work.push(Command::ReleaseReward {
                                slice: s.id,
                                lender: *l,
                            });
                        } else if sel.is_multiple_of(4) {
                            // Fraud found during the window (JOB-R22).
                            slice_work.push(Command::ContestReward {
                                slice: s.id,
                                lender: *l,
                            });
                        }
                    }
                }
                SliceStatus::Draining => {
                    // The lender still online presents its receipts (JOB-F16).
                    if let Some(cmd) = self.honest_claim(s.id, sel) {
                        slice_work.push(cmd);
                    }
                    if c.now() >= s.receipt_deadline.unwrap_or(0) {
                        slice_work.push(Command::CloseSlice { slice: s.id });
                    }
                }
                SliceStatus::Open => {}
            }
        }
        if !slice_work.is_empty() && sel.is_multiple_of(3) {
            return vec![slice_work[usize::from(sel) % slice_work.len()].clone()];
        }
        match j.exec {
            ExecStatus::Queued => vec![Command::Reserve { job: id }],
            ExecStatus::Reserved | ExecStatus::Recovering => {
                let lenders = (0..layout_of(id).len())
                    .map(|k| LENDERS[(k + usize::from(sel)) % LENDERS.len()])
                    .collect();
                let est = if j.intent == Intent::Resume {
                    u64::from(sel % 6)
                } else {
                    0
                };
                let mut v = self.client_confirm(id, sel);
                v.push(Command::Place {
                    job: id,
                    lenders,
                    layout: layout_of(id),
                    recovery_estimate: est,
                    witness: WITNESS,
                    expected_version: None,
                });
                v
            }
            ExecStatus::Placing => vec![
                Command::Heartbeat {
                    job: id,
                    attempt: j.attempt,
                },
                Command::AttemptReady {
                    job: id,
                    attempt: j.attempt,
                    restored: j.delivered,
                },
            ],
            ExecStatus::Paused => {
                let mut v = self.client_confirm(id, sel);
                v.push(Command::Resume {
                    job: id,
                    topup: if j.pool == CREDIT_POOL { 30 } else { 0 },
                });
                v
            }
            ExecStatus::Settling => {
                let mut v = self.client_confirm(id, sel);
                v.extend([
                    Command::Tick {
                        dt: c.config().drain_window + 1,
                    },
                    Command::Reconcile,
                ]);
                v
            }
            ExecStatus::Running => {
                let a = j.current().expect("running has an attempt");
                let wt = pick(&WorkType::ALL, sel / 7);
                let t = wt.idx();
                let open = c
                    .slices()
                    .values()
                    .find(|s| {
                        s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open
                    })
                    .map(|s| s.id);
                // Healthy cluster: renews its lease at every step.
                let hb = Command::Heartbeat {
                    job: id,
                    attempt: j.attempt,
                };
                let step: Vec<Command> = match sel % 10 {
                    0 | 1 => vec![Command::Produce {
                        job: id,
                        attempt: j.attempt,
                        wt,
                        upto: (a.produced[t] + 1 + u32::from(sel % 3)).min(j.max_outputs[t]),
                    }],
                    2 => vec![Command::Ack {
                        job: id,
                        attempt: j.attempt,
                        wt,
                        upto: a.produced[t],
                    }],
                    // The witness attests; the client does not ack right away.
                    3 => vec![Command::Deliver {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                        digest: c.frame_digest(id, wt, a.produced[t]),
                    }],
                    // The witness only sends its short commitment (JOB-R32).
                    9 => vec![Command::WitnessCommit {
                        job: id,
                        attempt: j.attempt,
                        witness: a.witness,
                        wt,
                        upto: a.produced[t],
                    }],
                    4 => a
                        .lenders
                        .iter()
                        .map(|l| Command::CommitReceipts {
                            job: id,
                            attempt: j.attempt,
                            lender: *l,
                            wt,
                            upto: a.produced[t],
                            digest: c.receipt_digest(id, j.attempt, *l, wt, a.produced[t]),
                        })
                        .collect(),
                    5 | 6 => open
                        .and_then(|s| self.honest_claim(s, sel))
                        .into_iter()
                        .collect(),
                    7 => {
                        let mut v: Vec<Command> = open
                            .map(|s| Command::CloseSlice { slice: s })
                            .into_iter()
                            .collect();
                        if j.delivered == a.produced && sel.is_multiple_of(2) {
                            v.push(Command::Finish {
                                job: id,
                                expected_version: None,
                            });
                        }
                        v
                    }
                    _ => {
                        // Recovery claimed by the replacement (JOB-R18).
                        if a.recovery_earmark > a.recovery_reserved {
                            open.map(|s| Command::Claim {
                                slice: s,
                                lender: a.lenders[0],
                                items: vec![ClaimItem::Recovery {
                                    segment: u32::from(sel % 4),
                                    amount: (a.recovery_earmark - a.recovery_reserved).min(3),
                                    evidence: Evidence::Committed,
                                }],
                            })
                            .into_iter()
                            .collect()
                        } else {
                            vec![Command::Ack {
                                job: id,
                                attempt: j.attempt,
                                wt,
                                upto: a.produced[t],
                            }]
                        }
                    }
                };
                let mut v = vec![hb];
                v.extend(step);
                v
            }
            _ => {
                let mut v = self.client_confirm(id, sel);
                v.extend(slice_work.into_iter().take(1));
                v
            }
        }
    }

    /// Client statement on its provisional outputs (JOB-R28): usually "all received", sometimes
    /// "nothing after validated".
    pub(super) fn client_confirm(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        // The client talks about the type that has provisional outputs, if any.
        let Some(wt) = WorkType::ALL
            .into_iter()
            .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
        else {
            return vec![];
        };
        let t = wt.idx();
        if sel % 4 == 3 {
            return vec![];
        }
        let confirmed = if sel.is_multiple_of(3) {
            j.validated[t]
        } else {
            j.delivered[t]
        };
        vec![Command::ConfirmDelivery {
            job: id,
            wt,
            confirmed,
            digest: c.frame_digest(id, wt, confirmed),
        }]
    }

    /// Honest claim: an attempt's lender claims its range for outputs validated on that attempt and
    /// not claimed yet.
    pub(super) fn honest_claim(&self, slice: SliceId, sel: u8) -> Option<Command> {
        // An honest lender sometimes sends its claim before its proof comes back, and supplements
        // it before the deadline (JOB-R35).
        let evidence = match sel % 7 {
            0 => Evidence::Uncommitted,
            1 => Evidence::None,
            _ => Evidence::Committed,
        };
        self.honest_claim_with(slice, sel, evidence)
    }

    pub(super) fn honest_claim_with(
        &self,
        slice: SliceId,
        sel: u8,
        evidence: Evidence,
    ) -> Option<Command> {
        let c = &self.coord;
        let j = c.job(slice.job).ok()?;
        let a = j.attempts.get(&slice.attempt)?;
        let stage = usize::from(sel) % a.lenders.len();
        let lender = a.lenders[stage];
        let (ls, le) = a.layer_range(stage)?;
        let staged: Vec<OutputId> = c.slices()[&slice]
            .staged
            .iter()
            .filter(|s| s.lender == lender)
            .filter_map(|s| match s.item {
                ClaimItem::Contribution { output, .. } => Some(output),
                _ => None,
            })
            .collect();
        let todo: Vec<OutputId> = c
            .delivery()
            .outputs()
            .iter()
            .filter(|(o, at)| o.job == slice.job && **at == slice.attempt)
            .map(|(o, _)| *o)
            .filter(|o| {
                !c.contributions().contains_key(&ContributionId {
                    output: *o,
                    charge: c.delivery().charges()[o].gen,
                    layer_start: ls,
                    layer_end: le,
                    role: ContributionRole::Executor,
                })
            })
            .filter(|o| !staged.contains(o))
            .take(3)
            .collect();
        if todo.is_empty() {
            return None;
        }
        Some(Command::Claim {
            slice,
            lender,
            items: todo
                .into_iter()
                .map(|o| ClaimItem::Contribution {
                    output: o,
                    stage: stage as u32,
                    evidence,
                })
                .collect(),
        })
    }

    /// A command that makes sense in the current state, to be sent by someone else.
    pub(super) fn impersonated(&self, job: u8, sel: u8) -> Option<Command> {
        let id = self.job(job);
        let fixed = match sel % 8 {
            0 => Some(Command::Issue {
                id: 900 + u32::from(sel),
                to: IssueTarget::User(STRANGER),
                amount: 1_000,
            }),
            1 => Some(Command::Cancel {
                job: id,
                expected_version: None,
            }),
            2 => Some(Command::FundRecovery { job: id, amount: 5 }),
            3 => Some(Command::SetRights {
                pool: CREDIT_POOL,
                account: STRANGER,
                rights: Rights {
                    borrow: true,
                    lend: true,
                    witness: true,
                },
            }),
            _ => None,
        };
        fixed.or_else(|| {
            self.resolve(&Op::Drive { job, sel })
                .into_iter()
                .find(|c| !matches!(c, Command::Tick { .. }))
        })
    }
}
