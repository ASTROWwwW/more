//! Adversarial multi-step operations: delivery disputes, late proofs, receipt bursts at the cap's
//! boundary, double faults, cross-attempt claims.

use super::*;

impl Sim {
    /// Claim without proof, close, evaluate (deferred), then supplement: committed if it exists
    /// (honest), wrongly claimed otherwise.
    pub(super) fn late_proof(&self, id: JobId, sel: u8, honest: bool) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        if j.exec != ExecStatus::Running {
            return vec![];
        }
        let Some(open) = c
            .slices()
            .values()
            .find(|s| s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open)
            .map(|s| s.id)
        else {
            return vec![];
        };
        let Some(Command::Claim {
            slice,
            lender,
            items,
        }) = self.honest_claim_with(open, sel, Evidence::None)
        else {
            return vec![];
        };
        let mut out = vec![
            Command::Claim {
                slice,
                lender,
                items: items.clone(),
            },
            Command::CloseSlice { slice },
            Command::Evaluate { slice },
        ];
        for it in items {
            if let ClaimItem::Contribution { output, .. } = it {
                if !honest || c.committed_before(slice, lender, output.wt, output.pos) {
                    out.push(Command::SupplementEvidence {
                        slice,
                        lender,
                        output,
                        evidence: Evidence::Committed,
                    });
                }
            }
        }
        out
    }

    /// Two bursts of uncommitted receipts around a multiple of 24 h, with the first reward
    /// contested in between (JOB-R19).
    pub(super) fn boundary_burst(&self, id: JobId, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let Ok(j) = c.job(id) else { return vec![] };
        if j.exec != ExecStatus::Running {
            return vec![];
        }
        let mut tmp = self.scratch(c.clone());
        let mut out = Vec::new();
        let mut step = |tmp: &mut Sim, cmd: Command| {
            tmp.quiet(&cmd);
            out.push(cmd);
        };
        let w = c.config().uncommitted_window;
        // Between 10 and 59 s before the next multiple of 24 h.
        let dt = (w - c.now() % w)
            .saturating_sub(10 + u64::from(sel % 50))
            .max(1);
        step(&mut tmp, Command::Tick { dt });
        for round in 0..2 {
            let attempt = tmp.coord.jobs()[&id].attempt;
            let Some(open) = tmp
                .coord
                .slices()
                .values()
                .find(|s| {
                    s.id.job == id && s.id.attempt == attempt && s.status == SliceStatus::Open
                })
                .map(|s| s.id)
            else {
                break;
            };
            // The lender with the smallest share is the one that can reach the cap.
            let last = (layout_of(id).len() - 1) as u8;
            let Some(Command::Claim {
                slice,
                lender,
                mut items,
            }) = tmp.honest_claim_with(open, last, Evidence::Uncommitted)
            else {
                break;
            };
            // One receipt before midnight, two after, so outputs remain to claim.
            items.truncate(if round == 0 { 1 } else { 2 });
            step(
                &mut tmp,
                Command::Claim {
                    slice,
                    lender,
                    items,
                },
            );
            step(&mut tmp, Command::CloseSlice { slice });
            step(&mut tmp, Command::Evaluate { slice });
            if round == 0 {
                step(&mut tmp, Command::ContestReward { slice, lender });
                step(&mut tmp, Command::Tick { dt: 60 });
            }
        }
        out
    }

    pub(super) fn deliver_and_settle(&self, job: u8, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        let Some(a) = j.current() else { return vec![] };
        if j.exec != ExecStatus::Running || a.revoked_at.is_some() {
            return vec![];
        }
        let wt = WorkType::ALL
            .into_iter()
            .find(|w| a.produced[w.idx()] > j.delivered[w.idx()])
            .unwrap_or(WorkType::Generate);
        let t = wt.idx();
        let Some(open) = c
            .slices()
            .values()
            .find(|s| s.id.job == id && s.id.attempt == j.attempt && s.status == SliceStatus::Open)
            .map(|s| s.id)
        else {
            return vec![];
        };
        let mut v = vec![
            Command::Heartbeat {
                job: id,
                attempt: j.attempt,
            },
            Command::Deliver {
                job: id,
                attempt: j.attempt,
                witness: a.witness,
                wt,
                upto: a.produced[t],
                digest: c.frame_digest(id, wt, a.produced[t]),
            },
        ];
        for l in &a.lenders {
            v.push(Command::CommitReceipts {
                job: id,
                attempt: j.attempt,
                lender: *l,
                wt,
                upto: a.produced[t],
                digest: c.receipt_digest(id, j.attempt, *l, wt, a.produced[t]),
            });
        }
        // Claims are computed on the current state, so target every bound output ahead of
        // the attestation.
        let mut tmp = self.scratch(c.clone());
        for cmd in &v {
            tmp.quiet(cmd);
        }
        for k in 0..a.lenders.len() as u8 {
            if let Some(cl) = tmp.honest_claim_with(open, sel.wrapping_add(k), Evidence::Committed)
            {
                tmp.quiet(&cl);
                v.push(cl);
            }
        }
        v.push(Command::CloseSlice { slice: open });
        v.push(Command::Evaluate { slice: open });
        v
    }

    pub(super) fn uncommitted_burst(&self, job: u8, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let live: Vec<SliceId> = c
            .slices()
            .values()
            .filter(|s| {
                s.id.job == id && matches!(s.status, SliceStatus::Open | SliceStatus::Draining)
            })
            .map(|s| s.id)
            .collect();
        if live.is_empty() {
            return vec![];
        }
        let sid = live[usize::from(sel) % live.len()];
        let st = c.slices()[&sid].status;
        let mut v: Vec<Command> = self
            .honest_claim_with(sid, sel, Evidence::Uncommitted)
            .into_iter()
            .collect();
        if st == SliceStatus::Open {
            v.push(Command::CloseSlice { slice: sid });
            v.push(Command::Evaluate { slice: sid });
        }
        v
    }

    pub(super) fn contest_under_live_resume(&self, job: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        let Some(a) = j.current() else { return vec![] };
        if j.exec != ExecStatus::Running || a.revoked_at.is_some() {
            return vec![];
        }
        let Some(wt) = WorkType::ALL
            .into_iter()
            .find(|w| a.produced[w.idx()] > j.validated[w.idx()])
        else {
            return vec![];
        };
        let t = wt.idx();
        let mut delivered = j.delivered;
        delivered[t] = a.produced[t];
        let lenders: Vec<AccountId> = a.lenders.iter().rev().copied().collect();
        vec![
            Command::Deliver {
                job: id,
                attempt: j.attempt,
                witness: a.witness,
                wt,
                upto: a.produced[t],
                digest: c.frame_digest(id, wt, a.produced[t]),
            },
            Command::WitnessLost {
                job: id,
                attempt: j.attempt,
            },
            Command::NodeLost {
                job: id,
                expected_version: None,
            },
            Command::Place {
                job: id,
                lenders,
                layout: layout_of(id),
                recovery_estimate: 0,
                witness: WITNESS,
                expected_version: None,
            },
            Command::AttemptReady {
                job: id,
                attempt: j.attempt + 1,
                restored: delivered,
            },
            Command::ConfirmDelivery {
                job: id,
                wt,
                confirmed: j.validated[t],
                digest: c.frame_digest(id, wt, j.validated[t]),
            },
        ]
    }

    pub(super) fn late_deliver(&self, job: u8, commit_first: bool) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        let Some(a) = j.current() else { return vec![] };
        let Some(wt) = WorkType::ALL
            .into_iter()
            .find(|w| a.produced[w.idx()] > j.delivered[w.idx()])
        else {
            return vec![];
        };
        let upto = a.produced[wt.idx()];
        let deliver = Command::Deliver {
            job: id,
            attempt: j.attempt,
            witness: a.witness,
            wt,
            upto,
            digest: c.frame_digest(id, wt, upto),
        };
        if a.revoked_at.is_some() {
            // After revocation, any commitment comes too late and proves nothing.
            let mut v = Vec::new();
            if commit_first {
                v.push(Command::WitnessCommit {
                    job: id,
                    attempt: j.attempt,
                    witness: a.witness,
                    wt,
                    upto,
                });
            }
            v.push(deliver);
            return v;
        }
        if j.exec != ExecStatus::Running {
            return vec![];
        }
        // Commitment (or not) before the fault, full attestation while draining.
        let mut v = vec![Command::Heartbeat {
            job: id,
            attempt: j.attempt,
        }];
        if commit_first {
            v.push(Command::WitnessCommit {
                job: id,
                attempt: j.attempt,
                witness: a.witness,
                wt,
                upto,
            });
        }
        v.push(Command::NodeLost {
            job: id,
            expected_version: None,
        });
        v.push(deliver);
        v
    }

    pub(super) fn contest_at_window_end(&self, job: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        let w = c.config().delivery_window;
        // An uncontested provisional output of a revoked attempt, window still open.
        let target = c.delivery().charges().iter().find_map(|(o, ch)| {
            let r = j.attempts.get(&ch.attempt)?.revoked_at?;
            (o.job == id && !ch.definitive && ch.contest.is_none() && c.now() + 60 < r + w)
                .then_some((o.wt, ch.attempt, r))
        });
        let Some((wt, attempt, r)) = target else {
            return vec![];
        };
        let t = wt.idx();
        vec![
            Command::Tick {
                dt: r + w - 60 - c.now(),
            },
            Command::ConfirmDelivery {
                job: id,
                wt,
                confirmed: j.validated[t],
                digest: c.frame_digest(id, wt, j.validated[t]),
            },
            Command::Tick { dt: 120 },
            Command::PurgeBuffer { job: id, attempt },
        ]
    }

    pub(super) fn contest_replay(&self, job: u8, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        let Some(wt) = WorkType::ALL
            .into_iter()
            .find(|w| j.delivered[w.idx()] > j.validated[w.idx()])
        else {
            return vec![];
        };
        let t = wt.idx();
        let (v, d) = (j.validated[t], j.delivered[t]);
        let confirmed = v + u32::from(sel) % (d - v);
        vec![Command::ConfirmDelivery {
            job: id,
            wt,
            confirmed,
            digest: c.frame_digest(id, wt, confirmed),
        }]
    }

    pub(super) fn purge_buffer(&self, job: u8, prev: bool) -> Vec<Command> {
        let c = &self.coord;
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
        vec![Command::PurgeBuffer { job: id, attempt }]
    }

    pub(super) fn supplement(&self, job: u8, sel: u8, honest: bool) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let mut cands = Vec::new();
        for s in c.slices().values().filter(|s| s.id.job == id) {
            for (l, line) in &s.lines {
                for it in &line.items {
                    if let ItemKind::Contribution(cid) = it.kind {
                        let undecided =
                            it.status == ItemStatus::PendingEvaluation || it.awaiting_delivery;
                        if undecided && it.evidence != Evidence::Committed {
                            let proven =
                                c.committed_before(s.id, *l, cid.output.wt, cid.output.pos);
                            if proven || !honest {
                                cands.push((s.id, *l, cid.output));
                            }
                        }
                    }
                }
            }
        }
        if cands.is_empty() {
            // No candidate: the lender claims without proof (it hasn't come back yet), the
            // slice closes, then it supplements (JOB-R35).
            return self.late_proof(id, sel, honest);
        }
        let (slice, lender, output) = cands[usize::from(sel) % cands.len()];
        vec![Command::SupplementEvidence {
            slice,
            lender,
            output,
            evidence: Evidence::Committed,
        }]
    }

    pub(super) fn arbitrate_disputed(&self, job: u8, sel: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let cands: Vec<(SliceId, AccountId)> = c
            .slices()
            .values()
            .filter(|s| {
                s.id.job == id && matches!(s.status, SliceStatus::Disputed | SliceStatus::Closed)
            })
            .flat_map(|s| {
                s.lines
                    .iter()
                    .filter(|(_, l)| {
                        l.items
                            .iter()
                            .any(|i| i.status == ItemStatus::Disputed && !i.awaiting_delivery)
                    })
                    .map(move |(l, _)| (s.id, *l))
            })
            .collect();
        if cands.is_empty() {
            return vec![];
        }
        let (slice, lender) = cands[usize::from(sel) % cands.len()];
        let mut v = Vec::new();
        // The arbiter waits for the end of evaluation (JOB-R35 deadline).
        if c.slices()[&slice].status == SliceStatus::Closed {
            v.push(Command::Tick {
                dt: c.config().evaluation_deadline,
            });
            v.push(Command::Reconcile);
        }
        v.push(Command::Arbitrate {
            slice,
            lender,
            pay: sel.is_multiple_of(2),
        });
        v
    }

    pub(super) fn double_fault(&self, job: u8, kind: u8) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Ok(j) = c.job(id) else { return vec![] };
        if kind.is_multiple_of(2) {
            // Silent client and expired lease at the same deadline.
            vec![
                Command::Tick {
                    dt: c.config().client_silence.max(c.config().lease_ttl),
                },
                Command::Reconcile,
            ]
        } else {
            vec![
                Command::WitnessLost {
                    job: id,
                    attempt: j.attempt.max(1),
                },
                Command::NodeLost {
                    job: id,
                    expected_version: None,
                },
            ]
        }
    }

    pub(super) fn cross_attempt_claim(
        &self,
        job: u8,
        slice: u8,
        stage: u8,
        pos: u8,
    ) -> Vec<Command> {
        let c = &self.coord;
        let id = self.job(job);
        let Some(sid) = self.slice_of(id, slice) else {
            return vec![];
        };
        let a = &c.jobs()[&id].attempts[&sid.attempt];
        let st = usize::from(stage) % a.lenders.len();
        let foreign: Vec<OutputId> = c
            .delivery()
            .outputs()
            .iter()
            .filter(|(o, at)| o.job == id && **at != sid.attempt)
            .map(|(o, _)| *o)
            .collect();
        if foreign.is_empty() {
            return vec![];
        }
        let o = foreign[usize::from(pos) % foreign.len()];
        vec![Command::Claim {
            slice: sid,
            lender: a.lenders[st],
            items: vec![ClaimItem::Contribution {
                output: o,
                stage: st as u32,
                evidence: Evidence::Committed,
            }],
        }]
    }
}
