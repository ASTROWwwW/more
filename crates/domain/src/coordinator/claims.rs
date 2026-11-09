//! Lender claims, supplementary proofs and slice closure (JOB-S03, JOB-R24, JOB-R35).

use super::*;

impl Coordinator {
    pub(super) fn claim(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        items: &[ClaimItem],
    ) -> R<Outcome> {
        let now = self.now;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        match s.status {
            SliceStatus::Open => {}
            SliceStatus::Draining => {
                if now > s.receipt_deadline.unwrap_or(0) {
                    return Err(DomainError::Precondition(
                        "JOB-S03: receipt deadline passed",
                    ));
                }
            }
            from => {
                return Err(DomainError::InvalidSliceTransition {
                    from,
                    rule: "claim",
                })
            }
        }
        let j = self.job(slice.job)?;
        let a = j
            .attempts
            .get(&slice.attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if !a.lenders.contains(&lender) {
            return Err(DomainError::Precondition("lender not in attempt"));
        }
        if items.is_empty() {
            return Err(DomainError::Precondition("empty claim"));
        }
        // JOB-R12 (b): while draining, at most "flow budget" uncommitted items per type.
        if s.status == SliceStatus::Draining {
            for wt in WorkType::ALL {
                let already = s
                    .staged
                    .iter()
                    .filter(|c| c.lender == lender && matches!(c.item, ClaimItem::Contribution { output, evidence: Evidence::Uncommitted, .. } if output.wt == wt))
                    .count();
                let new = items
                    .iter()
                    .filter(|i| matches!(i, ClaimItem::Contribution { output, evidence: Evidence::Uncommitted, .. } if output.wt == wt))
                    .count();
                if (already + new) as u32 > self.cfg.flow_budget[wt.idx()] {
                    return Err(DomainError::FlowBudgetExceeded);
                }
            }
        }
        let s = self.slice_mut(slice)?;
        for item in items {
            s.staged.push(StagedClaim {
                lender,
                item: *item,
            });
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R35: stronger proof, before the evaluation deadline.
    pub(super) fn supplement_evidence(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: Evidence,
    ) -> R<Outcome> {
        let now = self.now;
        let deadline = self.cfg.evaluation_deadline;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        let open = matches!(s.status, SliceStatus::Closed | SliceStatus::Disputed)
            && now < s.closed_at.unwrap_or(0) + deadline;
        if !open {
            return Err(DomainError::Precondition(
                "JOB-R35: evaluation deadline passed",
            ));
        }
        let line = s
            .lines
            .get(&lender)
            .ok_or(DomainError::Precondition("no line"))?;
        let idx = line
            .items
            .iter()
            .position(|i| {
                matches!(i.kind, ItemKind::Contribution(cid) if cid.output == output)
                    && (i.status == ItemStatus::PendingEvaluation || i.awaiting_delivery)
            })
            .ok_or(DomainError::Precondition("JOB-R35: no undecided item"))?;
        if evidence.rank() <= line.items[idx].evidence.rank() {
            return Ok(Outcome::AlreadyApplied);
        }
        self.line_mut(slice, lender)?.items[idx].evidence = evidence;
        self.audit.push(AuditEvent::EvidenceSupplemented {
            slice,
            lender,
            output,
            evidence,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-S03: closes the slice and reserves all claimed amounts atomically (JOB-R24).
    pub(super) fn close_slice(&mut self, slice: SliceId) -> R<Outcome> {
        let now = self.now;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?
            .clone();
        let j = self.job(slice.job)?.clone();
        let a = j
            .attempts
            .get(&slice.attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?
            .clone();
        let normal_close = match s.status {
            SliceStatus::Open => {
                // An open slice always belongs to the live attempt.
                if j.attempt != slice.attempt
                    || a.revoked_at.is_some()
                    || j.exec != ExecStatus::Running
                {
                    return Err(DomainError::Internal(
                        "open slice on a revoked attempt".into(),
                    ));
                }
                true
            }
            SliceStatus::Draining => {
                if now < s.receipt_deadline.unwrap_or(0) {
                    return Err(DomainError::Precondition(
                        "JOB-S03: drain window still open",
                    ));
                }
                false
            }
            from => {
                return Err(DomainError::InvalidSliceTransition {
                    from,
                    rule: "JOB-S03",
                })
            }
        };
        let mut recovery_reserved = a.recovery_reserved;
        let mut rejected = 0u32;
        let mut lines: BTreeMap<AccountId, Line> = BTreeMap::new();
        for StagedClaim { lender, item } in &s.staged {
            let reserved = match *item {
                ClaimItem::Contribution {
                    output,
                    stage,
                    evidence,
                } => {
                    let stage = stage as usize;
                    let ok_binding = output.job == slice.job
                        && self.delivery.outputs().get(&output) == Some(&slice.attempt);
                    let ok_stage = stage < a.layout.len() && a.lenders.get(stage) == Some(lender);
                    let range = a.layer_range(stage);
                    if let (true, Some((ls, le))) = (ok_binding && ok_stage, range) {
                        let cid = ContributionId {
                            output,
                            charge: self.delivery.generation(output),
                            layer_start: ls,
                            layer_end: le,
                            role: ContributionRole::Executor,
                        };
                        if self.contributions.contains_key(&cid) {
                            None
                        } else {
                            let amount = j.share(&a, output.wt, stage).ok_or_else(|| {
                                DomainError::Internal("share of a missing stage".into())
                            })?;
                            self.ledger_op(LedgerOp::ReserveLine {
                                line: line_ref(slice, *lender),
                                source: LineSource::OutputHold,
                                key: format!("claim/{:?}/{}/{:?}", slice, lender.0, cid),
                                amount,
                            })?;
                            self.contributions.insert(cid, slice);
                            Some((ItemKind::Contribution(cid), amount, evidence))
                        }
                    } else {
                        None
                    }
                }
                ClaimItem::Recovery {
                    segment,
                    amount,
                    evidence,
                } => {
                    let rid = RecoveryWorkId {
                        job: slice.job,
                        attempt: slice.attempt,
                        segment,
                    };
                    let fits = recovery_reserved
                        .checked_add(amount)
                        .is_some_and(|t| t <= a.recovery_earmark);
                    if !a.ready || self.recovery_items.contains_key(&rid) || !fits || amount == 0 {
                        None
                    } else {
                        self.ledger_op(LedgerOp::ReserveLine {
                            line: line_ref(slice, *lender),
                            source: LineSource::Recovery,
                            key: format!("claim/{:?}/{}/{:?}", slice, lender.0, rid),
                            amount,
                        })?;
                        recovery_reserved = add(recovery_reserved, amount, "recovery reserved")?;
                        self.recovery_items.insert(rid, slice);
                        Some((ItemKind::Recovery(rid), amount, evidence))
                    }
                }
            };
            match reserved {
                None => rejected += 1,
                Some((kind, amount, evidence)) => {
                    let line = lines.entry(*lender).or_default();
                    line.claimed = add(line.claimed, amount, "claimed")?;
                    line.pending = add(line.pending, amount, "pending")?;
                    line.items.push(LineItem {
                        kind,
                        amount,
                        evidence,
                        status: ItemStatus::PendingEvaluation,
                        pool_part: 0,
                        reward_done: false,
                        awaiting_delivery: false,
                    });
                    self.audit.push(AuditEvent::ItemReserved {
                        slice,
                        lender: *lender,
                        kind,
                        amount,
                    });
                }
            }
        }
        self.attempt_mut(slice.job, slice.attempt)?
            .recovery_reserved = recovery_reserved;
        let sm = self.slice_mut(slice)?;
        sm.staged.clear();
        sm.lines = lines;
        sm.rejected_items += rejected;
        self.set_slice(slice, SliceStatus::Closed, "JOB-S03")?;
        if normal_close {
            // JOB-T07: the attempt continues on a new slice.
            self.open_slice(slice.job, slice.attempt)?;
        }
        Ok(Outcome::Applied)
    }
}
