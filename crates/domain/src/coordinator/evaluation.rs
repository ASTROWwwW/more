//! Slice evaluation: one decision per item, payments, refunds, items waiting for their output (JOB-S04, JOB-R19, JOB-R30).

use super::*;

impl Coordinator {
    /// Reserved items of one billing generation of an output.
    pub(super) fn items_of(&self, output: OutputId, gen: u32) -> Vec<(SliceId, AccountId, usize)> {
        let mut v = Vec::new();
        for (sid, s) in self.slices.iter().filter(|(k, _)| k.job == output.job) {
            for (lender, l) in &s.lines {
                for (idx, it) in l.items.iter().enumerate() {
                    if let ItemKind::Contribution(cid) = it.kind {
                        if cid.output == output && cid.charge == gen {
                            v.push((*sid, *lender, idx));
                        }
                    }
                }
            }
        }
        v
    }

    /// JOB-S04 decision for a reserved item, based on its proof.
    fn decide(&mut self, slice: SliceId, lender: AccountId, idx: usize) -> R<Decision> {
        let item = self.slices[&slice].lines[&lender].items[idx].clone();
        let attempt_ready = self.job(slice.job)?.attempts[&slice.attempt].ready;
        // JOB-R35: a refund for missing proof only becomes final at the evaluation deadline.
        let before_deadline =
            self.now < self.slices[&slice].closed_at.unwrap_or(0) + self.cfg.evaluation_deadline;
        let refund = |r: RefundReason| {
            if before_deadline {
                Decision::Defer
            } else {
                Decision::Refund(r)
            }
        };
        Ok(match (item.kind, item.evidence) {
            (ItemKind::Contribution(cid), _)
                if self.delivery.charge(cid.output).map(|c| c.gen) != Some(cid.charge) =>
            {
                // Output voided since reservation (JOB-R29).
                Decision::Refund(RefundReason::OutputVoided)
            }
            (ItemKind::Contribution(cid), _)
                if !self
                    .delivery
                    .charge(cid.output)
                    .is_some_and(|c| c.definitive) =>
            {
                // JOB-R30: never paid while its output is provisional.
                Decision::Await
            }
            (ItemKind::Contribution(cid), Evidence::Committed) => {
                if self.committed_before(slice, lender, cid.output.wt, cid.output.pos) {
                    Decision::Pay
                } else {
                    // Commitment claimed but not found: treated as no proof.
                    refund(RefundReason::EvidenceNotFound)
                }
            }
            (ItemKind::Recovery(_), Evidence::Committed) => {
                if attempt_ready {
                    Decision::Pay
                } else {
                    Decision::Refund(RefundReason::AttemptNotStarted)
                }
            }
            (ItemKind::Contribution(cid), Evidence::Uncommitted)
                if !self.receipt_covers(
                    slice.job,
                    slice.attempt,
                    lender,
                    cid.output.wt,
                    cid.output.pos,
                ) =>
            {
                // JOB-R12, LEDGER-016: an uncommitted receipt must be presented, signed by the
                // recipient; claimed but missing, it is no proof.
                refund(RefundReason::EvidenceNotFound)
            }
            (_, Evidence::Uncommitted) => {
                // JOB-R19: sliding cap on gross admitted amounts.
                let now = self.now;
                let w = self.cfg.uncommitted_window;
                let log = self.uncommitted_paid.entry(lender).or_default();
                let recent = log
                    .iter()
                    .filter(|(t, _)| t + w > now)
                    .try_fold(0u64, |acc, (_, a)| acc.checked_add(*a))
                    .ok_or(DomainError::Overflow("sliding cap"))?;
                if add(recent, item.amount, "sliding cap")? <= self.cfg.uncommitted_cap {
                    log.push((now, item.amount));
                    Decision::Pay
                } else {
                    Decision::Dispute
                }
            }
            (_, Evidence::None) => refund(RefundReason::NoEvidence),
        })
    }

    /// JOB-S04: evaluates a closed slice.
    pub(super) fn evaluate(&mut self, slice: SliceId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?
            .clone();
        if s.status != SliceStatus::Closed {
            return Err(DomainError::InvalidSliceTransition {
                from: s.status,
                rule: "JOB-S04",
            });
        }
        let mut changed = false;
        let mut deferred = false;
        for (lender, line) in &s.lines {
            for (idx, item) in line.items.iter().enumerate() {
                // CE-04: an item already decided since closure is not evaluated again.
                if item.status != ItemStatus::PendingEvaluation {
                    continue;
                }
                let decision = self.decide(slice, *lender, idx)?;
                match decision {
                    Decision::Pay => self.pay_item(slice, *lender, idx, false)?,
                    Decision::Refund(r) => self.refund_item(slice, *lender, idx, r)?,
                    Decision::Defer => {
                        deferred = true;
                        continue;
                    }
                    Decision::Dispute | Decision::Await => {
                        let awaiting = matches!(decision, Decision::Await);
                        let l = self.line_mut(slice, *lender)?;
                        l.pending = sub(l.pending, item.amount, "pending")?;
                        l.disputed = add(l.disputed, item.amount, "disputed")?;
                        l.items[idx].status = ItemStatus::Disputed;
                        l.items[idx].awaiting_delivery = awaiting;
                        self.audit.push(if awaiting {
                            AuditEvent::ItemAwaitingDelivery {
                                slice,
                                lender: *lender,
                                kind: item.kind,
                                amount: item.amount,
                            }
                        } else {
                            AuditEvent::ItemDisputed {
                                slice,
                                lender: *lender,
                                kind: item.kind,
                                amount: item.amount,
                            }
                        });
                    }
                }
                changed = true;
            }
        }
        // JOB-R35: while an item waits for proof, the slice stays closed until the deadline at
        // most. CE-06: same while a contribution still waits for its output, since it may go back
        // to pending.
        let before_deadline = self.now < s.closed_at.unwrap_or(0) + self.cfg.evaluation_deadline;
        let awaiting = self.slices[&slice]
            .lines
            .values()
            .any(|l| l.items.iter().any(|i| i.awaiting_delivery));
        if deferred || (before_deadline && awaiting) {
            return Ok(if changed {
                Outcome::Applied
            } else {
                Outcome::AlreadyApplied
            });
        }
        let disputed = self.slices[&slice].lines.values().any(|l| l.disputed > 0);
        let to = if disputed {
            SliceStatus::Disputed
        } else {
            SliceStatus::Final
        };
        self.set_slice(slice, to, "JOB-S04")?;
        self.maybe_return_earmark(slice.job, slice.attempt)?;
        Ok(Outcome::Applied)
    }

    /// JOB-R30: the output became definitive; its waiting contributions are evaluated under the
    /// usual JOB-S04 rules.
    pub(super) fn resolve_awaiting(&mut self, output: OutputId) -> R {
        let Some(ch) = self.delivery.charge(output).copied() else {
            return Ok(());
        };
        let mut touched = Vec::new();
        for (slice, lender, idx) in self.items_of(output, ch.gen) {
            let it = &self.slices[&slice].lines[&lender].items[idx];
            if !(it.status == ItemStatus::Disputed && it.awaiting_delivery) {
                continue;
            }
            self.line_mut(slice, lender)?.items[idx].awaiting_delivery = false;
            match self.decide(slice, lender, idx)? {
                Decision::Pay => self.pay_item(slice, lender, idx, false)?,
                Decision::Refund(r) => self.refund_item(slice, lender, idx, r)?,
                Decision::Dispute => {
                    let it = &self.slices[&slice].lines[&lender].items[idx];
                    self.audit.push(AuditEvent::ItemDisputed {
                        slice,
                        lender,
                        kind: it.kind,
                        amount: it.amount,
                    });
                }
                Decision::Defer => {
                    // JOB-R35: before the deadline the item goes back to pending, so a stronger
                    // proof can still come.
                    let l = self.line_mut(slice, lender)?;
                    let amount = l.items[idx].amount;
                    l.disputed = sub(l.disputed, amount, "disputed")?;
                    l.pending = add(l.pending, amount, "pending")?;
                    l.items[idx].status = ItemStatus::PendingEvaluation;
                }
                Decision::Await => {
                    return Err(DomainError::Internal("await after resolution".into()))
                }
            }
            touched.push(slice);
        }
        for s in touched {
            self.maybe_finalize_disputed(s)?;
        }
        Ok(())
    }

    pub(super) fn maybe_finalize_disputed(&mut self, slice: SliceId) -> R {
        let s = &self.slices[&slice];
        if s.status == SliceStatus::Disputed && s.lines.values().all(|l| l.disputed == 0) {
            self.set_slice(slice, SliceStatus::Final, "JOB-R30")?;
            self.maybe_return_earmark(slice.job, slice.attempt)?;
        }
        Ok(())
    }

    pub(super) fn pay_item(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        idx: usize,
        by_arbitration: bool,
    ) -> R {
        let (kind, amount, evidence) = {
            let l = &self.slices[&slice].lines[&lender];
            (
                l.items[idx].kind,
                l.items[idx].amount,
                l.items[idx].evidence,
            )
        };
        let item = self.item_id(slice, kind)?;
        let paid = self.ledger_op(LedgerOp::PayLine {
            line: line_ref(slice, lender),
            item,
        })?;
        // CE-02, JOB-R18: borrower budget first, then pool relay.
        let mut pool_part = 0;
        if let ItemKind::Recovery(_) = kind {
            let j = self.job_mut(slice.job)?;
            let left = sub(
                j.recovery_budget,
                j.recovery_paid_borrower,
                "borrower budget",
            )?;
            let from_borrower = amount.min(left);
            pool_part = amount - from_borrower;
            let pool_paid = add(j.recovery_paid_pool, pool_part, "pool relay paid")?;
            if pool_paid > j.pool_recovery_funded {
                return Err(DomainError::Internal(
                    "recovery paid beyond borrower budget and pool relay".into(),
                ));
            }
            j.recovery_paid_borrower = add(j.recovery_paid_borrower, from_borrower, "paid")?;
            j.recovery_paid_pool = pool_paid;
        }
        // The ledger splits recovery from its own records (LEDGER-013); it must agree.
        if paid != (LedgerOutcome::Paid { amount, pool_part }) {
            return Err(DomainError::Internal(format!(
                "payment of {kind:?}: ledger {paid:?}, coordinator {amount}/{pool_part}"
            )));
        }
        let l = self.line_mut(slice, lender)?;
        l.items[idx].pool_part = pool_part;
        match l.items[idx].status {
            ItemStatus::PendingEvaluation => l.pending = sub(l.pending, amount, "pending")?,
            ItemStatus::Disputed => l.disputed = sub(l.disputed, amount, "disputed")?,
            st => return Err(DomainError::Internal(format!("pay from {st:?}"))),
        }
        l.paid = add(l.paid, amount, "paid")?;
        l.held = add(l.held, amount, "held")?;
        l.items[idx].status = ItemStatus::Paid;
        l.items[idx].awaiting_delivery = false;
        // A zero reward (free pool) has nothing to hold or release.
        l.items[idx].reward_done = amount == 0;
        self.audit.push(AuditEvent::ItemPaid {
            slice,
            lender,
            kind,
            amount,
            evidence,
            by_arbitration,
            at: self.now,
        });
        Ok(())
    }

    pub(super) fn refund_item(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        idx: usize,
        reason: RefundReason,
    ) -> R {
        let (kind, amount) = {
            let l = &self.slices[&slice].lines[&lender];
            (l.items[idx].kind, l.items[idx].amount)
        };
        // The ledger sends it back where it came from (LEDGER-013).
        let item = self.item_id(slice, kind)?;
        self.ledger_op(LedgerOp::RefundLine {
            line: line_ref(slice, lender),
            item,
        })?;
        if let ItemKind::Recovery(_) = kind {
            let a = self.attempt_mut(slice.job, slice.attempt)?;
            a.recovery_reserved = sub(a.recovery_reserved, amount, "recovery reserved")?;
        }
        let l = self.line_mut(slice, lender)?;
        match l.items[idx].status {
            ItemStatus::PendingEvaluation => l.pending = sub(l.pending, amount, "pending")?,
            ItemStatus::Disputed => l.disputed = sub(l.disputed, amount, "disputed")?,
            st => return Err(DomainError::Internal(format!("refund from {st:?}"))),
        }
        l.refunded = add(l.refunded, amount, "refunded")?;
        l.items[idx].status = ItemStatus::Refunded;
        l.items[idx].awaiting_delivery = false;
        self.audit.push(AuditEvent::ItemRefunded {
            slice,
            lender,
            kind,
            amount,
            reason,
        });
        Ok(())
    }
}

enum Decision {
    Pay,
    Refund(RefundReason),
    Dispute,
    /// Output still provisional (JOB-R30).
    Await,
    /// Refund for missing proof, deferred to the deadline (JOB-R35).
    Defer,
}
