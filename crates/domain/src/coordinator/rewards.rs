//! Arbitration, held rewards and job settlement (JOB-S06, JOB-S12, JOB-R22).

use super::*;

impl Coordinator {
    /// JOB-S06: arbitrates a disputed line.
    pub(super) fn arbitrate(&mut self, slice: SliceId, lender: AccountId, pay: bool) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        if s.status != SliceStatus::Disputed {
            return Err(DomainError::InvalidSliceTransition {
                from: s.status,
                rule: "JOB-S06",
            });
        }
        let line = s
            .lines
            .get(&lender)
            .ok_or(DomainError::Precondition("no line"))?;
        let idxs: Vec<usize> = line
            .items
            .iter()
            .enumerate()
            // JOB-R30: a contribution waiting for delivery follows its output, never arbitrated on
            // its own.
            .filter(|(_, i)| i.status == ItemStatus::Disputed && !i.awaiting_delivery)
            .map(|(k, _)| k)
            .collect();
        if idxs.is_empty() {
            return Err(DomainError::Precondition("line not disputed"));
        }
        let mut ruled = false;
        for idx in idxs {
            if !pay {
                self.refund_item(slice, lender, idx, RefundReason::Arbitration)?;
            } else if self.payable_by_ruling(slice, lender, idx) {
                self.pay_item(slice, lender, idx, true)?;
            } else {
                // JOB-R18: a ruling cannot pay recovery nobody corroborated. It stays held until
                // its recipient corroborates or a ruling refunds it.
                continue;
            }
            ruled = true;
        }
        if !ruled {
            return Err(DomainError::InadmissibleProof);
        }
        if self.slices[&slice].lines.values().all(|l| l.disputed == 0) {
            self.set_slice(slice, SliceStatus::Final, "JOB-S06")?;
            self.maybe_return_earmark(slice.job, slice.attempt)?;
        }
        Ok(Outcome::Applied)
    }

    /// A pay ruling applies to every disputed item except recovery work whose restoration was not
    /// corroborated (JOB-R18): the ledger would refuse it.
    fn payable_by_ruling(&self, slice: SliceId, lender: AccountId, idx: usize) -> bool {
        match self.slices[&slice].lines[&lender].items[idx].kind {
            ItemKind::Recovery(rid) => self.restore_corroborated(rid, lender),
            ItemKind::Contribution(_) => true,
        }
    }

    /// Paid items of the line whose reward is still held and whose own payment time passes
    /// `open`: their indexes, their total and the pool's share of it (LEDGER-018).
    fn held_items(
        &self,
        slice: SliceId,
        lender: AccountId,
        open: impl Fn(Time) -> bool,
    ) -> R<(Vec<usize>, Amount, Amount)> {
        let (mut idxs, mut total, mut pool) = (Vec::new(), 0, 0);
        let line = self.slices.get(&slice).and_then(|s| s.lines.get(&lender));
        for (k, i) in line.iter().flat_map(|l| l.items.iter().enumerate()) {
            let held = i.status == ItemStatus::Paid && !i.reward_done && i.amount > 0;
            if held && i.paid_at.is_some_and(&open) {
                idxs.push(k);
                total = add(total, i.amount, "held items")?;
                pool = add(pool, i.pool_part, "pool part")?;
            }
        }
        Ok((idxs, total, pool))
    }

    pub(super) fn release_reward(&mut self, slice: SliceId, lender: AccountId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        let Some(final_at) = s.final_at else {
            return Err(DomainError::Precondition("JOB-R22: slice not final"));
        };
        if self.now < final_at + self.cfg.reward_window {
            return Err(DomainError::Precondition("JOB-R22: contest window open"));
        }
        if s.lines.get(&lender).map_or(0, |l| l.held) == 0 {
            return Err(DomainError::Precondition("nothing held"));
        }
        // LEDGER-018: each payment has had its own window, counted from that payment.
        let (now, hold) = (self.now, self.ledger.limits().reward_hold);
        let due = |paid_at: Time| paid_at.checked_add(hold).is_some_and(|t| now >= t);
        let (idxs, amount, _) = self.held_items(slice, lender, due)?;
        if idxs.is_empty() {
            return Err(DomainError::Precondition("JOB-R22: contest window open"));
        }
        let LedgerOutcome::Released {
            to_lender,
            commission,
        } = self.ledger_op(LedgerOp::ReleaseReward {
            line: line_ref(slice, lender),
        })?
        else {
            return Err(DomainError::Internal("release outcome".into()));
        };
        if to_lender.checked_add(commission) != Some(amount) {
            return Err(DomainError::Internal(format!(
                "release: ledger {to_lender} + {commission}, coordinator {amount}"
            )));
        }
        let l = self.line_mut(slice, lender)?;
        l.held = sub(l.held, amount, "held")?;
        l.released = add(l.released, amount, "released")?;
        for k in idxs {
            l.items[k].reward_done = true;
        }
        self.audit.push(AuditEvent::RewardReleased {
            slice,
            lender,
            amount: to_lender,
            commission,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-R22: a contest refunds the borrower from held rewards; it never creates credits or
    /// touches the lender's balance.
    pub(super) fn contest_reward(&mut self, slice: SliceId, lender: AccountId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        if let Some(final_at) = s.final_at {
            if self.now >= final_at + self.cfg.reward_window {
                return Err(DomainError::Precondition("JOB-R22: contest window closed"));
            }
        }
        if s.lines.get(&lender).map_or(0, |l| l.held) == 0 {
            return Err(DomainError::Precondition("nothing held"));
        }
        // LEDGER-018: a contest is bounded payment by payment, even if the slice is not final
        // yet. It takes back the payments still inside their own limit; one past it stays held
        // and can only be released. CE-02: each payer gets its own share back (the pool for the
        // recovery it funded).
        let (now, limit) = (self.now, self.ledger.limits().contest_limit);
        let open = |paid_at: Time| paid_at.checked_add(limit).is_none_or(|t| now < t);
        let (idxs, amount, to_pool) = self.held_items(slice, lender, open)?;
        if idxs.is_empty() {
            return Err(DomainError::Precondition("JOB-R22: contest limit reached"));
        }
        let out = self.ledger_op(LedgerOp::ContestReward {
            line: line_ref(slice, lender),
        })?;
        let expected = LedgerOutcome::Contested {
            to_pool,
            to_owner: sub(amount, to_pool, "contest")?,
        };
        if out != expected {
            return Err(DomainError::Internal(format!(
                "contest: ledger {out:?}, coordinator {expected:?}"
            )));
        }
        let j = self.job_mut(slice.job)?;
        j.recovery_contested_pool = add(j.recovery_contested_pool, to_pool, "contested pool")?;
        let l = self.line_mut(slice, lender)?;
        l.held = sub(l.held, amount, "held")?;
        l.contested = add(l.contested, amount, "contested")?;
        for k in idxs {
            l.items[k].reward_done = true;
        }
        self.audit.push(AuditEvent::RewardContested {
            slice,
            lender,
            amount,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-S12: returns everything left to the borrower; escrow ends at zero.
    pub(super) fn settle(&mut self, job: JobId) -> R<Outcome> {
        let j = self.job(job)?.clone();
        if j.settle != SettleStatus::Finalizing {
            return Err(DomainError::Precondition("JOB-S12: not finalizing"));
        }
        if !self
            .slices_of(job, None)
            .iter()
            .all(|s| self.slices[s].status == SliceStatus::Final)
        {
            return Err(DomainError::Precondition("JOB-S12: slices not final"));
        }
        // JOB-R29: provisional deliveries are resolved before escrow is settled.
        if self.delivery.has_provisional(job, None) {
            return Err(DomainError::Precondition(
                "JOB-S12: provisional outputs pending",
            ));
        }
        // CE-02: unspent pool relay goes back to the pool; everything else to the borrower. The
        // ledger takes both destinations from the escrow record.
        let pool_unspent = sub(j.pool_recovery_funded, j.recovery_paid_pool, "pool relay")?;
        let out = self
            .ledger_op(LedgerOp::SettleJob { job: job_acct(job) })
            .map_err(|e| match e {
                DomainError::Ledger(e) => DomainError::Internal(format!("settle: {e:?}")),
                other => other,
            })?;
        if !matches!(out, LedgerOutcome::Settled { to_pool, .. } if to_pool == pool_unspent) {
            return Err(DomainError::Internal(format!(
                "settle: ledger {out:?}, coordinator pool share {pool_unspent}"
            )));
        }
        self.set_settle(job, SettleStatus::Closed, "JOB-S12")?;
        Ok(Outcome::Applied)
    }
}
