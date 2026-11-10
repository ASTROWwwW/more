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
        for idx in idxs {
            if pay {
                self.pay_item(slice, lender, idx, true)?;
            } else {
                self.refund_item(slice, lender, idx, RefundReason::Arbitration)?;
            }
        }
        if self.slices[&slice].lines.values().all(|l| l.disputed == 0) {
            self.set_slice(slice, SliceStatus::Final, "JOB-S06")?;
            self.maybe_return_earmark(slice.job, slice.attempt)?;
        }
        Ok(Outcome::Applied)
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
        let held = s.lines.get(&lender).map_or(0, |l| l.held);
        if held == 0 {
            return Err(DomainError::Precondition("nothing held"));
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
        let l = self.line_mut(slice, lender)?;
        l.held = 0;
        l.released = add(l.released, held, "released")?;
        for it in l.items.iter_mut().filter(|i| i.status == ItemStatus::Paid) {
            it.reward_done = true;
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
        let held = s.lines.get(&lender).map_or(0, |l| l.held);
        if held == 0 {
            return Err(DomainError::Precondition("nothing held"));
        }
        // CE-02: each payer gets its own share back (the pool for the recovery it funded).
        let to_pool = s.lines[&lender]
            .items
            .iter()
            .filter(|i| i.status == ItemStatus::Paid && !i.reward_done)
            .try_fold(0u64, |acc, i| acc.checked_add(i.pool_part))
            .ok_or(DomainError::Overflow("pool part"))?;
        let out = self.ledger_op(LedgerOp::ContestReward {
            line: line_ref(slice, lender),
        })?;
        let expected = LedgerOutcome::Contested {
            to_pool,
            to_owner: sub(held, to_pool, "contest")?,
        };
        if out != expected {
            return Err(DomainError::Internal(format!(
                "contest: ledger {out:?}, coordinator {expected:?}"
            )));
        }
        let j = self.job_mut(slice.job)?;
        j.recovery_contested_pool = add(j.recovery_contested_pool, to_pool, "contested pool")?;
        let l = self.line_mut(slice, lender)?;
        l.held = 0;
        l.contested = add(l.contested, held, "contested")?;
        for it in l.items.iter_mut().filter(|i| i.status == ItemStatus::Paid) {
            it.reward_done = true;
        }
        self.audit.push(AuditEvent::RewardContested {
            slice,
            lender,
            amount: held,
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
