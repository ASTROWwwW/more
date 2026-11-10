//! Line items and held rewards (LEDGER-013, LEDGER-016, LEDGER-018).
//!
//! The orchestrator proposes; the Ledger checks against what it holds signed: a line is only
//! reserved for a lender who signed the attempt, a contribution is only paid with a receipt signed
//! by the stage's recipient, recovery only on a restoration its recipient corroborated, and a
//! held reward leaves only through its contest cycle.

use super::book::{ItemRec, ItemState};
use super::types::{ItemId, LedgerApiError, LedgerOutcome, LineRef, OutputRef};
use super::work::{invalid, proof};
use super::{ApiResult, LedgerService};
use crate::{Account, Amount};

/// Where an item's reserve comes from, decided by what the item is.
fn source(job: u32, item: ItemId) -> Account {
    match item {
        ItemId::Contribution { .. } => Account::OutputHold(job),
        ItemId::Recovery { .. } => Account::EscrowRecovery(job),
    }
}

impl LedgerService {
    /// Checks shared by both reservations: the line's lender holds `stage` of the line's attempt
    /// and accepted it, and the item is new.
    fn line_holder(&self, line: LineRef, item: ItemId) -> ApiResult<usize> {
        let e = self.live_escrow(line.job)?;
        let rec = e
            .attempts
            .get(&line.attempt)
            .ok_or(invalid("unknown attempt"))?;
        let s = rec
            .stage_of(line.lender)
            .ok_or(proof("lender not in the attempt"))?;
        if !rec.accepted[s] {
            return Err(proof("lender never accepted the lease"));
        }
        if e.items.contains_key(&item) {
            return Err(invalid("item already reserved"));
        }
        Ok(s)
    }

    fn reserve_item(&mut self, line: LineRef, item: ItemId, amount: Amount) -> ApiResult {
        self.amount_ok(amount)?;
        self.ledger.transfer(
            format!("reserve/{}/{item:?}", line.job),
            source(line.job, item),
            line.line_account(),
            amount,
            "JOB-S03 reserve",
        )?;
        let rec = ItemRec {
            line,
            amount,
            state: ItemState::Reserved,
            pool_part: 0,
            rewarded: false,
            paid_at: None,
        };
        self.live_escrow_mut(line.job)?.items.insert(item, rec);
        Ok(LedgerOutcome::Moved(amount))
    }

    /// The share is the stage's layers over the model's, of the signed price, rounded down.
    pub(super) fn reserve_contribution(
        &mut self,
        line: LineRef,
        output: OutputRef,
        gen: u32,
        stage: u32,
    ) -> ApiResult {
        let item = ItemId::Contribution { output, gen, stage };
        let s = self.line_holder(line, item)?;
        if usize::try_from(stage).ok() != Some(s) {
            return Err(proof("lender does not hold this stage"));
        }
        let e = self.live_escrow(line.job)?;
        let charged = e.outputs.get(&output).and_then(|o| o.charged);
        if charged != Some((line.attempt, gen)) {
            return Err(invalid("output not charged to this attempt and generation"));
        }
        let price = e
            .terms
            .price
            .get(usize::from(output.wt))
            .copied()
            .unwrap_or(0);
        let width = e.attempts[&line.attempt].assignment.layout[s];
        let share = u128::from(price) * u128::from(width) / u128::from(e.terms.layers.max(1));
        let amount = Amount::try_from(share).map_err(|_| invalid("share"))?;
        self.reserve_item(line, item, amount)
    }

    pub(super) fn reserve_recovery(
        &mut self,
        line: LineRef,
        segment: u32,
        amount: Amount,
    ) -> ApiResult {
        let item = ItemId::Recovery {
            attempt: line.attempt,
            segment,
        };
        let s = self.line_holder(line, item)?;
        let rec = &self.live_escrow(line.job)?.attempts[&line.attempt];
        // JOB-R18: recovery work is attested by the attempt having started, that is by every
        // lender of the cluster signing ready, not by the claimant's word alone.
        if !rec.ready[s] || !rec.ready.iter().all(|r| *r) {
            return Err(proof(
                "recovery on an attempt whose lenders did not all sign ready",
            ));
        }
        if rec.earmark_returned {
            return Err(invalid("attempt's earmark already returned"));
        }
        let reserved = rec
            .recovery_reserved
            .checked_add(amount)
            .filter(|r| *r <= rec.assignment.recovery_earmark)
            .ok_or(invalid("recovery above the attempt's earmark"))?;
        if amount == 0 {
            return Err(invalid("empty recovery item"));
        }
        let out = self.reserve_item(line, item, amount)?;
        self.attempt_mut(line.job, line.attempt)?.recovery_reserved = reserved;
        Ok(out)
    }

    fn reserved_item(&self, line: LineRef, item: ItemId) -> ApiResult<ItemRec> {
        let it = *self
            .live_escrow(line.job)?
            .items
            .get(&item)
            .ok_or(invalid("unknown item"))?;
        if it.line != line || it.state != ItemState::Reserved {
            return Err(invalid("item not reserved on this line"));
        }
        Ok(it)
    }

    /// Pays a reserved item, with proof: a recipient's receipt covering the output for a
    /// contribution whose charge is still in force; for recovery, the restoration corroborated
    /// by the lender's recipient, on an attempt every lender signed ready for (checked at
    /// reservation). Recovery is paid from the owner's budget first, then the pool's relay.
    pub(super) fn pay_line(&mut self, line: LineRef, item: ItemId) -> ApiResult {
        let it = self.reserved_item(line, item)?;
        let e = self.live_escrow(line.job)?;
        let mut pool_part = 0;
        match item {
            ItemId::Contribution { output, gen, .. } => {
                let charged = e.outputs.get(&output).and_then(|o| o.charged);
                if charged != Some((line.attempt, gen)) {
                    return Err(invalid("charge no longer in force"));
                }
                let key = (line.attempt, line.lender, output.wt);
                if !e.receipt_covers(key.0, key.1, key.2, output.pos) {
                    return Err(proof("no receipt from the recipient covers this output"));
                }
            }
            ItemId::Recovery { attempt, segment } => {
                // JOB-R18: settled only on a restoration its recipient corroborated, and only for
                // the segments that corroboration covers.
                let rec = e.attempts.get(&attempt).ok_or(invalid("unknown attempt"))?;
                let s = rec
                    .stage_of(line.lender)
                    .ok_or(proof("lender not in the attempt"))?;
                if !rec.corroborated[s].is_some_and(|n| segment < n) {
                    return Err(proof("recovery without a corroborated restoration"));
                }
                let left = e
                    .owner_recovery
                    .checked_sub(e.recovery_paid_owner)
                    .ok_or(invalid("owner recovery overspent"))?;
                pool_part = it.amount - it.amount.min(left);
                let pool_paid = e
                    .recovery_paid_pool
                    .checked_add(pool_part)
                    .filter(|p| *p <= e.pool_funded)
                    .ok_or(invalid("recovery beyond owner budget and pool relay"))?;
                let owner_paid = e
                    .recovery_paid_owner
                    .checked_add(it.amount - pool_part)
                    .ok_or(invalid("owner recovery paid"))?;
                self.ledger.transfer(
                    format!("pay/{}/{item:?}", line.job),
                    line.line_account(),
                    line.reward_account(),
                    it.amount,
                    "JOB-S04 held payment",
                )?;
                let e = self.live_escrow_mut(line.job)?;
                e.recovery_paid_pool = pool_paid;
                e.recovery_paid_owner = owner_paid;
                return self.mark_paid(line.job, item, pool_part);
            }
        }
        self.ledger.transfer(
            format!("pay/{}/{item:?}", line.job),
            line.line_account(),
            line.reward_account(),
            it.amount,
            "JOB-S04 held payment",
        )?;
        self.mark_paid(line.job, item, pool_part)
    }

    fn mark_paid(&mut self, job: u32, item: ItemId, pool_part: Amount) -> ApiResult {
        let now = self.now;
        let it = self
            .live_escrow_mut(job)?
            .items
            .get_mut(&item)
            .ok_or(invalid("unknown item"))?;
        it.state = ItemState::Paid;
        it.pool_part = pool_part;
        it.paid_at = Some(now);
        // A zero reward (free pool) has nothing to hold or release.
        it.rewarded = it.amount == 0;
        Ok(LedgerOutcome::Paid {
            amount: it.amount,
            pool_part,
        })
    }

    /// The reserve goes back where the Ledger recorded it came from.
    pub(super) fn refund_line(&mut self, line: LineRef, item: ItemId) -> ApiResult {
        let it = self.reserved_item(line, item)?;
        self.ledger.transfer(
            format!("refund/{}/{item:?}", line.job),
            line.line_account(),
            source(line.job, item),
            it.amount,
            "JOB-S04 refund",
        )?;
        if let ItemId::Recovery { attempt, .. } = item {
            let a = self.attempt_mut(line.job, attempt)?;
            a.recovery_reserved = a
                .recovery_reserved
                .checked_sub(it.amount)
                .ok_or(invalid("recovery reserved"))?;
        }
        let r = self
            .live_escrow_mut(line.job)?
            .items
            .get_mut(&item)
            .ok_or(invalid("unknown item"))?;
        r.state = ItemState::Refunded;
        Ok(LedgerOutcome::Moved(it.amount))
    }

    /// Held rewards of `line`, with the pool's share and the times of the oldest and the latest
    /// payment still held. Works after settlement: a held reward always ends in a user, pool or
    /// commission account.
    fn held(&self, line: LineRef) -> ApiResult<(Amount, Amount, (u64, u64))> {
        let e = self.escrow(line.job)?;
        let held = self.ledger.available(line.reward_account());
        if held == 0 {
            return Err(invalid("nothing held"));
        }
        let pool = e
            .items
            .values()
            .filter(|i| i.line == line && i.state == ItemState::Paid && !i.rewarded)
            .try_fold(0u64, |acc, i| acc.checked_add(i.pool_part))
            .ok_or(invalid("pool part"))?;
        if pool > held {
            return Err(invalid("pool share above the held reward"));
        }
        let times = || {
            e.items
                .values()
                .filter(|i| i.line == line && i.state == ItemState::Paid && !i.rewarded)
                .filter_map(|i| i.paid_at)
        };
        let window = times()
            .min()
            .zip(times().max())
            .ok_or(invalid("held reward without a payment"))?;
        Ok((held, pool, window))
    }

    fn mark_rewarded(&mut self, line: LineRef) {
        if let Some(e) = self.escrows.get_mut(&line.job) {
            for i in e.items.values_mut() {
                if i.line == line && i.state == ItemState::Paid {
                    i.rewarded = true;
                }
            }
        }
    }

    /// JOB-R22, LEDGER-018: a payment becomes final only after the borrower had its contest
    /// window, counted by the ledger's own clock from the latest payment still held.
    pub(super) fn release_reward(&mut self, line: LineRef) -> ApiResult {
        let (held, _, (_, latest)) = self.held(line)?;
        let open_until = latest
            .checked_add(self.limits.reward_hold)
            .ok_or(invalid("contest window overflow"))?;
        if self.now < open_until {
            return Err(LedgerApiError::OutOfWindow("contest window still open"));
        }
        let commission =
            u64::try_from(u128::from(held) * u128::from(self.limits.commission_bps) / 10_000)
                .map_err(|_| invalid("commission"))?;
        let to_lender = held - commission.min(held);
        let reward = line.reward_account();
        // A line can be paid again after a release or a contest: the journal position keeps keys
        // unique.
        let n = self.ledger.entries().len();
        let tag = format!(
            "{}/{}/{}/{}/{n}",
            line.job, line.attempt, line.slice, line.lender
        );
        self.ledger.transfer(
            format!("release/{tag}"),
            reward,
            Account::User(line.lender),
            to_lender,
            "JOB-R22 release",
        )?;
        self.ledger.transfer(
            format!("commission/{tag}"),
            reward,
            Account::Commission,
            held - to_lender,
            "JOB-R22 commission",
        )?;
        self.mark_rewarded(line);
        Ok(LedgerOutcome::Released {
            to_lender,
            commission: held - to_lender,
        })
    }

    /// CE-02: each payer gets its own share back; the pool's share is what the Ledger recorded.
    /// LEDGER-018: a contest is bounded in time. Past the limit, counted from the oldest payment
    /// still held, the reward can only be released.
    pub(super) fn contest_reward(&mut self, line: LineRef) -> ApiResult {
        let (held, to_pool, (oldest, _)) = self.held(line)?;
        let limit = oldest
            .checked_add(self.limits.contest_limit)
            .ok_or(invalid("contest limit overflow"))?;
        if self.now >= limit {
            return Err(LedgerApiError::OutOfWindow("contest limit reached"));
        }
        let e = self.escrow(line.job)?;
        let (owner, pool) = (e.owner, e.pool);
        let n = self.ledger.entries().len();
        let tag = format!(
            "{}/{}/{}/{}/{n}",
            line.job, line.attempt, line.slice, line.lender
        );
        let reward = line.reward_account();
        self.ledger.transfer(
            format!("contest/{tag}/pool"),
            reward,
            Account::PoolReserve(pool),
            to_pool,
            "JOB-R22 contest (pool share)",
        )?;
        self.ledger.transfer(
            format!("contest/{tag}"),
            reward,
            Account::User(owner),
            held - to_pool,
            "JOB-R22 contest",
        )?;
        self.mark_rewarded(line);
        Ok(LedgerOutcome::Contested {
            to_pool,
            to_owner: held - to_pool,
        })
    }

    pub(super) fn return_earmark(&mut self, job: u32, attempt: u32) -> ApiResult {
        let e = self.live_escrow(job)?;
        let rec = e.attempts.get(&attempt).ok_or(invalid("unknown attempt"))?;
        if rec.earmark_returned {
            return Err(invalid("earmark already returned"));
        }
        let open = e.items.iter().any(|(id, i)| {
            matches!(id, ItemId::Recovery { attempt: a, .. } if *a == attempt)
                && i.state == ItemState::Reserved
        });
        if open {
            return Err(LedgerApiError::OpenItems(job));
        }
        let unused = rec
            .assignment
            .recovery_earmark
            .checked_sub(rec.recovery_reserved)
            .ok_or(invalid("recovery reserved above earmark"))?;
        self.attempt_mut(job, attempt)?.earmark_returned = true;
        Ok(LedgerOutcome::Moved(unused))
    }
}
