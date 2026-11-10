//! Escrow, charges and settlement. Each operation checks, writes its entries, then updates the
//! job record; see [`LedgerService::execute`].

use more_identity::{mandate_message, relay_message, JobTerms};

use super::book::Escrow;
use super::types::{EscrowBucket, IssueTo, LedgerApiError, LedgerOutcome, OutputRef};
use super::{ApiResult, LedgerService};
use crate::{Account, Amount};

fn add(a: Amount, b: Amount) -> ApiResult<Amount> {
    a.checked_add(b)
        .ok_or(LedgerApiError::LimitExceeded("amount overflow"))
}

impl LedgerService {
    pub(super) fn issue(&mut self, key: String, to: IssueTo, amount: Amount) -> ApiResult {
        if amount > self.limits.max_issue {
            return Err(LedgerApiError::LimitExceeded(
                "issuance above the per-issue limit",
            ));
        }
        let issued = u128::try_from(-self.ledger.balance(Account::Issuance)).unwrap_or(0);
        if issued + u128::from(amount) > u128::from(self.limits.supply_cap) {
            return Err(LedgerApiError::LimitExceeded("supply cap"));
        }
        let dest = match to {
            IssueTo::User(u) => Account::User(u),
            IssueTo::Pool(p) => Account::PoolReserve(p),
        };
        let r = "LEDGER-003 issuance";
        self.ledger
            .transfer(key, Account::Issuance, dest, amount, r)?;
        Ok(LedgerOutcome::Done)
    }

    pub(super) fn open_escrow(
        &mut self,
        job: u32,
        owner: u32,
        pool: u32,
        terms: JobTerms,
        signature: &[u8; 64],
    ) -> ApiResult {
        if self.escrows.contains_key(&job) {
            return Err(LedgerApiError::EscrowExists(job));
        }
        self.amount_ok(terms.max_budget)?;
        for p in terms.price {
            self.amount_ok(p)?;
        }
        if terms.layers == 0 {
            return Err(LedgerApiError::Invalid("model without layers"));
        }
        let msg = mandate_message(job, pool, owner, &terms);
        self.keys
            .verify(owner, &msg, signature)
            .map_err(|_| LedgerApiError::BadMandate)?;
        self.escrows.insert(job, Escrow::new(owner, pool, terms));
        Ok(LedgerOutcome::Done)
    }

    pub(super) fn reserve(
        &mut self,
        job: u32,
        bucket: EscrowBucket,
        key: String,
        amount: Amount,
    ) -> ApiResult {
        self.amount_ok(amount)?;
        let e = self.live_escrow(job)?;
        let total = u128::from(e.locked) + u128::from(amount);
        if total > u128::from(e.terms.max_budget) {
            return Err(LedgerApiError::MandateExceeded {
                job,
                mandate: e.terms.max_budget,
                requested_total: total,
            });
        }
        // `total` fits: it is bounded by the mandate, itself an Amount.
        let locked = u64::try_from(total).map_err(|_| LedgerApiError::Invalid("locked"))?;
        let owner_recovery = match bucket {
            EscrowBucket::Work => e.owner_recovery,
            EscrowBucket::Recovery => add(e.owner_recovery, amount)?,
        };
        let owner = e.owner;
        let (to, reason) = match bucket {
            EscrowBucket::Work => (Account::EscrowWork(job), "JOB-T02 work escrow"),
            EscrowBucket::Recovery => (Account::EscrowRecovery(job), "JOB-T02 recovery budget"),
        };
        self.ledger
            .transfer(key, Account::User(owner), to, amount, reason)?;
        let e = self.live_escrow_mut(job)?;
        e.locked = locked;
        e.owner_recovery = owner_recovery;
        Ok(LedgerOutcome::Done)
    }

    /// The pool's treasury moves only with its admin's signature over the new running total: the
    /// orchestrator cannot relay on its own, nor replay an old consent.
    pub(super) fn fund_recovery(
        &mut self,
        job: u32,
        amount: Amount,
        signature: &[u8; 64],
    ) -> ApiResult {
        self.amount_ok(amount)?;
        let e = self.live_escrow(job)?;
        let (pool, funded) = (e.pool, add(e.pool_funded, amount)?);
        let admin = *self
            .pools
            .get(&pool)
            .ok_or(LedgerApiError::BadProof("pool without a registered admin"))?;
        self.keys
            .verify(admin, &relay_message(job, pool, funded), signature)
            .map_err(|_| LedgerApiError::BadProof("relay not signed by the pool's admin"))?;
        self.ledger.transfer(
            format!("fund/{job}/{funded}"),
            Account::PoolReserve(pool),
            Account::EscrowRecovery(job),
            amount,
            "JOB-R18 pool relay",
        )?;
        self.live_escrow_mut(job)?.pool_funded = funded;
        Ok(LedgerOutcome::Done)
    }

    /// Price of one output of type `wt`, from the signed terms.
    fn price(e: &Escrow, output: OutputRef) -> ApiResult<Amount> {
        let t = usize::from(output.wt);
        let (Some(price), Some(max)) = (e.terms.price.get(t), e.terms.max_outputs.get(t)) else {
            return Err(LedgerApiError::Invalid("unknown output type"));
        };
        if output.pos >= *max {
            return Err(LedgerApiError::Invalid("output beyond the signed maximum"));
        }
        Ok(*price)
    }

    pub(super) fn charge_output(
        &mut self,
        job: u32,
        attempt: u32,
        output: OutputRef,
        gen: u32,
    ) -> ApiResult {
        let e = self.live_escrow(job)?;
        if !e.attempts.contains_key(&attempt) {
            return Err(LedgerApiError::Invalid("charge for an unknown attempt"));
        }
        let price = Self::price(e, output)?;
        let rec = e.outputs.get(&output).copied().unwrap_or_default();
        if rec.charged.is_some() {
            return Err(LedgerApiError::Invalid("output already charged"));
        }
        if gen != rec.next_gen {
            return Err(LedgerApiError::Invalid("wrong billing generation"));
        }
        let next = gen
            .checked_add(1)
            .ok_or(LedgerApiError::Invalid("billing generation"))?;
        self.ledger.transfer(
            format!("charge/{job}/{}/{}/{gen}", output.wt, output.pos),
            Account::EscrowWork(job),
            Account::OutputHold(job),
            price,
            "JOB-R23/R27 charge output",
        )?;
        let r = self
            .live_escrow_mut(job)?
            .outputs
            .entry(output)
            .or_default();
        r.charged = Some((attempt, gen));
        r.next_gen = next;
        Ok(LedgerOutcome::Moved(price))
    }

    pub(super) fn void_output(&mut self, job: u32, output: OutputRef, gen: u32) -> ApiResult {
        let e = self.live_escrow(job)?;
        let price = Self::price(e, output)?;
        let rec = e.outputs.get(&output).copied().unwrap_or_default();
        if !rec.charged.is_some_and(|(_, g)| g == gen) {
            return Err(LedgerApiError::Invalid(
                "output not charged at this generation",
            ));
        }
        // The price of a voided output goes back to escrow whole: its shares must be returned
        // first, and none may have been paid.
        let busy = e.items.iter().any(|(id, it)| {
            matches!(id, super::ItemId::Contribution { output: o, gen: g, .. } if *o == output && *g == gen)
                && it.state != super::ItemState::Refunded
        });
        if busy {
            return Err(LedgerApiError::Invalid(
                "void of an output with live shares",
            ));
        }
        self.ledger.transfer(
            format!("void/{job}/{}/{}/{gen}", output.wt, output.pos),
            Account::OutputHold(job),
            Account::EscrowWork(job),
            price,
            "JOB-R29 void provisional output",
        )?;
        let r = self
            .live_escrow_mut(job)?
            .outputs
            .entry(output)
            .or_default();
        r.charged = None;
        Ok(LedgerOutcome::Moved(price))
    }

    /// JOB-S12, LEDGER-014: refused while an item is undecided. The pool gets back what it relayed
    /// and the Ledger did not pay out; the owner gets everything else.
    pub(super) fn settle_job(&mut self, job: u32) -> ApiResult {
        let e = self.live_escrow(job)?;
        if e.has_open_items() {
            return Err(LedgerApiError::OpenItems(job));
        }
        let (owner, pool) = (e.owner, e.pool);
        let to_pool = e
            .pool_funded
            .checked_sub(e.recovery_paid_pool)
            .ok_or(LedgerApiError::Invalid("pool relay overspent"))?;
        let rec = self.ledger.available(Account::EscrowRecovery(job));
        if to_pool > rec {
            return Err(LedgerApiError::Invalid(
                "pool share exceeds recovery escrow",
            ));
        }
        self.ledger.transfer(
            format!("settle/{job}/recovery-pool"),
            Account::EscrowRecovery(job),
            Account::PoolReserve(pool),
            to_pool,
            "JOB-S12 return to pool",
        )?;
        let mut to_owner: Amount = 0;
        for (acct, tag) in [
            (Account::EscrowWork(job), "work"),
            (Account::EscrowRecovery(job), "recovery"),
            (Account::OutputHold(job), "hold"),
        ] {
            let amount = self.ledger.available(acct);
            to_owner = add(to_owner, amount)?;
            self.ledger.transfer(
                format!("settle/{job}/{tag}"),
                acct,
                Account::User(owner),
                amount,
                "JOB-S12 return",
            )?;
        }
        self.live_escrow_mut(job)?.settled = true;
        Ok(LedgerOutcome::Settled { to_pool, to_owner })
    }
}
