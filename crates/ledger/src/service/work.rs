//! Attempts and the signed statements about them: leases, readiness, corroborated restorations,
//! receipts (LEDGER-015, LEDGER-016). Line items that rely on them are in `lines.rs`.

use std::collections::BTreeSet;

use more_identity::{
    lease_message, ready_message, receipt_message, restore_message, Assignment, Restoration,
};

use super::book::AttemptRec;
use super::types::{LedgerApiError, LedgerOutcome};
use super::{ApiResult, LedgerService};

pub(super) fn proof(why: &'static str) -> LedgerApiError {
    LedgerApiError::BadProof(why)
}

pub(super) fn invalid(why: &'static str) -> LedgerApiError {
    LedgerApiError::Invalid(why)
}

impl LedgerService {
    fn attempt(&self, job: u32, attempt: u32) -> ApiResult<&AttemptRec> {
        self.live_escrow(job)?
            .attempts
            .get(&attempt)
            .ok_or(invalid("unknown attempt"))
    }

    pub(super) fn attempt_mut(&mut self, job: u32, attempt: u32) -> ApiResult<&mut AttemptRec> {
        self.live_escrow_mut(job)?
            .attempts
            .get_mut(&attempt)
            .ok_or(invalid("unknown attempt"))
    }

    pub(super) fn register_attempt(&mut self, a: Assignment) -> ApiResult {
        let e = self.live_escrow(a.job)?;
        if e.attempts
            .keys()
            .next_back()
            .is_some_and(|last| *last >= a.attempt)
        {
            return Err(invalid("attempts are registered in increasing order"));
        }
        if a.lenders.is_empty() || a.lenders.len() != a.layout.len() || a.layout.contains(&0) {
            return Err(invalid("one non-empty layer range per lender"));
        }
        let covered = a
            .layout
            .iter()
            .try_fold(0u32, |acc, l| acc.checked_add(*l))
            .ok_or(invalid("layout overflow"))?;
        if covered != e.terms.layers {
            return Err(invalid("layout does not cover the signed model"));
        }
        let mut seen = BTreeSet::new();
        if !a.lenders.iter().all(|l| seen.insert(*l)) {
            return Err(invalid("a lender holds one range only"));
        }
        if a.lenders.contains(&a.witness) || a.witness == e.owner {
            return Err(invalid("witness not independent"));
        }
        self.amount_ok(a.recovery_earmark)?;
        let free = e.recovery_free().ok_or(invalid("recovery overflow"))?;
        if a.recovery_earmark > free {
            return Err(invalid("earmark above the free recovery budget"));
        }
        let n = a.lenders.len();
        let rec = AttemptRec {
            assignment: a,
            accepted: vec![false; n],
            ready: vec![false; n],
            restored: vec![[0; 3]; n],
            state: vec![0; n],
            corroborated: vec![None; n],
            recovery_reserved: 0,
            earmark_returned: false,
        };
        let job = rec.assignment.job;
        self.live_escrow_mut(job)?
            .attempts
            .insert(rec.assignment.attempt, rec);
        Ok(LedgerOutcome::Done)
    }

    fn stage_lender(rec: &AttemptRec, stage: u32) -> ApiResult<(usize, u32)> {
        let s = usize::try_from(stage).map_err(|_| invalid("stage"))?;
        let l = rec
            .assignment
            .lenders
            .get(s)
            .ok_or(invalid("unknown stage"))?;
        Ok((s, *l))
    }

    pub(super) fn accept_lease(
        &mut self,
        job: u32,
        attempt: u32,
        stage: u32,
        signature: &[u8; 64],
    ) -> ApiResult {
        let rec = self.attempt(job, attempt)?;
        let (s, lender) = Self::stage_lender(rec, stage)?;
        if rec.accepted[s] {
            return Err(invalid("lease already accepted"));
        }
        self.keys
            .verify(lender, &lease_message(&rec.assignment), signature)
            .map_err(|_| proof("lease not signed by the stage's lender"))?;
        self.attempt_mut(job, attempt)?.accepted[s] = true;
        Ok(LedgerOutcome::Done)
    }

    pub(super) fn lease_ready(
        &mut self,
        job: u32,
        attempt: u32,
        stage: u32,
        (restored, state): ([u32; 3], u64),
        signature: &[u8; 64],
    ) -> ApiResult {
        let rec = self.attempt(job, attempt)?;
        let (s, lender) = Self::stage_lender(rec, stage)?;
        if !rec.accepted[s] || rec.ready[s] {
            return Err(invalid("ready without an accepted lease, or twice"));
        }
        self.keys
            .verify(
                lender,
                &ready_message(job, attempt, lender, restored, state),
                signature,
            )
            .map_err(|_| proof("readiness not signed by the stage's lender"))?;
        let rec = self.attempt_mut(job, attempt)?;
        rec.ready[s] = true;
        rec.restored[s] = restored;
        rec.state[s] = state;
        Ok(LedgerOutcome::Done)
    }

    /// JOB-R18: a lender's word that it restored its state is not enough to be paid for it. The
    /// account that receives its output must sign what it received: the stage and its layers,
    /// the positions, the number of recovery segments and the commitment the lender signed. The
    /// first corroboration of a stage is final; another one, identical or not, is refused.
    pub(super) fn record_restore(
        &mut self,
        job: u32,
        attempt: u32,
        producer: u32,
        segments: u32,
        signature: &[u8; 64],
    ) -> ApiResult {
        let rec = self.attempt(job, attempt)?;
        let s = rec
            .stage_of(producer)
            .ok_or(invalid("producer not in attempt"))?;
        if !rec.ready[s] || rec.corroborated[s].is_some() || segments == 0 {
            return Err(invalid(
                "restoration not signed by its lender, or corroborated twice",
            ));
        }
        let recipient = rec.recipient_of(s).ok_or(invalid("no recipient"))?;
        let start: u32 = rec.assignment.layout[..s].iter().sum();
        let msg = restore_message(&Restoration {
            job,
            attempt,
            producer,
            layers: (start, start + rec.assignment.layout[s]),
            restored: rec.restored[s],
            segments,
            state: rec.state[s],
        });
        self.keys
            .verify(recipient, &msg, signature)
            .map_err(|_| proof("restoration not corroborated by the producer's recipient"))?;
        self.attempt_mut(job, attempt)?.corroborated[s] = Some(segments);
        Ok(LedgerOutcome::Done)
    }

    /// LEDGER-016: kept only if signed by the account the assignment names as the producer's
    /// recipient.
    pub(super) fn record_receipt(
        &mut self,
        job: u32,
        attempt: u32,
        producer: u32,
        (wt, upto, digest): (u8, u32, u64),
        signature: &[u8; 64],
    ) -> ApiResult {
        let rec = self.attempt(job, attempt)?;
        let stage = rec
            .stage_of(producer)
            .ok_or(invalid("producer not in attempt"))?;
        let recipient = rec.recipient_of(stage).ok_or(invalid("no recipient"))?;
        if wt > 2 {
            return Err(invalid("unknown output type"));
        }
        let msg = receipt_message(job, attempt, producer, wt, upto, digest);
        self.keys
            .verify(recipient, &msg, signature)
            .map_err(|_| proof("receipt not signed by the producer's recipient"))?;
        // A recorded receipt is final: the same coverage cannot come back with another digest,
        // before or after a payment relied on it.
        let key = (attempt, producer, wt);
        let known = self.live_escrow(job)?.receipts.get(&key);
        if known
            .and_then(|r| r.get(&upto))
            .is_some_and(|d| *d != digest)
        {
            return Err(proof("contradicts a recorded receipt"));
        }
        self.live_escrow_mut(job)?
            .receipts
            .entry(key)
            .or_default()
            .insert(upto, digest);
        Ok(LedgerOutcome::Done)
    }
}
