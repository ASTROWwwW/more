//! What the Ledger remembers about each job, independently of the orchestrator: the signed terms,
//! the attempts its lenders signed, the receipts their recipients signed, the charged outputs, and
//! every line item with its provenance.

use std::collections::BTreeMap;

use crate::Amount;

use super::types::{Assignment, ItemId, JobTerms, LineRef, OutputRef};

/// Escrow of one job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub owner: u32,
    pub pool: u32,
    /// Terms signed by the owner (JOB-R37).
    pub terms: JobTerms,
    /// Credits already taken from the owner for this job, both buckets.
    pub locked: Amount,
    /// Closed by `SettleJob`; no write may touch the job's escrow, hold or lines afterwards.
    pub settled: bool,
    /// Recovery budget paid in by the owner.
    pub owner_recovery: Amount,
    /// Recovery budget relayed by the pool (JOB-R18).
    pub pool_funded: Amount,
    /// Recovery paid to lenders, by payer (CE-02: owner first, then pool).
    pub recovery_paid_owner: Amount,
    pub recovery_paid_pool: Amount,
    pub attempts: BTreeMap<u32, AttemptRec>,
    pub outputs: BTreeMap<OutputRef, OutputRec>,
    pub items: BTreeMap<ItemId, ItemRec>,
    /// Receipts signed by the recipient, per `(attempt, producer, type)`: covered up to → digest.
    /// A recorded receipt is final: the same coverage with another digest is refused.
    pub receipts: BTreeMap<(u32, u32, u8), BTreeMap<u32, u64>>,
}

/// An attempt as its lenders signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRec {
    pub assignment: Assignment,
    /// Per stage: the lender signed the assignment.
    pub accepted: Vec<bool>,
    /// Per stage: the lender signed that its state is restored.
    pub ready: Vec<bool>,
    /// Per stage: the positions the lender signed it restored to.
    pub restored: Vec<[u32; 3]>,
    /// Per stage: the commitment to the restored state the lender signed.
    pub state: Vec<u64>,
    /// Per stage: the commitment the lender signed for each recovery segment, by segment number.
    pub segments: Vec<Vec<u64>>,
    /// Per stage: what the stage's recipient signed it received (JOB-R18). Written once.
    pub corroborated: Vec<Option<Corroboration>>,
    /// Position of the revocation in the ledger's order of records. Proofs are only added to an
    /// attempt before it (CE-03).
    pub revoked: Option<u64>,
    /// Recovery reserved in lines for this attempt, paid or not (refunds give it back).
    pub recovery_reserved: Amount,
    pub earmark_returned: bool,
}

/// A recipient's corroboration as recorded: the segments it names, and when it was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corroboration {
    pub segments: Vec<u32>,
    /// Position in the ledger's order of records.
    pub seq: u64,
}

impl AttemptRec {
    /// The recipient of `stage` corroborated `segment` explicitly.
    pub fn corroborates(&self, stage: usize, segment: u32) -> bool {
        self.corroborated
            .get(stage)
            .and_then(|c| c.as_ref())
            .is_some_and(|c| c.segments.contains(&segment))
    }

    pub fn stage_of(&self, lender: u32) -> Option<usize> {
        self.assignment.lenders.iter().position(|l| *l == lender)
    }

    /// Who receives `stage`'s output and signs its receipts: the next stage, or the witness.
    pub fn recipient_of(&self, stage: usize) -> Option<u32> {
        let n = self.assignment.lenders.len();
        if stage + 1 < n {
            self.assignment.lenders.get(stage + 1).copied()
        } else if stage + 1 == n {
            Some(self.assignment.witness)
        } else {
            None
        }
    }

    /// Recovery this attempt holds against the job's budget.
    pub fn committed_recovery(&self) -> Amount {
        if self.earmark_returned {
            self.recovery_reserved
        } else {
            self.assignment.recovery_earmark
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutputRec {
    /// Charge in force: `(attempt, generation)`.
    pub charged: Option<(u32, u32)>,
    pub next_gen: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemState {
    Reserved,
    Paid,
    Refunded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemRec {
    pub line: LineRef,
    pub amount: Amount,
    pub state: ItemState,
    /// Share of a paid recovery item funded by the pool.
    pub pool_part: Amount,
    /// The held reward of this item was released or contested.
    pub rewarded: bool,
    /// Ledger time of the payment: start of the contest window (JOB-R22).
    pub paid_at: Option<u64>,
}

impl Escrow {
    pub(crate) fn new(owner: u32, pool: u32, terms: JobTerms) -> Self {
        Escrow {
            owner,
            pool,
            terms,
            locked: 0,
            settled: false,
            owner_recovery: 0,
            pool_funded: 0,
            recovery_paid_owner: 0,
            recovery_paid_pool: 0,
            attempts: BTreeMap::new(),
            outputs: BTreeMap::new(),
            items: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    /// Recovery budget not yet promised to an attempt; `None` on overflow.
    pub fn recovery_free(&self) -> Option<Amount> {
        let total = self.owner_recovery.checked_add(self.pool_funded)?;
        let committed = self
            .attempts
            .values()
            .try_fold(0u64, |acc, a| acc.checked_add(a.committed_recovery()))?;
        total.checked_sub(committed)
    }

    /// A recorded receipt of `producer` on `attempt` covers position `pos` of type `wt`.
    pub fn receipt_covers(&self, attempt: u32, producer: u32, wt: u8, pos: u32) -> bool {
        self.receipts
            .get(&(attempt, producer, wt))
            .is_some_and(|r| r.range(pos.saturating_add(1)..).next().is_some())
    }

    pub fn has_open_items(&self) -> bool {
        self.items.values().any(|i| i.state == ItemState::Reserved)
    }
}
