//! Delivery state (trust domain "Delivery / Witness"): which outputs are charged, on what basis,
//! open contests, billing generations and witness commitments. This module has no access to the
//! ledger: it records delivery facts, and the orchestrator turns them into ledger operations.

use std::collections::BTreeMap;

use crate::error::DomainError;
use crate::ids::*;
use crate::model::{ChargeBasis, Contest, OutputCharge};

type R<T = ()> = Result<T, DomainError>;

/// Witness commitments: (job, attempt, type) to [(attested up to, log sequence)] (JOB-R32).
pub type WitnessCommits = BTreeMap<(JobId, u32, WorkType), Vec<(u32, u64)>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeliveryBook {
    /// Charged output (provisional or definitive) to the attempt that produced it (JOB-R17). Same
    /// keys as `charges`; kept apart so the checker can compare the two.
    outputs: BTreeMap<OutputId, u32>,
    /// Charge in force for each output (JOB-R27).
    charges: BTreeMap<OutputId, OutputCharge>,
    /// Next billing generation of each output.
    charge_gens: BTreeMap<OutputId, u32>,
    witness_commits: WitnessCommits,
}

impl DeliveryBook {
    pub fn outputs(&self) -> &BTreeMap<OutputId, u32> {
        &self.outputs
    }

    pub fn charges(&self) -> &BTreeMap<OutputId, OutputCharge> {
        &self.charges
    }

    pub fn charge_gens(&self) -> &BTreeMap<OutputId, u32> {
        &self.charge_gens
    }

    pub fn witness_commits(&self) -> &WitnessCommits {
        &self.witness_commits
    }

    pub fn charge(&self, o: OutputId) -> Option<&OutputCharge> {
        self.charges.get(&o)
    }

    /// Generation of the charge in force, or of the next one.
    pub fn generation(&self, o: OutputId) -> u32 {
        match self.charges.get(&o) {
            Some(c) => c.gen,
            None => self.charge_gens.get(&o).copied().unwrap_or(0),
        }
    }

    /// JOB-R17: records a new charge; an output is never charged twice at once.
    pub(crate) fn record_charge(
        &mut self,
        o: OutputId,
        attempt: u32,
        definitive: bool,
        basis: ChargeBasis,
        replayable: bool,
    ) -> R<u32> {
        if self.outputs.contains_key(&o) {
            return Err(DomainError::Internal(format!(
                "output charged twice: {o:?}"
            )));
        }
        let gen = self.charge_gens.get(&o).copied().unwrap_or(0);
        let next = gen
            .checked_add(1)
            .ok_or(DomainError::Overflow("billing generation"))?;
        self.charge_gens.insert(o, next);
        self.outputs.insert(o, attempt);
        self.charges.insert(
            o,
            OutputCharge {
                attempt,
                gen,
                definitive,
                basis,
                replayable,
                contest: None,
            },
        );
        Ok(gen)
    }

    /// Makes a provisional output definitive. Returns true if it was provisional.
    pub(crate) fn make_definitive(&mut self, o: OutputId, basis: ChargeBasis) -> R<bool> {
        let ch = self
            .charges
            .get_mut(&o)
            .ok_or_else(|| DomainError::Internal(format!("uncharged {o:?}")))?;
        if ch.definitive {
            return Ok(false);
        }
        ch.definitive = true;
        ch.basis = basis;
        ch.contest = None;
        Ok(true)
    }

    pub(crate) fn open_contest(&mut self, o: OutputId, contest: Contest) -> R {
        let ch = self
            .charges
            .get_mut(&o)
            .ok_or_else(|| DomainError::Internal(format!("contest uncharged {o:?}")))?;
        ch.contest = Some(contest);
        Ok(())
    }

    /// Removes a voided charge (JOB-R29) and returns it.
    pub(crate) fn void(&mut self, o: OutputId) -> R<OutputCharge> {
        self.outputs.remove(&o);
        self.charges
            .remove(&o)
            .ok_or_else(|| DomainError::Internal(format!("void uncharged {o:?}")))
    }

    /// The witness can no longer replay this attempt's outputs (buffer lost or purged).
    pub(crate) fn stop_replay(&mut self, job: JobId, attempt: u32) {
        for (o, ch) in self.charges.iter_mut() {
            if o.job == job && ch.attempt == attempt {
                ch.replayable = false;
            }
        }
    }

    /// An output of `job` (of `attempt`, if given) is still provisional or contested.
    pub fn has_provisional(&self, job: JobId, attempt: Option<u32>) -> bool {
        self.charges.iter().any(|(o, ch)| {
            o.job == job && !ch.definitive && attempt.is_none_or(|a| ch.attempt == a)
        })
    }

    /// First contested position past its deadline, per type (JOB-R33).
    pub fn contests_due(&self, job: JobId, now: Time) -> BTreeMap<WorkType, u32> {
        let mut first: BTreeMap<WorkType, u32> = BTreeMap::new();
        for (o, ch) in &self.charges {
            if o.job == job && !ch.definitive && ch.contest.is_some_and(|c| now >= c.deadline) {
                let e = first.entry(o.wt).or_insert(o.pos);
                *e = (*e).min(o.pos);
            }
        }
        first
    }

    /// Short witness commitment, kept in log order (JOB-R32). Returns false if it adds nothing.
    pub(crate) fn record_witness_commit(
        &mut self,
        key: (JobId, u32, WorkType),
        upto: u32,
        seq: u64,
    ) -> bool {
        let log = self.witness_commits.entry(key).or_default();
        if log.last().is_some_and(|(u, _)| *u >= upto) {
            return false;
        }
        log.push((upto, seq));
        true
    }

    /// A commitment covering `upto` was recorded before log position `cutoff`.
    pub fn witness_committed_before(
        &self,
        key: (JobId, u32, WorkType),
        upto: u32,
        cutoff: u64,
    ) -> bool {
        self.witness_commits
            .get(&key)
            .is_some_and(|v| v.iter().any(|(u, seq)| *u >= upto && *seq < cutoff))
    }
}
