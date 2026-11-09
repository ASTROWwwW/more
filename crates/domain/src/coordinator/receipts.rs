//! Receipt commitments and their precedence (JOB-R12, JOB-R15, SEC-004).

use super::*;

impl Coordinator {
    /// Digest binding a receipt commitment to its job, attempt, producer, type and covered
    /// positions (SEC-004). Symbolic (FNV-1a) in the model, like the frame digest: the real one
    /// will hash the signed receipts themselves.
    pub fn receipt_digest(
        &self,
        job: JobId,
        attempt: u32,
        producer: AccountId,
        wt: WorkType,
        upto: u32,
    ) -> u64 {
        let stream = self.jobs.get(&job).map_or(0, |j| j.stream);
        fnv(&[
            0x5245_4345_4950_5453,
            u64::from(job.0),
            stream,
            u64::from(attempt),
            u64::from(producer.0),
            wt.idx() as u64,
            u64::from(upto),
        ])
    }

    pub(super) fn commit_receipts(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
    ) -> R<Outcome> {
        if digest != self.receipt_digest(job, attempt, lender, wt, upto) {
            return Err(DomainError::InadmissibleProof);
        }
        let now = self.now;
        let j = self.job_mut(job)?;
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if !a.lenders.contains(&lender) {
            return Err(DomainError::Precondition("lender not in attempt"));
        }
        if upto > a.produced[wt.idx()] {
            return Err(DomainError::Precondition("commitment beyond produced"));
        }
        let prev = a.commitments.get(&(lender, wt)).map_or(0, |c| c.0);
        if upto <= prev {
            return Ok(Outcome::AlreadyApplied);
        }
        a.commitments.insert((lender, wt), (upto, now));
        // Keep the full history: an older commitment's timestamp still proves what it covered came
        // first (JOB-R12 a).
        let seq = self.seq;
        self.commit_log
            .entry((job, attempt, lender, wt))
            .or_default()
            .push((upto, now, seq));
        Ok(Outcome::Applied)
    }

    /// JOB-R12 (a): the position is covered by a commitment recorded, in log order, BEFORE the
    /// earlier of the attempt's revocation and the slice's closure (CE-03).
    pub fn committed_before(
        &self,
        slice: SliceId,
        lender: AccountId,
        wt: WorkType,
        pos: u32,
    ) -> bool {
        let Ok(j) = self.job(slice.job) else {
            return false;
        };
        let Some(a) = j.attempts.get(&slice.attempt) else {
            return false;
        };
        let closed = self
            .slices
            .get(&slice)
            .and_then(|s| s.closed_seq)
            .unwrap_or(self.seq);
        let cutoff = a.revoked_seq.map_or(closed, |r| r.min(closed));
        self.commit_log
            .get(&(slice.job, slice.attempt, lender, wt))
            .is_some_and(|v| v.iter().any(|(upto, _, seq)| *upto > pos && *seq < cutoff))
    }
}
