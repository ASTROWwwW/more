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

    /// Checks a receipt about `lender`'s output on `attempt` and hands its signature to the
    /// ledger, which keeps it only if the recipient named by the assignment signed it.
    fn check_receipt(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        (wt, upto, digest): (WorkType, u32, u64),
        signature: &[u8; 64],
    ) -> R {
        if digest != self.receipt_digest(job, attempt, lender, wt, upto) {
            return Err(DomainError::InadmissibleProof);
        }
        let j = self.job(job)?;
        if j.settle == SettleStatus::Closed {
            return Err(DomainError::Precondition("job settled"));
        }
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if !a.lenders.contains(&lender) {
            return Err(DomainError::Precondition("lender not in attempt"));
        }
        if upto > a.produced[wt.idx()] {
            return Err(DomainError::Precondition("receipt beyond produced"));
        }
        self.ledger_proof(LedgerOp::RecordReceipt {
            job: job_acct(job),
            attempt,
            producer: lender.0,
            wt: wt.idx() as u8,
            upto,
            digest,
            signature: *signature,
        })
    }

    pub(super) fn commit_receipts(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        (wt, upto, digest): (WorkType, u32, u64),
        signature: &[u8; 64],
    ) -> R<Outcome> {
        let prev = self
            .job(job)?
            .attempts
            .get(&attempt)
            .and_then(|a| a.commitments.get(&(lender, wt)))
            .map_or(0, |c| c.0);
        // Checked even when already applied, like any other command (JOB-R04).
        self.check_receipt(job, attempt, lender, (wt, upto, digest), signature)?;
        if upto <= prev {
            return Ok(Outcome::AlreadyApplied);
        }
        let now = self.now;
        self.attempt_mut(job, attempt)?
            .commitments
            .insert((lender, wt), (upto, now));
        // Keep the full history: an older commitment's timestamp still proves what it covered came
        // first (JOB-R12 a).
        let seq = self.seq;
        self.commit_log
            .entry((job, attempt, lender, wt))
            .or_default()
            .push((upto, now, seq));
        Ok(Outcome::Applied)
    }

    /// The producer presents a receipt its recipient co-signed (JOB-R12, LEDGER-016).
    pub(super) fn present_receipt(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        (wt, upto, digest): (WorkType, u32, u64),
        signature: &[u8; 64],
    ) -> R<Outcome> {
        self.check_receipt(job, attempt, lender, (wt, upto, digest), signature)?;
        let key = (job, attempt, lender, wt);
        if self.presented.get(&key).is_some_and(|u| *u >= upto) {
            return Ok(Outcome::AlreadyApplied);
        }
        self.presented.insert(key, upto);
        Ok(Outcome::Applied)
    }

    /// A receipt signed by the recipient, committed or presented, covers position `pos`. This is
    /// what the ledger requires to pay a contribution (LEDGER-016).
    pub fn receipt_covers(
        &self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        pos: u32,
    ) -> bool {
        let key = (job, attempt, lender, wt);
        let committed = self
            .commit_log
            .get(&key)
            .is_some_and(|v| v.iter().any(|(upto, _, _)| *upto > pos));
        committed || self.presented.get(&key).is_some_and(|u| *u > pos)
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
