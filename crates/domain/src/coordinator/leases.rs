//! Per-node leases (JOB-R38, JOB-R39): each stage moves `assigned → accepted → loaded → ready` on
//! its own lender's word, the attempt starts only when every stage is ready, and each node renews
//! only its own lease.

use super::*;

impl Coordinator {
    /// Configuration a stage must load: model, attempt and layer range. Symbolic (FNV-1a) in the
    /// model; the real one hashes the weights' manifest.
    pub fn config_digest(&self, job: JobId, attempt: u32, stage: usize) -> Option<u64> {
        let j = self.jobs.get(&job)?;
        let a = j.attempts.get(&attempt)?;
        let (start, end) = a.layer_range(stage)?;
        Some(fnv(&[
            0x434f_4e46_4947,
            u64::from(job.0),
            u64::from(j.model.0),
            u64::from(attempt),
            stage as u64,
            u64::from(start),
            u64::from(end),
        ]))
    }

    /// The current attempt while it is being placed, and `lender`'s stage in it. Refused once
    /// revoked or once the lender's own lease expired (JOB-R31).
    fn placing_stage(&self, job: JobId, attempt: u32, lender: AccountId) -> R<usize> {
        let j = self.job(job)?;
        if j.exec != ExecStatus::Placing {
            return Err(DomainError::InvalidTransition {
                from: j.exec,
                rule: "JOB-R38",
            });
        }
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if attempt != j.attempt || a.revoked_at.is_some() {
            return Err(DomainError::StaleAttempt);
        }
        let stage = a
            .stage_of(lender)
            .ok_or(DomainError::Precondition("lender not in attempt"))?;
        if self.now >= a.leases[stage].expires_at {
            return Err(DomainError::LeaseExpired);
        }
        Ok(stage)
    }

    /// Moves `lender`'s lease from `from` to the next state. `Ok(false)`: already past `from`.
    fn advance_lease(
        &mut self,
        job: JobId,
        attempt: u32,
        stage: usize,
        from: LeaseState,
        to: LeaseState,
    ) -> R<bool> {
        let lease = &mut self.attempt_mut(job, attempt)?.leases[stage];
        if lease.state >= to {
            return Ok(false);
        }
        if lease.state != from {
            return Err(DomainError::Precondition(
                "JOB-R38: lease state out of order",
            ));
        }
        lease.state = to;
        Ok(true)
    }

    pub(super) fn ledger_proof(&mut self, op: LedgerOp) -> R {
        match self.ledger_op(op) {
            Ok(_) => Ok(()),
            Err(DomainError::Ledger(LedgerApiError::BadProof(_))) => {
                Err(DomainError::InadmissibleProof)
            }
            Err(e) => Err(e),
        }
    }

    pub(super) fn accept_lease(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        signature: &[u8; 64],
    ) -> R<Outcome> {
        let stage = self.placing_stage(job, attempt, lender)?;
        if self.job(job)?.attempts[&attempt].leases[stage].state >= LeaseState::Accepted {
            return Ok(Outcome::AlreadyApplied);
        }
        self.ledger_proof(LedgerOp::AcceptLease {
            job: job_acct(job),
            attempt,
            stage: stage as u32,
            signature: *signature,
        })?;
        self.advance_lease(
            job,
            attempt,
            stage,
            LeaseState::Assigned,
            LeaseState::Accepted,
        )?;
        self.audit.push(AuditEvent::Lease {
            job,
            attempt,
            lender,
            state: LeaseState::Accepted,
        });
        Ok(Outcome::Applied)
    }

    pub(super) fn lease_loaded(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        config: u64,
    ) -> R<Outcome> {
        let stage = self.placing_stage(job, attempt, lender)?;
        if self.config_digest(job, attempt, stage) != Some(config) {
            return Err(DomainError::InadmissibleProof);
        }
        if !self.advance_lease(
            job,
            attempt,
            stage,
            LeaseState::Accepted,
            LeaseState::Loaded,
        )? {
            return Ok(Outcome::AlreadyApplied);
        }
        self.audit.push(AuditEvent::Lease {
            job,
            attempt,
            lender,
            state: LeaseState::Loaded,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-T05: the lender's state is restored to the last delivered position (0 on a first
    /// start). The attempt starts on the last ready lease.
    pub(super) fn attempt_ready(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        (restored, commitment): (PerType<u32>, u64),
        signature: &[u8; 64],
    ) -> R<Outcome> {
        let stage = self.placing_stage(job, attempt, lender)?;
        let j = self.job(job)?;
        let state = j.attempts[&attempt].leases[stage].state;
        if state == LeaseState::Ready {
            return Ok(Outcome::AlreadyApplied);
        }
        if state != LeaseState::Loaded {
            return Err(DomainError::Precondition("JOB-R38: lease not loaded"));
        }
        if restored != j.delivered {
            return Err(DomainError::Precondition(
                "JOB-T05: state not restored to last delivered position",
            ));
        }
        self.ledger_proof(LedgerOp::LeaseReady {
            job: job_acct(job),
            attempt,
            stage: stage as u32,
            restored,
            state: commitment,
            signature: *signature,
        })?;
        self.advance_lease(job, attempt, stage, LeaseState::Loaded, LeaseState::Ready)?;
        self.attempt_mut(job, attempt)?.leases[stage].restored = Some(Restored {
            positions: restored,
            state: commitment,
        });
        self.audit.push(AuditEvent::Lease {
            job,
            attempt,
            lender,
            state: LeaseState::Ready,
        });
        let now = self.now;
        let j = self.job_mut(job)?;
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?;
        if a.leases.iter().any(|l| l.state != LeaseState::Ready) {
            return Ok(Outcome::Applied);
        }
        a.ready = true;
        j.last_ack_at = now;
        let (intent, validated, delivered) = (j.intent, j.validated, j.delivered);
        self.audit.push(AuditEvent::AttemptStarted {
            job,
            attempt,
            intent,
            restored,
            validated,
            delivered,
        });
        self.set_exec(job, ExecStatus::Running, "JOB-T05")?;
        self.open_slice(job, attempt)?;
        Ok(Outcome::Applied)
    }

    /// JOB-R18: the recipient of `lender`'s output attests that it received `lender`'s restored
    /// state. Without it, `lender`'s recovery work is never paid automatically. The statement is
    /// about the past: it is accepted after a revocation, until the job is settled.
    pub(super) fn corroborate_restore(
        &mut self,
        job: JobId,
        attempt: u32,
        lender: AccountId,
        segments: u32,
        signature: &[u8; 64],
    ) -> R<Outcome> {
        let j = self.job(job)?;
        if j.settle == SettleStatus::Closed {
            return Err(DomainError::Precondition("job settled"));
        }
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        let stage = a
            .stage_of(lender)
            .ok_or(DomainError::Precondition("lender not in attempt"))?;
        let lease = a.leases[stage];
        if lease.state != LeaseState::Ready {
            return Err(DomainError::Precondition(
                "JOB-R18: nothing restored to corroborate",
            ));
        }
        // The first corroboration is final: the same one again changes nothing, another one is
        // refused, so a proof a payment relied on cannot be replaced.
        match lease.corroborated {
            Some(n) if n == segments => return Ok(Outcome::AlreadyApplied),
            Some(_) => {
                return Err(DomainError::Precondition(
                    "JOB-R18: restoration already corroborated",
                ))
            }
            None => {}
        }
        if segments == 0 {
            return Err(DomainError::InvalidInput("no segment corroborated"));
        }
        self.ledger_proof(LedgerOp::RecordRestore {
            job: job_acct(job),
            attempt,
            producer: lender.0,
            segments,
            signature: *signature,
        })?;
        self.attempt_mut(job, attempt)?.leases[stage].corroborated = Some(segments);
        self.audit.push(AuditEvent::RestoreCorroborated {
            job,
            attempt,
            lender,
            segments,
        });
        Ok(Outcome::Applied)
    }

    /// The live attempt of `job`, for a renewal. An expired lease is never renewed (JOB-R31).
    fn renewable(&self, job: JobId, attempt: u32) -> R<&Attempt> {
        let j = self.job(job)?;
        if attempt != j.attempt || !matches!(j.exec, ExecStatus::Placing | ExecStatus::Running) {
            return Err(DomainError::StaleAttempt);
        }
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if a.revoked_at.is_some() {
            return Err(DomainError::StaleAttempt);
        }
        Ok(a)
    }

    /// JOB-R39: renews `lender`'s lease only; a live node never keeps a silent one alive.
    pub(super) fn heartbeat(&mut self, job: JobId, attempt: u32, lender: AccountId) -> R<Outcome> {
        let now = self.now;
        let ttl = self.cfg.lease_ttl;
        let a = self.renewable(job, attempt)?;
        let stage = a
            .stage_of(lender)
            .ok_or(DomainError::Precondition("lender not in attempt"))?;
        let lease = a.leases[stage];
        if now >= lease.expires_at {
            return Err(DomainError::LeaseExpired);
        }
        if lease.expires_at == now + ttl {
            return Ok(Outcome::AlreadyApplied);
        }
        self.attempt_mut(job, attempt)?.leases[stage].expires_at = now + ttl;
        Ok(Outcome::Applied)
    }

    /// JOB-R39: the witness renews its own lease, independently of the lenders.
    pub(super) fn witness_heartbeat(
        &mut self,
        job: JobId,
        attempt: u32,
        witness: AccountId,
    ) -> R<Outcome> {
        let now = self.now;
        let ttl = self.cfg.lease_ttl;
        let a = self.renewable(job, attempt)?;
        if a.witness != witness {
            return Err(DomainError::Precondition("not the attempt's witness"));
        }
        if now >= a.witness_expires_at {
            return Err(DomainError::LeaseExpired);
        }
        if a.witness_expires_at == now + ttl {
            return Ok(Outcome::AlreadyApplied);
        }
        self.attempt_mut(job, attempt)?.witness_expires_at = now + ttl;
        Ok(Outcome::Applied)
    }
}
