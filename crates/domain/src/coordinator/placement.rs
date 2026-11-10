//! Placement and production: attempts, placement failures, the live-attempt check (JOB-T04 to
//! JOB-T09, JOB-R13, JOB-R25, JOB-R31). Leases are in `leases.rs`.

use super::*;

impl Coordinator {
    pub(super) fn place(
        &mut self,
        job: JobId,
        lenders: &[AccountId],
        layout: &[u32],
        recovery_estimate: Amount,
        witness: AccountId,
    ) -> R<Outcome> {
        let now = self.now;
        let ttl = self.cfg.lease_ttl;
        let max_attempts = self.cfg.max_attempts;
        let j = self.job(job)?;
        let from = j.exec;
        let rule = match from {
            ExecStatus::Reserved => "JOB-T04",
            ExecStatus::Recovering => "JOB-T09",
            _ => {
                return Err(DomainError::InvalidTransition {
                    from,
                    rule: "JOB-T04/T09",
                })
            }
        };
        // Layout chosen by the scheduler: one non-empty range per lender, covering the model.
        if lenders.is_empty() || lenders.len() != layout.len() || layout.contains(&0) {
            return Err(DomainError::Precondition("one lender per layer range"));
        }
        let covered = layout
            .iter()
            .try_fold(0u32, |acc, l| acc.checked_add(*l))
            .ok_or(DomainError::Overflow("layout"))?;
        if covered != j.model_layers {
            return Err(DomainError::Precondition("layout does not cover the model"));
        }
        // JOB-T04: one layer range per lender. Two ranges on one account would let it commit its
        // own receipts (SAFE-002).
        let mut seen = std::collections::BTreeSet::new();
        if !lenders.iter().all(|l| seen.insert(*l)) {
            return Err(DomainError::Precondition(
                "JOB-T04: a lender holds one range only",
            ));
        }
        let pool = self.registry.pool(j.pool)?;
        if !lenders.iter().all(|l| pool.rights(*l).lend) {
            return Err(DomainError::Precondition(
                "lender without the lend right in this pool",
            ));
        }
        if !pool.rights(witness).witness {
            return Err(DomainError::Precondition(
                "witness without the witness right in this pool",
            ));
        }
        if j.attempt >= max_attempts {
            return Err(DomainError::Precondition("max attempts reached: JOB-T16"));
        }
        // JOB-R26: the witness is independent of lenders and borrower.
        if witness == j.borrower || lenders.contains(&witness) {
            return Err(DomainError::Precondition(
                "JOB-R26: witness not independent",
            ));
        }
        // JOB-R18: a resume starts only if its recompute is funded.
        if j.intent == Intent::Resume {
            if recovery_estimate > j.recovery_unearmarked {
                return Err(DomainError::RecoveryBudget);
            }
        } else if recovery_estimate != 0 {
            return Err(DomainError::Precondition(
                "no recovery work on an initial placement",
            ));
        }
        let unearmarked = sub(j.recovery_unearmarked, recovery_estimate, "recovery budget")?;
        let no = j
            .attempt
            .checked_add(1)
            .ok_or(DomainError::Overflow("attempt"))?;
        // LEDGER-015: the ledger records the cluster before anyone can be paid for it; its lenders
        // then sign it one by one.
        self.ledger_op(LedgerOp::RegisterAttempt {
            assignment: Assignment {
                job: job_acct(job),
                attempt: no,
                lenders: lenders.iter().map(|l| l.0).collect(),
                layout: layout.to_vec(),
                witness: witness.0,
                recovery_earmark: recovery_estimate,
            },
        })?;
        let j = self.job_mut(job)?;
        j.recovery_unearmarked = unearmarked;
        j.attempt = no;
        // Start from delivered positions: they get replayed, never regenerated (JOB-R28).
        let produced = j.delivered;
        let lease = Lease {
            state: LeaseState::Assigned,
            expires_at: now + ttl,
            restored: None,
            corroborated: None,
        };
        j.attempts.insert(
            no,
            Attempt {
                no,
                lenders: lenders.to_vec(),
                layout: layout.to_vec(),
                issued_at: now,
                witness,
                leases: vec![lease; lenders.len()],
                witness_expires_at: now + ttl,
                witness_lost: false,
                buffer_purged: false,
                revoked_at: None,
                revoked_seq: None,
                ready: false,
                produced,
                commitments: BTreeMap::new(),
                recovery_earmark: recovery_estimate,
                recovery_reserved: 0,
                earmark_returned: false,
                next_slice: 0,
            },
        );
        j.placing_from = Some(from);
        self.set_exec(job, ExecStatus::Placing, rule)?;
        Ok(Outcome::Applied)
    }

    pub(super) fn placement_failed(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Placing, "JOB-T06")?;
        self.revoke_current(job)?;
        let max = self.cfg.max_placement_failures;
        let j = self.job_mut(job)?;
        j.placement_failures += 1;
        let back = j
            .placing_from
            .ok_or_else(|| DomainError::Internal("placing_from".into()))?;
        if j.placement_failures >= max {
            return self.terminate(job, ExecStatus::Failed, "JOB-T16");
        }
        self.set_exec(job, back, "JOB-T06")?;
        Ok(Outcome::Applied)
    }

    pub(super) fn current_live_attempt(&self, job: JobId, attempt: u32) -> R<&Attempt> {
        let j = self.job(job)?;
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if attempt != j.attempt
            || a.revoked_at.is_some()
            || !a.ready
            || j.exec != ExecStatus::Running
        {
            return Err(DomainError::StaleAttempt);
        }
        // JOB-R31, JOB-R39: the pipeline needs every node; nothing is accepted once any of their
        // leases expired, even before reconciliation revokes the attempt.
        if a.any_expired(self.now) {
            return Err(DomainError::LeaseExpired);
        }
        Ok(a)
    }

    pub(super) fn produce(
        &mut self,
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    ) -> R<Outcome> {
        let a = self.current_live_attempt(job, attempt)?;
        let j = self.job(job)?;
        let t = wt.idx();
        if upto <= a.produced[t] {
            return Err(DomainError::Precondition("no progress"));
        }
        if upto > j.max_outputs[t] {
            return Err(DomainError::Precondition("beyond max outputs"));
        }
        // JOB-R13: produced and unacked units stay within the flow budget.
        let unacked = upto
            .checked_sub(j.validated[t])
            .ok_or_else(|| DomainError::Internal("produced below validated".into()))?;
        if unacked > self.cfg.flow_budget[t] {
            return Err(DomainError::FlowBudgetExceeded);
        }
        // JOB-R25: produced but not yet charged units must be covered by work escrow.
        let mut produced = a.produced;
        produced[t] = upto;
        let mut window: Amount = 0;
        for ((p, d), price) in produced.iter().zip(j.delivered).zip(j.price) {
            let units = p
                .checked_sub(d)
                .ok_or_else(|| DomainError::Internal("delivered beyond produced".into()))?;
            let part = price
                .checked_mul(Amount::from(units))
                .ok_or(DomainError::Overflow("window"))?;
            window = add(window, part, "window")?;
        }
        if window > self.escrow_work(job)? {
            return Err(DomainError::WindowNotCovered);
        }
        let from = a.produced[t];
        self.attempt_mut(job, attempt)?.produced[t] = upto;
        self.audit.push(AuditEvent::Produced {
            job,
            attempt,
            wt,
            from,
            to: upto,
        });
        Ok(Outcome::Applied)
    }
}
