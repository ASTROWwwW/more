//! Job lifecycle: submission, reservation, pauses, resumes, terminal states (JOB-T01 to JOB-T17).

use super::*;

impl Coordinator {
    /// Advances the coordinator clock. SAFE-001: time stays below `MAX_TIME`, so `time + duration`
    /// never overflows.
    pub(super) fn tick(&mut self, dt: Time) -> R<Outcome> {
        self.now = self
            .now
            .checked_add(dt)
            .filter(|t| *t <= MAX_TIME)
            .ok_or(DomainError::Overflow("clock beyond MAX_TIME"))?;
        Ok(Outcome::Applied)
    }

    /// LEDGER-003. The treasury's own credential goes to the ledger: the orchestrator cannot issue.
    pub(super) fn issue(
        &mut self,
        ctx: &AuthContext,
        id: u32,
        to: IssueTarget,
        amount: Amount,
    ) -> R<Outcome> {
        let to = match to {
            IssueTarget::User(a) => IssueTo::User(a.0),
            IssueTarget::Pool(p) => {
                self.registry.pool(p)?;
                IssueTo::Pool(p.0)
            }
        };
        let treasury = ctx
            .credential()
            .ok_or(DomainError::Unauthorized("only the treasury issues"))?;
        let op = LedgerOp::Issue {
            key: format!("issue/{id}"),
            to,
            amount,
        };
        match self.ledger.execute(treasury, op) {
            Ok(_) => Ok(Outcome::Applied),
            Err(LedgerApiError::Ledger(LedgerError::DuplicateKey(_))) => {
                Ok(Outcome::AlreadyApplied)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// JOB-T03.
    pub(super) fn reject_queued(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Queued, "JOB-T03")?;
        self.set_exec(job, ExecStatus::Cancelled, "JOB-T03")?;
        self.set_settle(job, SettleStatus::Closed, "JOB-S13")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T08.
    pub(super) fn node_lost(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Running, "JOB-T08")?;
        self.revoke_current(job)?;
        self.job_mut(job)?.intent = Intent::Resume;
        self.set_exec(job, ExecStatus::Recovering, "JOB-T08")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T11.
    pub(super) fn pause(&mut self, job: JobId, reason: PauseReason) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Running, "JOB-T11")?;
        self.revoke_current(job)?;
        let j = self.job_mut(job)?;
        j.checkpoint = true;
        j.pause_reason = Some(reason);
        if j.delivered.iter().any(|v| *v > 0) {
            j.intent = Intent::Resume;
        }
        self.set_exec(job, ExecStatus::Paused, "JOB-T11")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T10.
    pub(super) fn recovery_timeout(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Recovering, "JOB-T10")?;
        let j = self.job_mut(job)?;
        j.checkpoint = true;
        j.pause_reason = None;
        self.set_exec(job, ExecStatus::Paused, "JOB-T10")?;
        Ok(Outcome::Applied)
    }

    /// JOB-R18: the pool relays the recovery budget.
    pub(super) fn fund_recovery(
        &mut self,
        job: JobId,
        amount: Amount,
        signature: &[u8; 64],
    ) -> R<Outcome> {
        if !self.is_credits(job)? {
            return Err(DomainError::Precondition(
                "free pool has no recovery escrow",
            ));
        }
        let j = self.job(job)?;
        // CE-01: the pool may only fund a job with active escrow, otherwise nobody owns those
        // credits.
        if j.settle != SettleStatus::Active {
            return Err(DomainError::Precondition("JOB-R18: settlement not active"));
        }
        let unearmarked = add(j.recovery_unearmarked, amount, "recovery budget")?;
        let funded = add(j.pool_recovery_funded, amount, "pool relay")?;
        // The ledger checks the admin's signature over the new total itself: the orchestrator
        // cannot move the pool's treasury on its own.
        self.ledger_proof(LedgerOp::FundRecovery {
            job: job_acct(job),
            amount,
            signature: *signature,
        })?;
        let j = self.job_mut(job)?;
        j.recovery_unearmarked = unearmarked;
        j.pool_recovery_funded = funded;
        Ok(Outcome::Applied)
    }

    /// The platform admin creates a pool; its own credential tells the ledger who administers
    /// the pool's treasury, so the orchestrator cannot name an admin of its choice.
    pub(super) fn create_pool(
        &mut self,
        ctx: &AuthContext,
        pool: PoolId,
        mode: PoolMode,
        access: crate::registry::PoolAccess,
        admin: AccountId,
    ) -> R<Outcome> {
        let out = self.registry.create(pool, mode, access, admin)?;
        if out == Outcome::Applied {
            let platform = ctx
                .credential()
                .ok_or(DomainError::Unauthorized("only the platform admin"))?;
            let op = LedgerOp::RegisterPool {
                pool: pool.0,
                admin: admin.0,
            };
            self.ledger.execute(platform, op)?;
        }
        Ok(out)
    }

    /// JOB-T13: every produced unit is delivered (attested or acked).
    pub(super) fn finish(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Running, "JOB-T13")?;
        let j = self.job(job)?;
        let a = j
            .current()
            .ok_or_else(|| DomainError::Internal("no attempt".into()))?;
        if a.produced != j.delivered {
            return Err(DomainError::Precondition("JOB-T13: undelivered output"));
        }
        self.revoke_current(job)?;
        self.set_exec(job, ExecStatus::Settling, "JOB-T13")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T14.
    pub(super) fn complete_settling(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Settling, "JOB-T14")?;
        let busy = self.slices_of(job, None).iter().any(|s| {
            matches!(
                self.slices[s].status,
                SliceStatus::Open | SliceStatus::Draining
            )
        });
        if busy {
            return Err(DomainError::Precondition(
                "JOB-T14: slices still open or draining",
            ));
        }
        self.set_exec(job, ExecStatus::Completed, "JOB-T14")?;
        self.set_settle(job, SettleStatus::Finalizing, "JOB-S11")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T17.
    pub(super) fn expire_pause(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Paused, "JOB-T17")?;
        if self.now < self.job(job)?.exec_since + self.cfg.pause_max {
            return Err(DomainError::Precondition("JOB-T17: pause not expired"));
        }
        self.job_mut(job)?.checkpoint = false;
        self.set_exec(job, ExecStatus::Cancelled, "JOB-T17")?;
        self.set_settle(job, SettleStatus::Finalizing, "JOB-S11")?;
        Ok(Outcome::Applied)
    }

    /// JOB-T01. The price is the pool's tariff for the model; the client only chooses how many
    /// outputs it wants and signs the most it agrees to lock (SEC-002).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn submit(
        &mut self,
        job: JobId,
        borrower: AccountId,
        pool: PoolId,
        model: ModelId,
        outputs: PerType<u32>,
        max_budget: Amount,
        mandate: &[u8; 64],
    ) -> R<Outcome> {
        let p = self.registry.pool(pool)?;
        if let Some(existing) = self.jobs.get(&job) {
            // JOB-T01: same idempotency key returns the existing job.
            let same = existing.borrower == borrower
                && existing.pool == pool
                && existing.model == model
                && existing.max_outputs == outputs
                && existing.max_budget == max_budget;
            return if same {
                Ok(Outcome::AlreadyApplied)
            } else {
                Err(DomainError::Precondition(
                    "job id reused with other parameters",
                ))
            };
        }
        let spec = *p
            .model(model)
            .ok_or(DomainError::InvalidInput("model not in the pool's catalog"))?;
        if outputs.iter().zip(spec.max_outputs).any(|(o, m)| *o > m) {
            return Err(DomainError::InvalidInput(
                "more outputs than the model allows",
            ));
        }
        if outputs == [0; 3] {
            return Err(DomainError::InvalidInput("no output requested"));
        }
        let price = spec.price;
        let mut est_cost: Amount = 0;
        for t in 0..3 {
            let part = price[t]
                .checked_mul(Amount::from(outputs[t]))
                .ok_or(DomainError::Overflow("estimated cost"))?;
            est_cost = add(est_cost, part, "estimated cost")?;
        }
        let recovery_budget = est_cost
            .checked_mul(self.cfg.recovery_budget_pct)
            .ok_or(DomainError::Overflow("recovery budget"))?
            / 100;
        let needed = add(est_cost, recovery_budget, "job budget")?;
        if needed > max_budget {
            return Err(DomainError::Precondition(
                "JOB-T01: signed budget below the estimated cost",
            ));
        }
        // The ledger checks the borrower's signature over the job's terms itself: a compromised
        // orchestrator cannot open an escrow nobody agreed to, nor change the price or the model's
        // size that shares are computed from.
        self.ledger_op(LedgerOp::OpenEscrow {
            job: job_acct(job),
            owner: borrower.0,
            pool: pool.0,
            terms: JobTerms {
                model: model.0,
                layers: spec.layers,
                price,
                max_outputs: outputs,
                max_budget,
            },
            signature: *mandate,
        })?;
        self.jobs.insert(
            job,
            Job {
                id: job,
                borrower,
                pool,
                stream: fnv(&[u64::from(job.0), u64::from(borrower.0), 0x5354_5245_414d]),
                model,
                model_layers: spec.layers,
                max_budget,
                version: 1,
                exec: ExecStatus::Queued,
                settle: SettleStatus::None,
                intent: Intent::Initial,
                exec_since: self.now,
                placing_from: None,
                placement_failures: 0,
                price,
                max_outputs: outputs,
                est_cost,
                recovery_budget,
                recovery_unearmarked: recovery_budget,
                attempt: 0,
                attempts: BTreeMap::new(),
                validated: [0; 3],
                delivered: [0; 3],
                last_ack_at: self.now,
                checkpoint: false,
                pause_reason: None,
                pool_recovery_funded: 0,
                recovery_paid_borrower: 0,
                recovery_paid_pool: 0,
                recovery_contested_pool: 0,
            },
        );
        self.audit.push(AuditEvent::Exec {
            job,
            from: None,
            to: ExecStatus::Queued,
            rule: "JOB-T01",
        });
        Ok(Outcome::Applied)
    }

    pub(super) fn reserve(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Queued, "JOB-T02")?;
        let j = self.job(job)?.clone();
        let mode = self.registry.pool(j.pool)?.mode();
        match mode {
            PoolMode::Credits => {
                // Escrow = estimated work + recovery budget (JOB-T02, JOB-R18).
                let initial = j.est_cost.min(self.cfg.initial_reserve_max);
                self.ledger_op(LedgerOp::Reserve {
                    job: job_acct(job),
                    bucket: EscrowBucket::Work,
                    key: format!("reserve/{}/work", job.0),
                    amount: initial,
                })?;
                self.ledger_op(LedgerOp::Reserve {
                    job: job_acct(job),
                    bucket: EscrowBucket::Recovery,
                    key: format!("reserve/{}/recovery", job.0),
                    amount: j.recovery_budget,
                })?;
            }
            PoolMode::FreeShare { quota_per_borrower } => {
                let active = self
                    .jobs
                    .values()
                    .filter(|o| {
                        o.id != job
                            && o.pool == j.pool
                            && o.borrower == j.borrower
                            && o.settle == SettleStatus::Active
                    })
                    .count() as u32;
                if active >= quota_per_borrower {
                    return Err(DomainError::Precondition("JOB-T02: quota exhausted"));
                }
            }
        }
        self.set_settle(job, SettleStatus::Active, "JOB-S10")?;
        self.set_exec(job, ExecStatus::Reserved, "JOB-T02")?;
        Ok(Outcome::Applied)
    }

    pub(super) fn resume(&mut self, job: JobId, topup: Amount) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Paused, "JOB-T12")?;
        let j = self.job(job)?.clone();
        if self.now >= j.exec_since + self.cfg.pause_max {
            return Err(DomainError::Precondition("JOB-T12: pause expired"));
        }
        if self.is_credits(job)? {
            self.ledger_op(LedgerOp::Reserve {
                job: job_acct(job),
                bucket: EscrowBucket::Work,
                key: format!("topup/{}/{}", job.0, j.version),
                amount: topup,
            })?;
            let remaining_needed =
                (0..3).any(|i| j.delivered[i] < j.max_outputs[i] && j.price[i] > 0);
            let min_price = (0..3)
                .filter(|i| j.delivered[*i] < j.max_outputs[*i])
                .map(|i| j.price[i])
                .filter(|p| *p > 0)
                .min()
                .unwrap_or(0);
            if remaining_needed && self.escrow_work(job)? < min_price {
                return Err(DomainError::Precondition(
                    "JOB-T12: escrow cannot cover one output",
                ));
            }
        } else if topup != 0 {
            return Err(DomainError::Precondition("free pool takes no credits"));
        }
        // execution_intent kept (JOB-T12).
        self.set_exec(job, ExecStatus::Reserved, "JOB-T12")?;
        Ok(Outcome::Applied)
    }

    pub(super) fn terminate(
        &mut self,
        job: JobId,
        to: ExecStatus,
        rule: &'static str,
    ) -> R<Outcome> {
        let j = self.job(job)?;
        if j.exec == ExecStatus::Settling {
            return Err(DomainError::JobSettling);
        }
        if j.exec.is_terminal() {
            return Err(DomainError::InvalidTransition { from: j.exec, rule });
        }
        let settle = j.settle;
        self.revoke_current(job)?;
        self.set_exec(job, to, rule)?;
        match settle {
            SettleStatus::Active => self.set_settle(job, SettleStatus::Finalizing, "JOB-S11")?,
            SettleStatus::None => self.set_settle(job, SettleStatus::Closed, "JOB-S13")?,
            other => {
                return Err(DomainError::Internal(format!(
                    "terminate with settle {other:?}"
                )))
            }
        }
        Ok(Outcome::Applied)
    }
}
