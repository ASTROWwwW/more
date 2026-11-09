//! Coordinator: applies commands as atomic transitions. `apply` runs a command on a full copy of
//! the state and keeps it only if the whole transition succeeds, the in-memory equivalent of
//! JOB-R01's single transaction.

use std::collections::BTreeMap;

use gpu_ledger::{
    Account, Amount, EscrowBucket, IssueTo, Ledger, LedgerApiError, LedgerOp, LedgerOutcome,
    LedgerService, LineRef, LineSource,
};
use more_identity::{AuthContext, ServiceCredential, ServiceRole};

use crate::authorization::authorize;
use crate::command::{Command, IssueTarget, Outcome};
use crate::config::{Config, MAX_LAYERS, MAX_OUTPUTS, MAX_PRICE, MAX_TIME};
use crate::error::DomainError;
use crate::ids::*;
use crate::model::*;

/// Audit log (JOB-R10), also read by the invariant checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    Exec {
        job: JobId,
        from: Option<ExecStatus>,
        to: ExecStatus,
        rule: &'static str,
    },
    Settle {
        job: JobId,
        from: SettleStatus,
        to: SettleStatus,
        rule: &'static str,
    },
    SliceState {
        slice: SliceId,
        from: Option<SliceStatus>,
        to: SliceStatus,
        rule: &'static str,
    },
    AttemptStarted {
        job: JobId,
        attempt: u32,
        intent: Intent,
        restored: PerType<u32>,
        validated: PerType<u32>,
        delivered: PerType<u32>,
    },
    Produced {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    Validated {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    OutputCharged {
        output: OutputId,
        attempt: u32,
        amount: Amount,
        gen: u32,
        /// Provisional charge on witness attestation (JOB-R27).
        provisional: bool,
    },
    /// Provisional output made definitive (JOB-R27 to JOB-R29).
    OutputConfirmed {
        output: OutputId,
        basis: ChargeBasis,
    },
    /// Provisional output voided by a rewind; price back to escrow (JOB-R29).
    OutputVoided {
        output: OutputId,
        gen: u32,
        amount: Amount,
    },
    /// Output replayed from the witness buffer, not charged again (JOB-R28).
    Replayed {
        output: OutputId,
    },
    /// Contest opened: replay requested, deadline set (JOB-R33).
    ContestOpened {
        output: OutputId,
        deadline: Time,
    },
    /// Full attestation received while draining, covered by a commitment made before revocation
    /// (JOB-R32).
    LateDelivery {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        to: u32,
    },
    BufferPurged {
        job: JobId,
        attempt: u32,
    },
    EvidenceSupplemented {
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: Evidence,
    },
    Delivered {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    Rewound {
        job: JobId,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    /// Contribution to a provisional output, waiting for the output (JOB-R30).
    ItemAwaitingDelivery {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    ItemReserved {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    ItemPaid {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
        evidence: Evidence,
        by_arbitration: bool,
        /// Payment time, used by the sliding cap (JOB-R19).
        at: Time,
    },
    ItemRefunded {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
        reason: RefundReason,
    },
    ItemDisputed {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    RewardReleased {
        slice: SliceId,
        lender: AccountId,
        amount: Amount,
        commission: Amount,
    },
    RewardContested {
        slice: SliceId,
        lender: AccountId,
        amount: Amount,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinator {
    pub cfg: Config,
    pub now: Time,
    /// Ledger service. Private: the orchestrator reaches it only through typed operations, with
    /// its own credential.
    ledger: LedgerService,
    /// The orchestrator's credential towards the ledger (role `Orchestrator`).
    cred: ServiceCredential,
    pub pools: BTreeMap<PoolId, Pool>,
    pub jobs: BTreeMap<JobId, Job>,
    pub slices: BTreeMap<SliceId, Slice>,
    /// Charged output (provisional or definitive) to the attempt that produced it (JOB-R17). Same
    /// keys as `charges`.
    pub outputs: BTreeMap<OutputId, u32>,
    /// Charge in force for each output (JOB-R27).
    pub charges: BTreeMap<OutputId, OutputCharge>,
    /// Next billing generation of each output.
    pub charge_gens: BTreeMap<OutputId, u32>,
    /// Reserved or paid contribution to its slice (JOB-R21).
    pub contributions: BTreeMap<ContributionId, SliceId>,
    /// Reserved or paid recovery work to its slice (JOB-R18).
    pub recovery_items: BTreeMap<RecoveryWorkId, SliceId>,
    /// Payments admitted on uncommitted receipts, per account: (time, amount). Gross amounts; a
    /// refund does not restore quota (JOB-R19).
    pub uncommitted_paid: BTreeMap<AccountId, Vec<(Time, Amount)>>,
    /// Short witness commitments: (job, attempt, type) to [(up to, seq)] (JOB-R32).
    pub witness_commits: BTreeMap<(JobId, u32, WorkType), Vec<(u32, u64)>>,
    /// Receipt commitment history: (covered up to, time, seq) (JOB-R15).
    pub commit_log: CommitLog,
    /// Logical sequence number: total order of applied commands (CE-03).
    pub seq: u64,
    pub audit: Vec<AuditEvent>,
}

type R<T = ()> = Result<T, DomainError>;

/// (job, attempt, producer, type) to [(covered up to, time, seq)].
pub type CommitLog = BTreeMap<(JobId, u32, AccountId, WorkType), Vec<(u32, Time, u64)>>;

fn job_acct(j: JobId) -> u32 {
    j.0
}

fn line_ref(s: SliceId, lender: AccountId) -> LineRef {
    LineRef {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

fn add(a: Amount, b: Amount, what: &'static str) -> R<Amount> {
    a.checked_add(b).ok_or(DomainError::Overflow(what))
}

/// Subtraction on internal counters: going below zero is a model bug, never an input error.
fn sub(a: Amount, b: Amount, what: &'static str) -> R<Amount> {
    a.checked_sub(b)
        .ok_or_else(|| DomainError::Internal(format!("{what}: {a} - {b}")))
}

impl Coordinator {
    /// `ledger` is the Ledger service; `cred` must be an Orchestrator credential it accepts.
    pub fn new(cfg: Config, ledger: LedgerService, cred: ServiceCredential) -> R<Self> {
        cfg.validate().map_err(DomainError::InvalidInput)?;
        if cred.role() != ServiceRole::Orchestrator {
            return Err(DomainError::InvalidInput(
                "orchestrator credential expected",
            ));
        }
        Ok(Coordinator {
            cfg,
            now: 0,
            ledger,
            cred,
            pools: BTreeMap::new(),
            jobs: BTreeMap::new(),
            slices: BTreeMap::new(),
            outputs: BTreeMap::new(),
            charges: BTreeMap::new(),
            charge_gens: BTreeMap::new(),
            contributions: BTreeMap::new(),
            recovery_items: BTreeMap::new(),
            uncommitted_paid: BTreeMap::new(),
            witness_commits: BTreeMap::new(),
            commit_log: BTreeMap::new(),
            seq: 0,
            audit: Vec::new(),
        })
    }

    /// Authorizes then applies a command atomically. An unauthorized command is refused before
    /// anything is touched (SEC-001).
    pub fn execute(&mut self, ctx: &AuthContext, cmd: &Command) -> R<Outcome> {
        authorize(self, ctx, cmd)?;
        let mut next = self.clone();
        let out = next.step(ctx, cmd)?;
        // An already applied command changes nothing, not even the sequence (JOB-R04).
        if out == Outcome::Applied {
            *self = next;
        }
        Ok(out)
    }

    /// Full read access to the ledger, for the Auditor role only.
    pub fn audit_ledger(&self, auditor: &ServiceCredential) -> R<&Ledger> {
        Ok(self.ledger.audit_view(auditor)?)
    }

    /// The ledger service itself, read-only, for audits of escrows and denials.
    pub fn ledger_service(&self) -> &LedgerService {
        &self.ledger
    }

    fn ledger_op(&mut self, op: LedgerOp) -> R<LedgerOutcome> {
        Ok(self.ledger.execute(&self.cred, op)?)
    }

    fn escrow_work(&self, job: JobId) -> R<Amount> {
        Ok(self
            .ledger
            .job_balance(&self.cred, Account::EscrowWork(job_acct(job)))?)
    }

    pub fn job(&self, id: JobId) -> R<&Job> {
        self.jobs.get(&id).ok_or(DomainError::UnknownJob(id))
    }

    fn job_mut(&mut self, id: JobId) -> R<&mut Job> {
        self.jobs.get_mut(&id).ok_or(DomainError::UnknownJob(id))
    }

    fn slice_mut(&mut self, id: SliceId) -> R<&mut Slice> {
        self.slices
            .get_mut(&id)
            .ok_or(DomainError::UnknownSlice(id))
    }

    fn attempt_mut(&mut self, job: JobId, attempt: u32) -> R<&mut Attempt> {
        self.job_mut(job)?
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal(format!("missing attempt {attempt}")))
    }

    fn line_mut(&mut self, slice: SliceId, lender: AccountId) -> R<&mut Line> {
        self.slice_mut(slice)?
            .lines
            .get_mut(&lender)
            .ok_or_else(|| DomainError::Internal(format!("missing line {lender:?}")))
    }

    fn is_credits(&self, job: JobId) -> R<bool> {
        let pool = self.job(job)?.pool;
        let p = self.pools.get(&pool).ok_or(DomainError::UnknownPool)?;
        Ok(matches!(p.mode, PoolMode::Credits))
    }

    fn check_version(&self, job: JobId, expected: Option<u64>) -> R {
        if let Some(e) = expected {
            let actual = self.job(job)?.version;
            if e != actual {
                return Err(DomainError::VersionConflict {
                    expected: e,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn set_exec(&mut self, job: JobId, to: ExecStatus, rule: &'static str) -> R {
        let now = self.now;
        let j = self.job_mut(job)?;
        let from = j.exec;
        if !ExecStatus::allowed(from, to) {
            return Err(DomainError::InvalidTransition { from, rule });
        }
        j.exec = to;
        j.exec_since = now;
        j.version += 1;
        self.audit.push(AuditEvent::Exec {
            job,
            from: Some(from),
            to,
            rule,
        });
        Ok(())
    }

    fn set_settle(&mut self, job: JobId, to: SettleStatus, rule: &'static str) -> R {
        let j = self.job_mut(job)?;
        let from = j.settle;
        let ok = matches!(
            (from, to),
            (SettleStatus::None, SettleStatus::Active)
                | (SettleStatus::Active, SettleStatus::Finalizing)
                | (SettleStatus::Finalizing, SettleStatus::Closed)
                | (SettleStatus::None, SettleStatus::Closed)
        );
        if !ok {
            return Err(DomainError::Internal(format!("settle {from:?} -> {to:?}")));
        }
        j.settle = to;
        j.version += 1;
        self.audit.push(AuditEvent::Settle {
            job,
            from,
            to,
            rule,
        });
        Ok(())
    }

    fn set_slice(&mut self, id: SliceId, to: SliceStatus, rule: &'static str) -> R {
        let now = self.now;
        let s = self.slice_mut(id)?;
        let from = s.status;
        if !SliceStatus::allowed(from, to) {
            return Err(DomainError::InvalidSliceTransition { from, rule });
        }
        s.status = to;
        let seq = self.seq;
        let s = self.slice_mut(id)?;
        match to {
            SliceStatus::Closed => {
                s.closed_at = Some(now);
                s.closed_seq = Some(seq);
            }
            SliceStatus::Final => s.final_at = Some(now),
            _ => {}
        }
        self.audit.push(AuditEvent::SliceState {
            slice: id,
            from: Some(from),
            to,
            rule,
        });
        Ok(())
    }

    fn open_slice(&mut self, job: JobId, attempt: u32) -> R {
        let now = self.now;
        let a = self
            .job_mut(job)?
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?;
        a.next_slice += 1;
        let id = SliceId {
            job,
            attempt,
            slice: a.next_slice,
        };
        self.slices.insert(
            id,
            Slice {
                id,
                status: SliceStatus::Open,
                opened_at: now,
                receipt_deadline: None,
                closed_at: None,
                closed_seq: None,
                final_at: None,
                staged: Vec::new(),
                lines: BTreeMap::new(),
                rejected_items: 0,
            },
        );
        self.audit.push(AuditEvent::SliceState {
            slice: id,
            from: None,
            to: SliceStatus::Open,
            rule: "JOB-S01",
        });
        Ok(())
    }

    fn slices_of(&self, job: JobId, attempt: Option<u32>) -> Vec<SliceId> {
        self.slices
            .keys()
            .filter(|s| s.job == job && attempt.is_none_or(|a| s.attempt == a))
            .copied()
            .collect()
    }

    /// Revokes the current attempt (JOB-R11); its open slices start draining (JOB-S02).
    fn revoke_current(&mut self, job: JobId) -> R {
        let now = self.now;
        let seq = self.seq;
        let drain = self.cfg.drain_window;
        let j = self.job_mut(job)?;
        let attempt = j.attempt;
        let Some(a) = j.attempts.get_mut(&attempt) else {
            return Ok(());
        };
        if a.revoked_at.is_some() {
            return Ok(());
        }
        a.revoked_at = Some(now);
        a.revoked_seq = Some(seq);
        for id in self.slices_of(job, Some(attempt)) {
            if self.slices[&id].status == SliceStatus::Open {
                self.set_slice(id, SliceStatus::Draining, "JOB-S02")?;
                self.slice_mut(id)?.receipt_deadline = Some(now + drain);
            }
        }
        self.maybe_return_earmark(job, attempt)
    }

    /// Returns an attempt's unused recovery share to the budget once it is revoked and all its
    /// slices are final (JOB-R18).
    fn maybe_return_earmark(&mut self, job: JobId, attempt: u32) -> R {
        let all_final = self
            .slices_of(job, Some(attempt))
            .iter()
            .all(|s| self.slices[s].status == SliceStatus::Final);
        let j = self.job_mut(job)?;
        let Some(a) = j.attempts.get_mut(&attempt) else {
            return Ok(());
        };
        if a.revoked_at.is_none() || a.earmark_returned || !all_final {
            return Ok(());
        }
        let unused = a
            .recovery_earmark
            .checked_sub(a.recovery_reserved)
            .ok_or_else(|| DomainError::Internal("recovery reserved > earmark".into()))?;
        a.earmark_returned = true;
        j.recovery_unearmarked = add(j.recovery_unearmarked, unused, "recovery budget")?;
        Ok(())
    }

    fn step(&mut self, ctx: &AuthContext, cmd: &Command) -> R<Outcome> {
        use Command::*;
        // Rejected commands roll back with the rest of the state, so sequence numbers have no gaps.
        self.seq += 1;
        match cmd {
            Tick { dt } => {
                // SAFE-001: time stays below MAX_TIME, so `time + duration` never overflows.
                let now = self
                    .now
                    .checked_add(*dt)
                    .filter(|t| *t <= MAX_TIME)
                    .ok_or(DomainError::Overflow("clock beyond MAX_TIME"))?;
                self.now = now;
                Ok(Outcome::Applied)
            }
            Issue { id, to, amount } => {
                let to = match to {
                    IssueTarget::User(a) => IssueTo::User(a.0),
                    IssueTarget::Pool(p) => {
                        if !self.pools.contains_key(p) {
                            return Err(DomainError::UnknownPool);
                        }
                        IssueTo::Pool(p.0)
                    }
                };
                // The treasury's own credential goes to the ledger: the orchestrator cannot issue.
                let treasury = ctx
                    .credential()
                    .ok_or(DomainError::Unauthorized("only the treasury issues"))?;
                let op = LedgerOp::Issue {
                    key: format!("issue/{id}"),
                    to,
                    amount: *amount,
                };
                match self.ledger.execute(treasury, op) {
                    Ok(_) => Ok(Outcome::Applied),
                    Err(LedgerApiError::Ledger(gpu_ledger::LedgerError::DuplicateKey(_))) => {
                        Ok(Outcome::AlreadyApplied)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            CreatePool {
                pool,
                mode,
                access,
                admin,
            } => self.create_pool(*pool, *mode, *access, *admin),
            SetRights {
                pool,
                account,
                rights,
            } => self.set_rights(*pool, *account, *rights),
            JoinPool { pool, account } => self.join_pool(*pool, *account),
            RegisterModel { pool, model, spec } => self.register_model(*pool, *model, *spec),
            Submit {
                job,
                borrower,
                pool,
                model,
                outputs,
                max_budget,
                mandate,
            } => self.submit(
                *job,
                *borrower,
                *pool,
                *model,
                *outputs,
                *max_budget,
                mandate,
            ),
            Reserve { job } => self.reserve(*job),
            RejectQueued { job } => {
                if self.job(*job)?.exec != ExecStatus::Queued {
                    return Err(DomainError::InvalidTransition {
                        from: self.job(*job)?.exec,
                        rule: "JOB-T03",
                    });
                }
                self.set_exec(*job, ExecStatus::Cancelled, "JOB-T03")?;
                self.set_settle(*job, SettleStatus::Closed, "JOB-S13")?;
                Ok(Outcome::Applied)
            }
            Place {
                job,
                lenders,
                layout,
                recovery_estimate,
                witness,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.place(*job, lenders, layout, *recovery_estimate, *witness)
            }
            Heartbeat { job, attempt } => self.heartbeat(*job, *attempt),
            Deliver {
                job,
                attempt,
                witness,
                wt,
                upto,
                digest,
            } => self.deliver(*job, *attempt, *witness, *wt, *upto, *digest),
            WitnessCommit {
                job,
                attempt,
                witness,
                wt,
                upto,
            } => self.witness_commit(*job, *attempt, *witness, *wt, *upto),
            ConfirmDelivery {
                job,
                wt,
                confirmed,
                digest,
            } => self.confirm_delivery(*job, *wt, *confirmed, *digest),
            ClientHeartbeat { job } => {
                // JOB-R33: a keepalive covers no position, so it resolves nothing.
                self.job(*job)?;
                Ok(Outcome::AlreadyApplied)
            }
            ResolveContests { job } => self.resolve_contests(*job),
            PurgeBuffer { job, attempt } => self.purge_buffer(*job, *attempt),
            SupplementEvidence {
                slice,
                lender,
                output,
                evidence,
            } => self.supplement_evidence(*slice, *lender, *output, *evidence),
            WitnessLost { job, attempt } => self.witness_lost(*job, *attempt),
            ExpireDeliveryWindow { job } => self.expire_delivery_window(*job),
            PlacementFailed { job } => self.placement_failed(*job),
            AttemptReady {
                job,
                attempt,
                restored,
            } => self.attempt_ready(*job, *attempt, *restored),
            Produce {
                job,
                attempt,
                wt,
                upto,
            } => self.produce(*job, *attempt, *wt, *upto),
            Ack {
                job,
                attempt,
                wt,
                upto,
            } => self.ack(*job, *attempt, *wt, *upto),
            CommitReceipts {
                job,
                attempt,
                lender,
                wt,
                upto,
                digest,
            } => self.commit_receipts(*job, *attempt, *lender, *wt, *upto, *digest),
            Claim {
                slice,
                lender,
                items,
            } => self.claim(*slice, *lender, items),
            CloseSlice { slice } => self.close_slice(*slice),
            Evaluate { slice } => self.evaluate(*slice),
            Arbitrate { slice, lender, pay } => self.arbitrate(*slice, *lender, *pay),
            NodeLost {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.require_exec(*job, ExecStatus::Running, "JOB-T08")?;
                self.revoke_current(*job)?;
                self.job_mut(*job)?.intent = Intent::Resume;
                self.set_exec(*job, ExecStatus::Recovering, "JOB-T08")?;
                Ok(Outcome::Applied)
            }
            Pause {
                job,
                reason,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.require_exec(*job, ExecStatus::Running, "JOB-T11")?;
                self.revoke_current(*job)?;
                let j = self.job_mut(*job)?;
                j.checkpoint = true;
                j.pause_reason = Some(*reason);
                if j.delivered.iter().any(|v| *v > 0) {
                    j.intent = Intent::Resume;
                }
                self.set_exec(*job, ExecStatus::Paused, "JOB-T11")?;
                Ok(Outcome::Applied)
            }
            Resume { job, topup } => self.resume(*job, *topup),
            RecoveryTimeout { job } => {
                self.require_exec(*job, ExecStatus::Recovering, "JOB-T10")?;
                let j = self.job_mut(*job)?;
                j.checkpoint = true;
                j.pause_reason = None;
                self.set_exec(*job, ExecStatus::Paused, "JOB-T10")?;
                Ok(Outcome::Applied)
            }
            FundRecovery { job, amount } => {
                if !self.is_credits(*job)? {
                    return Err(DomainError::Precondition(
                        "free pool has no recovery escrow",
                    ));
                }
                let j = self.job(*job)?;
                // CE-01: the pool may only fund a job with active escrow, otherwise nobody owns
                // those credits.
                if j.settle != SettleStatus::Active {
                    return Err(DomainError::Precondition("JOB-R18: settlement not active"));
                }
                let key = format!("fund/{}/{}", job.0, self.audit.len());
                let unearmarked = add(j.recovery_unearmarked, *amount, "recovery budget")?;
                let funded = add(j.pool_recovery_funded, *amount, "pool relay")?;
                self.ledger_op(LedgerOp::FundRecovery {
                    job: job_acct(*job),
                    key,
                    amount: *amount,
                })?;
                let j = self.job_mut(*job)?;
                j.recovery_unearmarked = unearmarked;
                j.pool_recovery_funded = funded;
                Ok(Outcome::Applied)
            }
            Finish {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.require_exec(*job, ExecStatus::Running, "JOB-T13")?;
                let j = self.job(*job)?;
                let a = j
                    .current()
                    .ok_or_else(|| DomainError::Internal("no attempt".into()))?;
                // JOB-T13: every produced unit is delivered (attested or acked).
                if a.produced != j.delivered {
                    return Err(DomainError::Precondition("JOB-T13: undelivered output"));
                }
                self.revoke_current(*job)?;
                self.set_exec(*job, ExecStatus::Settling, "JOB-T13")?;
                Ok(Outcome::Applied)
            }
            CompleteSettling { job } => {
                self.require_exec(*job, ExecStatus::Settling, "JOB-T14")?;
                let busy = self.slices_of(*job, None).iter().any(|s| {
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
                self.set_exec(*job, ExecStatus::Completed, "JOB-T14")?;
                self.set_settle(*job, SettleStatus::Finalizing, "JOB-S11")?;
                Ok(Outcome::Applied)
            }
            Cancel {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.terminate(*job, ExecStatus::Cancelled, "JOB-T15")
            }
            Fail { job } => self.terminate(*job, ExecStatus::Failed, "JOB-T16"),
            ExpirePause { job } => {
                self.require_exec(*job, ExecStatus::Paused, "JOB-T17")?;
                if self.now < self.job(*job)?.exec_since + self.cfg.pause_max {
                    return Err(DomainError::Precondition("JOB-T17: pause not expired"));
                }
                self.job_mut(*job)?.checkpoint = false;
                self.set_exec(*job, ExecStatus::Cancelled, "JOB-T17")?;
                self.set_settle(*job, SettleStatus::Finalizing, "JOB-S11")?;
                Ok(Outcome::Applied)
            }
            Settle { job } => self.settle(*job),
            ReleaseReward { slice, lender } => self.release_reward(*slice, *lender),
            ContestReward { slice, lender } => self.contest_reward(*slice, *lender),
            Reconcile => self.reconcile(ctx),
        }
    }

    fn require_exec(&self, job: JobId, want: ExecStatus, rule: &'static str) -> R {
        let from = self.job(job)?.exec;
        if from != want {
            return Err(DomainError::InvalidTransition { from, rule });
        }
        Ok(())
    }

    fn create_pool(
        &mut self,
        pool: PoolId,
        mode: PoolMode,
        access: PoolAccess,
        admin: AccountId,
    ) -> R<Outcome> {
        if let Some(p) = self.pools.get(&pool) {
            return if p.mode == mode && p.access == access && p.is_admin(admin) {
                Ok(Outcome::AlreadyApplied)
            } else {
                Err(DomainError::Precondition("pool id reused"))
            };
        }
        self.pools.insert(
            pool,
            Pool {
                id: pool,
                mode,
                access,
                admins: [admin].into_iter().collect(),
                members: BTreeMap::new(),
                models: BTreeMap::new(),
            },
        );
        Ok(Outcome::Applied)
    }

    fn set_rights(&mut self, pool: PoolId, account: AccountId, rights: Rights) -> R<Outcome> {
        let p = self.pools.get_mut(&pool).ok_or(DomainError::UnknownPool)?;
        if p.rights(account) == rights {
            return Ok(Outcome::AlreadyApplied);
        }
        if rights == Rights::NONE {
            p.members.remove(&account);
        } else {
            p.members.insert(account, rights);
        }
        Ok(Outcome::Applied)
    }

    fn join_pool(&mut self, pool: PoolId, account: AccountId) -> R<Outcome> {
        let p = self.pools.get_mut(&pool).ok_or(DomainError::UnknownPool)?;
        if p.access != PoolAccess::Open {
            return Err(DomainError::Precondition(
                "private pool: rights come from its admins",
            ));
        }
        let r = p.members.entry(account).or_insert(Rights::NONE);
        if r.borrow && r.lend {
            return Ok(Outcome::AlreadyApplied);
        }
        r.borrow = true;
        r.lend = true;
        Ok(Outcome::Applied)
    }

    /// Model Registry: catalog and tariff, bounded so job costs cannot overflow (SAFE-001).
    fn register_model(&mut self, pool: PoolId, model: ModelId, spec: ModelSpec) -> R<Outcome> {
        let p = self.pools.get_mut(&pool).ok_or(DomainError::UnknownPool)?;
        if spec.layers == 0 || spec.layers > MAX_LAYERS {
            return Err(DomainError::InvalidInput("model layers out of range"));
        }
        if spec.price.iter().any(|x| *x > MAX_PRICE) {
            return Err(DomainError::InvalidInput("price above MAX_PRICE"));
        }
        if spec.max_outputs.iter().any(|x| *x > MAX_OUTPUTS) {
            return Err(DomainError::InvalidInput("max outputs above MAX_OUTPUTS"));
        }
        if matches!(p.mode, PoolMode::FreeShare { .. }) && spec.price != [0; 3] {
            return Err(DomainError::InvalidInput(
                "a free-sharing pool has no tariff",
            ));
        }
        if p.models.get(&model) == Some(&spec) {
            return Ok(Outcome::AlreadyApplied);
        }
        p.models.insert(model, spec);
        Ok(Outcome::Applied)
    }

    /// JOB-T01. The price is the pool's tariff for the model; the client only chooses how many
    /// outputs it wants and signs the most it agrees to lock (SEC-002).
    #[allow(clippy::too_many_arguments)]
    fn submit(
        &mut self,
        job: JobId,
        borrower: AccountId,
        pool: PoolId,
        model: ModelId,
        outputs: PerType<u32>,
        max_budget: Amount,
        mandate: &[u8; 64],
    ) -> R<Outcome> {
        let p = self.pools.get(&pool).ok_or(DomainError::UnknownPool)?;
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
            .models
            .get(&model)
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
        // The ledger checks the borrower's signature itself: a compromised orchestrator cannot
        // open an escrow nobody agreed to.
        self.ledger_op(LedgerOp::OpenEscrow {
            job: job_acct(job),
            owner: borrower.0,
            pool: pool.0,
            max_budget,
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

    fn reserve(&mut self, job: JobId) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Queued, "JOB-T02")?;
        let j = self.job(job)?.clone();
        let mode = self
            .pools
            .get(&j.pool)
            .ok_or(DomainError::UnknownPool)?
            .mode;
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

    fn place(
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
        let pool = self.pools.get(&j.pool).ok_or(DomainError::UnknownPool)?;
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
        let j = self.job_mut(job)?;
        j.recovery_unearmarked = unearmarked;
        j.attempt += 1;
        let no = j.attempt;
        // Start from delivered positions: they get replayed, never regenerated (JOB-R28).
        let produced = j.delivered;
        j.attempts.insert(
            no,
            Attempt {
                no,
                lenders: lenders.to_vec(),
                layout: layout.to_vec(),
                issued_at: now,
                witness,
                lease_expires_at: now + ttl,
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

    fn placement_failed(&mut self, job: JobId) -> R<Outcome> {
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

    fn attempt_ready(&mut self, job: JobId, attempt: u32, restored: PerType<u32>) -> R<Outcome> {
        self.require_exec(job, ExecStatus::Placing, "JOB-T05")?;
        let now = self.now;
        let j = self.job_mut(job)?;
        if attempt != j.attempt {
            return Err(DomainError::StaleAttempt);
        }
        // JOB-T05: on resume, state must be restored exactly to the last delivered position; 0 on
        // first start.
        if restored != j.delivered {
            return Err(DomainError::Precondition(
                "JOB-T05: state not restored to last delivered position",
            ));
        }
        let intent = j.intent;
        let validated = j.validated;
        let delivered = j.delivered;
        j.last_ack_at = now;
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?;
        if a.revoked_at.is_some() {
            return Err(DomainError::StaleAttempt);
        }
        if now >= a.lease_expires_at {
            return Err(DomainError::LeaseExpired);
        }
        a.ready = true;
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

    fn current_live_attempt(&self, job: JobId, attempt: u32) -> R<&Attempt> {
        let j = self.job(job)?;
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if attempt != j.attempt
            || a.revoked_at.is_some()
            || !a.ready
            || j.exec != ExecStatus::Running
        {
            return Err(DomainError::StaleAttempt);
        }
        // JOB-R31: nothing is accepted under an expired lease, even before reconciliation revokes
        // the attempt.
        if self.now >= a.lease_expires_at {
            return Err(DomainError::LeaseExpired);
        }
        Ok(a)
    }

    fn produce(&mut self, job: JobId, attempt: u32, wt: WorkType, upto: u32) -> R<Outcome> {
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

    /// Charges an output (work escrow to output hold), provisionally or definitively, and binds it
    /// to its attempt (JOB-R17).
    fn charge_output(
        &mut self,
        output: OutputId,
        attempt: u32,
        definitive: bool,
        basis: ChargeBasis,
    ) -> R {
        if self.outputs.contains_key(&output) {
            return Err(DomainError::Internal(format!(
                "output charged twice: {output:?}"
            )));
        }
        let (price, replayable) = {
            let j = self.job(output.job)?;
            let a = j
                .attempts
                .get(&attempt)
                .ok_or_else(|| DomainError::Internal("attempt".into()))?;
            (
                j.price[output.wt.idx()],
                !a.witness_lost && !a.buffer_purged,
            )
        };
        let gen = self.charge_gens.get(&output).copied().unwrap_or(0);
        self.ledger_op(LedgerOp::ChargeOutput {
            job: job_acct(output.job),
            key: format!(
                "charge/{}/{:?}/{}/{}",
                output.job.0, output.wt, output.pos, gen
            ),
            amount: price,
        })?;
        self.charge_gens.insert(output, gen + 1);
        self.outputs.insert(output, attempt);
        self.charges.insert(
            output,
            OutputCharge {
                attempt,
                gen,
                definitive,
                basis,
                replayable,
                contest: None,
            },
        );
        self.audit.push(AuditEvent::OutputCharged {
            output,
            attempt,
            amount: price,
            gen,
            provisional: !definitive,
        });
        Ok(())
    }

    /// Makes a provisional output definitive. Returns true if it was provisional.
    fn make_definitive(&mut self, output: OutputId, basis: ChargeBasis) -> R<bool> {
        let ch = self
            .charges
            .get_mut(&output)
            .ok_or_else(|| DomainError::Internal(format!("uncharged {output:?}")))?;
        if ch.definitive {
            return Ok(false);
        }
        ch.definitive = true;
        ch.basis = basis;
        ch.contest = None;
        self.audit
            .push(AuditEvent::OutputConfirmed { output, basis });
        Ok(true)
    }

    fn heartbeat(&mut self, job: JobId, attempt: u32) -> R<Outcome> {
        let now = self.now;
        let ttl = self.cfg.lease_ttl;
        let j = self.job_mut(job)?;
        if attempt != j.attempt || !matches!(j.exec, ExecStatus::Placing | ExecStatus::Running) {
            return Err(DomainError::StaleAttempt);
        }
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if a.revoked_at.is_some() {
            return Err(DomainError::StaleAttempt);
        }
        // JOB-R31: an expired lease is never renewed.
        if now >= a.lease_expires_at {
            return Err(DomainError::LeaseExpired);
        }
        if a.lease_expires_at == now + ttl {
            return Ok(Outcome::AlreadyApplied);
        }
        a.lease_expires_at = now + ttl;
        Ok(Outcome::Applied)
    }

    /// JOB-R26, JOB-R27: delivery attestation by the assigned witness.
    fn deliver(
        &mut self,
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
    ) -> R<Outcome> {
        let now = self.now;
        let drain = self.cfg.drain_window;
        let j = self.job(job)?;
        let a = j
            .attempts
            .get(&attempt)
            .ok_or(DomainError::StaleAttempt)?
            .clone();
        let late = match a.revoked_at {
            None => {
                self.current_live_attempt(job, attempt)?;
                false
            }
            Some(r) => {
                // JOB-R32: late attestations only while draining, and only if no newer attempt was
                // placed.
                if attempt != j.attempt || now > r + drain {
                    return Err(DomainError::StaleAttempt);
                }
                true
            }
        };
        // Only the assigned witness can attest; a lender attesting its own delivery proves nothing
        // (JOB-R26).
        if witness != a.witness || a.witness_lost || a.buffer_purged {
            return Err(DomainError::InadmissibleProof);
        }
        let t = wt.idx();
        let from = j.delivered[t];
        if upto <= from {
            return Ok(Outcome::AlreadyApplied);
        }
        if upto > a.produced[t] {
            return Err(DomainError::Precondition(
                "JOB-R27: attestation beyond produced",
            ));
        }
        // JOB-R34: the digest must match the frames signed by the output node for this stream;
        // substituted or foreign frames are rejected.
        if digest != self.frame_digest(job, wt, upto) {
            return Err(DomainError::InadmissibleProof);
        }
        if late {
            let cutoff = a.revoked_seq.unwrap_or(0);
            let committed = self
                .witness_commits
                .get(&(job, attempt, wt))
                .is_some_and(|v| v.iter().any(|(u, seq)| *u >= upto && *seq < cutoff));
            if !committed {
                return Err(DomainError::InadmissibleProof);
            }
        }
        for pos in from..upto {
            self.charge_output(
                OutputId { job, wt, pos },
                attempt,
                false,
                ChargeBasis::Witnessed,
            )?;
        }
        let j = self.job_mut(job)?;
        j.delivered[t] = upto;
        j.intent = Intent::Resume;
        j.version += 1;
        self.audit.push(if late {
            AuditEvent::LateDelivery {
                job,
                attempt,
                wt,
                to: upto,
            }
        } else {
            AuditEvent::Delivered {
                job,
                attempt,
                wt,
                from,
                to: upto,
            }
        });
        Ok(Outcome::Applied)
    }

    /// Chained digest of a stream's frames `0..upto` (JOB-R34): job, client stream, model, type,
    /// and each position with its billing generation. FNV-1a in the model.
    pub fn frame_digest(&self, job: JobId, wt: WorkType, upto: u32) -> u64 {
        let Ok(j) = self.job(job) else { return 0 };
        let mut h = fnv(&[
            u64::from(job.0),
            j.stream,
            u64::from(j.model.0),
            wt.idx() as u64,
        ]);
        for pos in 0..upto {
            let o = OutputId { job, wt, pos };
            let gen = self
                .charges
                .get(&o)
                .map(|c| c.gen)
                .unwrap_or_else(|| self.charge_gens.get(&o).copied().unwrap_or(0));
            h = fnv(&[h, u64::from(pos), u64::from(gen)]);
        }
        h
    }

    /// JOB-R32: short witness commitment, live attempt only.
    fn witness_commit(
        &mut self,
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
    ) -> R<Outcome> {
        let a = self.current_live_attempt(job, attempt)?;
        if witness != a.witness || a.witness_lost {
            return Err(DomainError::InadmissibleProof);
        }
        if upto > a.produced[wt.idx()] {
            return Err(DomainError::Precondition(
                "JOB-R32: commitment beyond produced",
            ));
        }
        let seq = self.seq;
        let log = self.witness_commits.entry((job, attempt, wt)).or_default();
        if log.last().is_some_and(|(u, _)| *u >= upto) {
            return Ok(Outcome::AlreadyApplied);
        }
        log.push((upto, seq));
        Ok(Outcome::Applied)
    }

    fn ack(&mut self, job: JobId, attempt: u32, wt: WorkType, upto: u32) -> R<Outcome> {
        let a = self.current_live_attempt(job, attempt)?;
        let t = wt.idx();
        let produced = a.produced[t];
        let j = self.job(job)?;
        let from = j.validated[t];
        let delivered = j.delivered[t];
        if upto <= from {
            return Ok(Outcome::AlreadyApplied);
        }
        if upto > produced {
            return Err(DomainError::Precondition("ack beyond produced"));
        }
        // JOB-R23: client acks are cumulative. Delivered (provisional) positions become definitive;
        // later ones are charged now, once (JOB-R17).
        let mut resolved = Vec::new();
        for pos in from..upto {
            let output = OutputId { job, wt, pos };
            if pos < delivered {
                if self.make_definitive(output, ChargeBasis::ClientSigned)? {
                    resolved.push(output);
                }
            } else {
                self.charge_output(output, attempt, true, ChargeBasis::ClientSigned)?;
            }
        }
        let now = self.now;
        let j = self.job_mut(job)?;
        j.validated[t] = upto;
        j.delivered[t] = j.delivered[t].max(upto);
        j.last_ack_at = now;
        j.intent = Intent::Resume;
        j.version += 1;
        self.audit.push(AuditEvent::Validated {
            job,
            attempt,
            wt,
            from,
            to: upto,
        });
        for o in resolved {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R28, JOB-R29: signed client statement "I hold exactly `0..confirmed`". Earlier positions
    /// become definitive; missing ones are replayed, or voided with everything after them if the
    /// buffer is lost.
    fn confirm_delivery(
        &mut self,
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        digest: u64,
    ) -> R<Outcome> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let resolution = self.cfg.contest_resolution;
        let j = self.job(job)?;
        if j.settle == SettleStatus::Closed {
            return Err(DomainError::Precondition("JOB-R28: job closed"));
        }
        let t = wt.idx();
        let (validated, delivered) = (j.validated[t], j.delivered[t]);
        if confirmed < validated {
            return Err(DomainError::Precondition(
                "JOB-R28: a validated position cannot be unconfirmed",
            ));
        }
        if confirmed > delivered {
            return Err(DomainError::Precondition(
                "JOB-R28: confirmed beyond delivered",
            ));
        }
        // JOB-R34: the statement is bound to the stream by the prefix digest; one from another
        // session is rejected.
        if digest != self.frame_digest(job, wt, confirmed) {
            return Err(DomainError::InadmissibleProof);
        }
        // Missing outputs: contest them (window open), or just retransmit (already definitive or
        // contested).
        let mut to_contest = Vec::new();
        let mut first_lost = None;
        for pos in confirmed..delivered {
            let output = OutputId { job, wt, pos };
            let ch = self.charges.get(&output).ok_or_else(|| {
                DomainError::Internal(format!("delivered but uncharged {output:?}"))
            })?;
            let producer = j
                .attempts
                .get(&ch.attempt)
                .ok_or_else(|| DomainError::Internal("attempt".into()))?;
            // An output of the live attempt is retransmitted, not contested.
            let Some(revoked) = producer.revoked_at else {
                return Err(DomainError::Precondition(
                    "JOB-R28: missing output of the live attempt (retransmit)",
                ));
            };
            let window_open = now < revoked + w;
            let provisional = !ch.definitive && (ch.contest.is_some() || window_open);
            if !ch.replayable {
                if !provisional {
                    return Err(DomainError::Precondition(
                        "JOB-R29: definitive output can no longer be replayed",
                    ));
                }
                // Witness cannot produce the buffer: refund (JOB-R33).
                first_lost = Some(pos);
                break;
            }
            if provisional && ch.contest.is_none() {
                to_contest.push(output);
            }
        }
        if confirmed == validated && to_contest.is_empty() && first_lost.is_none() {
            return Ok(Outcome::AlreadyApplied);
        }
        let mut resolved = Vec::new();
        for pos in validated..confirmed {
            let output = OutputId { job, wt, pos };
            if self.make_definitive(output, ChargeBasis::ClientSigned)? {
                resolved.push(output);
            }
        }
        {
            let j = self.job_mut(job)?;
            j.validated[t] = confirmed;
            j.version += 1;
        }
        // One contest per output: replay requested, deadline set. Only a signed cumulative ack
        // covering it makes it definitive.
        for output in to_contest {
            let deadline = now + resolution;
            let ch = self
                .charges
                .get_mut(&output)
                .ok_or_else(|| DomainError::Internal(format!("contest uncharged {output:?}")))?;
            ch.contest = Some(Contest {
                opened_at: now,
                deadline,
            });
            self.audit
                .push(AuditEvent::ContestOpened { output, deadline });
            self.audit.push(AuditEvent::Replayed { output });
        }
        if let Some(p) = first_lost {
            self.rewind(job, wt, p)?;
        }
        for o in resolved {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R33: at the deadline, a contested output with no covering ack is refunded along with
    /// everything after it.
    fn resolve_contests(&mut self, job: JobId) -> R<Outcome> {
        let now = self.now;
        let mut first: BTreeMap<WorkType, u32> = BTreeMap::new();
        for (o, ch) in &self.charges {
            if o.job == job && !ch.definitive && ch.contest.is_some_and(|c| now >= c.deadline) {
                let e = first.entry(o.wt).or_insert(o.pos);
                *e = (*e).min(o.pos);
            }
        }
        if first.is_empty() {
            return Err(DomainError::Precondition("JOB-R33: no contest due"));
        }
        for (wt, p) in first {
            self.rewind(job, wt, p)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R28: the witness keeps its buffer until the delivery window has passed AND no output of
    /// the attempt is provisional or contested.
    fn purge_buffer(&mut self, job: JobId, attempt: u32) -> R<Outcome> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let j = self.job(job)?;
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if a.buffer_purged {
            return Ok(Outcome::AlreadyApplied);
        }
        let Some(r) = a.revoked_at else {
            return Err(DomainError::Precondition("JOB-R28: attempt still live"));
        };
        if now < r + w {
            return Err(DomainError::Precondition("JOB-R28: retention not over"));
        }
        if self
            .charges
            .iter()
            .any(|(o, ch)| o.job == job && ch.attempt == attempt && !ch.definitive)
        {
            return Err(DomainError::Precondition(
                "JOB-R28: provisional or contested outputs pending",
            ));
        }
        self.attempt_mut(job, attempt)?.buffer_purged = true;
        for (o, ch) in self.charges.iter_mut() {
            if o.job == job && ch.attempt == attempt {
                ch.replayable = false;
            }
        }
        self.audit.push(AuditEvent::BufferPurged { job, attempt });
        Ok(Outcome::Applied)
    }

    /// JOB-R35: stronger proof, before the evaluation deadline.
    fn supplement_evidence(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: Evidence,
    ) -> R<Outcome> {
        let now = self.now;
        let deadline = self.cfg.evaluation_deadline;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        let open = matches!(s.status, SliceStatus::Closed | SliceStatus::Disputed)
            && now < s.closed_at.unwrap_or(0) + deadline;
        if !open {
            return Err(DomainError::Precondition(
                "JOB-R35: evaluation deadline passed",
            ));
        }
        let line = s
            .lines
            .get(&lender)
            .ok_or(DomainError::Precondition("no line"))?;
        let idx = line
            .items
            .iter()
            .position(|i| {
                matches!(i.kind, ItemKind::Contribution(cid) if cid.output == output)
                    && (i.status == ItemStatus::PendingEvaluation || i.awaiting_delivery)
            })
            .ok_or(DomainError::Precondition("JOB-R35: no undecided item"))?;
        if evidence.rank() <= line.items[idx].evidence.rank() {
            return Ok(Outcome::AlreadyApplied);
        }
        self.line_mut(slice, lender)?.items[idx].evidence = evidence;
        self.audit.push(AuditEvent::EvidenceSupplemented {
            slice,
            lender,
            output,
            evidence,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-R29: rewinds to `to`. Every charged output of this type from `to` on is provisional and
    /// voided; a live attempt built on them is revoked.
    fn rewind(&mut self, job: JobId, wt: WorkType, to: u32) -> R {
        let t = wt.idx();
        let from = self.job(job)?.delivered[t];
        for pos in (to..from).rev() {
            self.void_output(OutputId { job, wt, pos })?;
        }
        {
            let j = self.job_mut(job)?;
            j.delivered[t] = to;
            j.version += 1;
        }
        self.audit.push(AuditEvent::Rewound { job, wt, from, to });
        let j = self.job(job)?;
        let live = j
            .current()
            .is_some_and(|a| a.revoked_at.is_none() && a.produced[t] > to);
        if live {
            match j.exec {
                ExecStatus::Running => {
                    self.revoke_current(job)?;
                    self.job_mut(job)?.intent = Intent::Resume;
                    self.set_exec(job, ExecStatus::Recovering, "JOB-T08")?;
                }
                ExecStatus::Placing => {
                    self.revoke_current(job)?;
                    let back = self
                        .job(job)?
                        .placing_from
                        .ok_or_else(|| DomainError::Internal("placing_from".into()))?;
                    self.set_exec(job, back, "JOB-T06")?;
                }
                other => return Err(DomainError::Internal(format!("live attempt in {other:?}"))),
            }
        }
        Ok(())
    }

    /// Voids a provisional output: its reserved contributions are returned, then its price goes
    /// back to work escrow (JOB-R29, JOB-R30).
    fn void_output(&mut self, output: OutputId) -> R {
        let ch = *self
            .charges
            .get(&output)
            .ok_or_else(|| DomainError::Internal(format!("void uncharged {output:?}")))?;
        if ch.definitive {
            return Err(DomainError::Internal(format!(
                "voiding a definitive output {output:?}"
            )));
        }
        let mut touched = Vec::new();
        let targets = self.items_of(output, ch.gen);
        for (slice, lender, idx) in targets {
            let st = self.slices[&slice].lines[&lender].items[idx].status;
            match st {
                ItemStatus::PendingEvaluation | ItemStatus::Disputed => {
                    self.refund_item(slice, lender, idx, RefundReason::OutputVoided)?;
                    touched.push(slice);
                }
                ItemStatus::Refunded => {}
                ItemStatus::Paid => {
                    return Err(DomainError::Internal(format!(
                        "contribution of provisional {output:?} was paid"
                    )))
                }
            }
        }
        let price = self.job(output.job)?.price[output.wt.idx()];
        self.ledger_op(LedgerOp::VoidOutput {
            job: job_acct(output.job),
            key: format!(
                "void/{}/{:?}/{}/{}",
                output.job.0, output.wt, output.pos, ch.gen
            ),
            amount: price,
        })?;
        self.outputs.remove(&output);
        self.charges.remove(&output);
        self.audit.push(AuditEvent::OutputVoided {
            output,
            gen: ch.gen,
            amount: price,
        });
        for s in touched {
            self.maybe_finalize_disputed(s)?;
        }
        Ok(())
    }

    /// Reserved items of one billing generation of an output.
    fn items_of(&self, output: OutputId, gen: u32) -> Vec<(SliceId, AccountId, usize)> {
        let mut v = Vec::new();
        for (sid, s) in self.slices.iter().filter(|(k, _)| k.job == output.job) {
            for (lender, l) in &s.lines {
                for (idx, it) in l.items.iter().enumerate() {
                    if let ItemKind::Contribution(cid) = it.kind {
                        if cid.output == output && cid.charge == gen {
                            v.push((*sid, *lender, idx));
                        }
                    }
                }
            }
        }
        v
    }

    /// JOB-R30: the output became definitive; its waiting contributions are evaluated under the
    /// usual JOB-S04 rules.
    fn resolve_awaiting(&mut self, output: OutputId) -> R {
        let Some(ch) = self.charges.get(&output).copied() else {
            return Ok(());
        };
        let mut touched = Vec::new();
        for (slice, lender, idx) in self.items_of(output, ch.gen) {
            let it = &self.slices[&slice].lines[&lender].items[idx];
            if !(it.status == ItemStatus::Disputed && it.awaiting_delivery) {
                continue;
            }
            self.line_mut(slice, lender)?.items[idx].awaiting_delivery = false;
            match self.decide(slice, lender, idx)? {
                Decision::Pay => self.pay_item(slice, lender, idx, false)?,
                Decision::Refund(r) => self.refund_item(slice, lender, idx, r)?,
                Decision::Dispute => {
                    let it = &self.slices[&slice].lines[&lender].items[idx];
                    self.audit.push(AuditEvent::ItemDisputed {
                        slice,
                        lender,
                        kind: it.kind,
                        amount: it.amount,
                    });
                }
                Decision::Defer => {
                    // JOB-R35: before the deadline the item goes back to pending, so a stronger
                    // proof can still come.
                    let l = self.line_mut(slice, lender)?;
                    let amount = l.items[idx].amount;
                    l.disputed = sub(l.disputed, amount, "disputed")?;
                    l.pending = add(l.pending, amount, "pending")?;
                    l.items[idx].status = ItemStatus::PendingEvaluation;
                }
                Decision::Await => {
                    return Err(DomainError::Internal("await after resolution".into()))
                }
            }
            touched.push(slice);
        }
        for s in touched {
            self.maybe_finalize_disputed(s)?;
        }
        Ok(())
    }

    fn maybe_finalize_disputed(&mut self, slice: SliceId) -> R {
        let s = &self.slices[&slice];
        if s.status == SliceStatus::Disputed && s.lines.values().all(|l| l.disputed == 0) {
            self.set_slice(slice, SliceStatus::Final, "JOB-R30")?;
            self.maybe_return_earmark(slice.job, slice.attempt)?;
        }
        Ok(())
    }

    fn witness_lost(&mut self, job: JobId, attempt: u32) -> R<Outcome> {
        let j = self.job_mut(job)?;
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if a.witness_lost {
            return Ok(Outcome::AlreadyApplied);
        }
        a.witness_lost = true;
        for (o, ch) in self.charges.iter_mut() {
            if o.job == job && ch.attempt == attempt {
                ch.replayable = false;
            }
        }
        Ok(Outcome::Applied)
    }

    /// Uncontested provisional outputs whose window expired, in position order. Stops at the first
    /// contested or not yet due one, since later outputs depend on it (JOB-R29, JOB-R33).
    fn window_due(&self, job: JobId) -> Vec<OutputId> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let Ok(j) = self.job(job) else { return vec![] };
        let mut due = Vec::new();
        for wt in WorkType::ALL {
            let t = wt.idx();
            for pos in j.validated[t]..j.delivered[t] {
                let o = OutputId { job, wt, pos };
                let Some(ch) = self.charges.get(&o) else {
                    break;
                };
                if ch.definitive {
                    continue;
                }
                let expired = j.attempts[&ch.attempt]
                    .revoked_at
                    .is_some_and(|r| now >= r + w);
                if ch.contest.is_some() || !expired {
                    break;
                }
                due.push(o);
            }
        }
        due
    }

    /// JOB-R29: an attested delivery with no contest during the window becomes definitive.
    fn expire_delivery_window(&mut self, job: JobId) -> R<Outcome> {
        let due = self.window_due(job);
        if due.is_empty() {
            return Err(DomainError::Precondition(
                "JOB-R29: no delivery window expired",
            ));
        }
        for o in &due {
            self.make_definitive(*o, ChargeBasis::WindowExpired)?;
        }
        for o in due {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }

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

    fn commit_receipts(
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

    fn claim(&mut self, slice: SliceId, lender: AccountId, items: &[ClaimItem]) -> R<Outcome> {
        let now = self.now;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        match s.status {
            SliceStatus::Open => {}
            SliceStatus::Draining => {
                if now > s.receipt_deadline.unwrap_or(0) {
                    return Err(DomainError::Precondition(
                        "JOB-S03: receipt deadline passed",
                    ));
                }
            }
            from => {
                return Err(DomainError::InvalidSliceTransition {
                    from,
                    rule: "claim",
                })
            }
        }
        let j = self.job(slice.job)?;
        let a = j
            .attempts
            .get(&slice.attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if !a.lenders.contains(&lender) {
            return Err(DomainError::Precondition("lender not in attempt"));
        }
        if items.is_empty() {
            return Err(DomainError::Precondition("empty claim"));
        }
        // JOB-R12 (b): while draining, at most "flow budget" uncommitted items per type.
        if s.status == SliceStatus::Draining {
            for wt in WorkType::ALL {
                let already = s
                    .staged
                    .iter()
                    .filter(|c| c.lender == lender && matches!(c.item, ClaimItem::Contribution { output, evidence: Evidence::Uncommitted, .. } if output.wt == wt))
                    .count();
                let new = items
                    .iter()
                    .filter(|i| matches!(i, ClaimItem::Contribution { output, evidence: Evidence::Uncommitted, .. } if output.wt == wt))
                    .count();
                if (already + new) as u32 > self.cfg.flow_budget[wt.idx()] {
                    return Err(DomainError::FlowBudgetExceeded);
                }
            }
        }
        let s = self.slice_mut(slice)?;
        for item in items {
            s.staged.push(StagedClaim {
                lender,
                item: *item,
            });
        }
        Ok(Outcome::Applied)
    }

    /// JOB-S03: closes the slice and reserves all claimed amounts atomically (JOB-R24).
    fn close_slice(&mut self, slice: SliceId) -> R<Outcome> {
        let now = self.now;
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?
            .clone();
        let j = self.job(slice.job)?.clone();
        let a = j
            .attempts
            .get(&slice.attempt)
            .ok_or_else(|| DomainError::Internal("attempt".into()))?
            .clone();
        let normal_close = match s.status {
            SliceStatus::Open => {
                // An open slice always belongs to the live attempt.
                if j.attempt != slice.attempt
                    || a.revoked_at.is_some()
                    || j.exec != ExecStatus::Running
                {
                    return Err(DomainError::Internal(
                        "open slice on a revoked attempt".into(),
                    ));
                }
                true
            }
            SliceStatus::Draining => {
                if now < s.receipt_deadline.unwrap_or(0) {
                    return Err(DomainError::Precondition(
                        "JOB-S03: drain window still open",
                    ));
                }
                false
            }
            from => {
                return Err(DomainError::InvalidSliceTransition {
                    from,
                    rule: "JOB-S03",
                })
            }
        };
        let mut recovery_reserved = a.recovery_reserved;
        let mut rejected = 0u32;
        let mut lines: BTreeMap<AccountId, Line> = BTreeMap::new();
        for StagedClaim { lender, item } in &s.staged {
            let reserved = match *item {
                ClaimItem::Contribution {
                    output,
                    stage,
                    evidence,
                } => {
                    let stage = stage as usize;
                    let ok_binding = output.job == slice.job
                        && self.outputs.get(&output) == Some(&slice.attempt);
                    let ok_stage = stage < a.layout.len() && a.lenders.get(stage) == Some(lender);
                    let range = a.layer_range(stage);
                    if let (true, Some((ls, le))) = (ok_binding && ok_stage, range) {
                        let cid = ContributionId {
                            output,
                            charge: self.charges[&output].gen,
                            layer_start: ls,
                            layer_end: le,
                            role: ContributionRole::Executor,
                        };
                        if self.contributions.contains_key(&cid) {
                            None
                        } else {
                            let amount = j.share(&a, output.wt, stage).ok_or_else(|| {
                                DomainError::Internal("share of a missing stage".into())
                            })?;
                            self.ledger_op(LedgerOp::ReserveLine {
                                line: line_ref(slice, *lender),
                                source: LineSource::OutputHold,
                                key: format!("claim/{:?}/{}/{:?}", slice, lender.0, cid),
                                amount,
                            })?;
                            self.contributions.insert(cid, slice);
                            Some((ItemKind::Contribution(cid), amount, evidence))
                        }
                    } else {
                        None
                    }
                }
                ClaimItem::Recovery {
                    segment,
                    amount,
                    evidence,
                } => {
                    let rid = RecoveryWorkId {
                        job: slice.job,
                        attempt: slice.attempt,
                        segment,
                    };
                    let fits = recovery_reserved
                        .checked_add(amount)
                        .is_some_and(|t| t <= a.recovery_earmark);
                    if !a.ready || self.recovery_items.contains_key(&rid) || !fits || amount == 0 {
                        None
                    } else {
                        self.ledger_op(LedgerOp::ReserveLine {
                            line: line_ref(slice, *lender),
                            source: LineSource::Recovery,
                            key: format!("claim/{:?}/{}/{:?}", slice, lender.0, rid),
                            amount,
                        })?;
                        recovery_reserved = add(recovery_reserved, amount, "recovery reserved")?;
                        self.recovery_items.insert(rid, slice);
                        Some((ItemKind::Recovery(rid), amount, evidence))
                    }
                }
            };
            match reserved {
                None => rejected += 1,
                Some((kind, amount, evidence)) => {
                    let line = lines.entry(*lender).or_default();
                    line.claimed = add(line.claimed, amount, "claimed")?;
                    line.pending = add(line.pending, amount, "pending")?;
                    line.items.push(LineItem {
                        kind,
                        amount,
                        evidence,
                        status: ItemStatus::PendingEvaluation,
                        pool_part: 0,
                        reward_done: false,
                        awaiting_delivery: false,
                    });
                    self.audit.push(AuditEvent::ItemReserved {
                        slice,
                        lender: *lender,
                        kind,
                        amount,
                    });
                }
            }
        }
        self.attempt_mut(slice.job, slice.attempt)?
            .recovery_reserved = recovery_reserved;
        let sm = self.slice_mut(slice)?;
        sm.staged.clear();
        sm.lines = lines;
        sm.rejected_items += rejected;
        self.set_slice(slice, SliceStatus::Closed, "JOB-S03")?;
        if normal_close {
            // JOB-T07: the attempt continues on a new slice.
            self.open_slice(slice.job, slice.attempt)?;
        }
        Ok(Outcome::Applied)
    }

    fn pay_item(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        idx: usize,
        by_arbitration: bool,
    ) -> R {
        let (kind, amount, evidence) = {
            let l = &self.slices[&slice].lines[&lender];
            (
                l.items[idx].kind,
                l.items[idx].amount,
                l.items[idx].evidence,
            )
        };
        self.ledger_op(LedgerOp::PayLine {
            line: line_ref(slice, lender),
            key: format!("pay/{:?}/{}/{:?}", slice, lender.0, kind),
            amount,
        })?;
        // CE-02, JOB-R18: borrower budget first, then pool relay.
        let mut pool_part = 0;
        if let ItemKind::Recovery(_) = kind {
            let j = self.job_mut(slice.job)?;
            let left = sub(
                j.recovery_budget,
                j.recovery_paid_borrower,
                "borrower budget",
            )?;
            let from_borrower = amount.min(left);
            pool_part = amount - from_borrower;
            let pool_paid = add(j.recovery_paid_pool, pool_part, "pool relay paid")?;
            if pool_paid > j.pool_recovery_funded {
                return Err(DomainError::Internal(
                    "recovery paid beyond borrower budget and pool relay".into(),
                ));
            }
            j.recovery_paid_borrower = add(j.recovery_paid_borrower, from_borrower, "paid")?;
            j.recovery_paid_pool = pool_paid;
        }
        let l = self.line_mut(slice, lender)?;
        l.items[idx].pool_part = pool_part;
        match l.items[idx].status {
            ItemStatus::PendingEvaluation => l.pending = sub(l.pending, amount, "pending")?,
            ItemStatus::Disputed => l.disputed = sub(l.disputed, amount, "disputed")?,
            st => return Err(DomainError::Internal(format!("pay from {st:?}"))),
        }
        l.paid = add(l.paid, amount, "paid")?;
        l.held = add(l.held, amount, "held")?;
        l.items[idx].status = ItemStatus::Paid;
        l.items[idx].awaiting_delivery = false;
        // A zero reward (free pool) has nothing to hold or release.
        l.items[idx].reward_done = amount == 0;
        self.audit.push(AuditEvent::ItemPaid {
            slice,
            lender,
            kind,
            amount,
            evidence,
            by_arbitration,
            at: self.now,
        });
        Ok(())
    }

    fn refund_item(
        &mut self,
        slice: SliceId,
        lender: AccountId,
        idx: usize,
        reason: RefundReason,
    ) -> R {
        let (kind, amount) = {
            let l = &self.slices[&slice].lines[&lender];
            (l.items[idx].kind, l.items[idx].amount)
        };
        let back = match kind {
            ItemKind::Contribution(_) => LineSource::OutputHold,
            ItemKind::Recovery(_) => LineSource::Recovery,
        };
        self.ledger_op(LedgerOp::RefundLine {
            line: line_ref(slice, lender),
            to: back,
            key: format!("refund/{:?}/{}/{:?}", slice, lender.0, kind),
            amount,
        })?;
        if let ItemKind::Recovery(_) = kind {
            let a = self.attempt_mut(slice.job, slice.attempt)?;
            a.recovery_reserved = sub(a.recovery_reserved, amount, "recovery reserved")?;
        }
        let l = self.line_mut(slice, lender)?;
        match l.items[idx].status {
            ItemStatus::PendingEvaluation => l.pending = sub(l.pending, amount, "pending")?,
            ItemStatus::Disputed => l.disputed = sub(l.disputed, amount, "disputed")?,
            st => return Err(DomainError::Internal(format!("refund from {st:?}"))),
        }
        l.refunded = add(l.refunded, amount, "refunded")?;
        l.items[idx].status = ItemStatus::Refunded;
        l.items[idx].awaiting_delivery = false;
        self.audit.push(AuditEvent::ItemRefunded {
            slice,
            lender,
            kind,
            amount,
            reason,
        });
        Ok(())
    }

    /// JOB-S04 decision for a reserved item, based on its proof.
    fn decide(&mut self, slice: SliceId, lender: AccountId, idx: usize) -> R<Decision> {
        let item = self.slices[&slice].lines[&lender].items[idx].clone();
        let attempt_ready = self.job(slice.job)?.attempts[&slice.attempt].ready;
        // JOB-R35: a refund for missing proof only becomes final at the evaluation deadline.
        let before_deadline =
            self.now < self.slices[&slice].closed_at.unwrap_or(0) + self.cfg.evaluation_deadline;
        let refund = |r: RefundReason| {
            if before_deadline {
                Decision::Defer
            } else {
                Decision::Refund(r)
            }
        };
        Ok(match (item.kind, item.evidence) {
            (ItemKind::Contribution(cid), _)
                if self.charges.get(&cid.output).map(|c| c.gen) != Some(cid.charge) =>
            {
                // Output voided since reservation (JOB-R29).
                Decision::Refund(RefundReason::OutputVoided)
            }
            (ItemKind::Contribution(cid), _) if !self.charges[&cid.output].definitive => {
                // JOB-R30: never paid while its output is provisional.
                Decision::Await
            }
            (ItemKind::Contribution(cid), Evidence::Committed) => {
                if self.committed_before(slice, lender, cid.output.wt, cid.output.pos) {
                    Decision::Pay
                } else {
                    // Commitment claimed but not found: treated as no proof.
                    refund(RefundReason::EvidenceNotFound)
                }
            }
            (ItemKind::Recovery(_), Evidence::Committed) => {
                if attempt_ready {
                    Decision::Pay
                } else {
                    Decision::Refund(RefundReason::AttemptNotStarted)
                }
            }
            (_, Evidence::Uncommitted) => {
                // JOB-R19: sliding cap on gross admitted amounts.
                let now = self.now;
                let w = self.cfg.uncommitted_window;
                let log = self.uncommitted_paid.entry(lender).or_default();
                let recent = log
                    .iter()
                    .filter(|(t, _)| t + w > now)
                    .try_fold(0u64, |acc, (_, a)| acc.checked_add(*a))
                    .ok_or(DomainError::Overflow("sliding cap"))?;
                if add(recent, item.amount, "sliding cap")? <= self.cfg.uncommitted_cap {
                    log.push((now, item.amount));
                    Decision::Pay
                } else {
                    Decision::Dispute
                }
            }
            (_, Evidence::None) => refund(RefundReason::NoEvidence),
        })
    }

    /// JOB-S04: evaluates a closed slice.
    fn evaluate(&mut self, slice: SliceId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?
            .clone();
        if s.status != SliceStatus::Closed {
            return Err(DomainError::InvalidSliceTransition {
                from: s.status,
                rule: "JOB-S04",
            });
        }
        let mut changed = false;
        let mut deferred = false;
        for (lender, line) in &s.lines {
            for (idx, item) in line.items.iter().enumerate() {
                // CE-04: an item already decided since closure is not evaluated again.
                if item.status != ItemStatus::PendingEvaluation {
                    continue;
                }
                let decision = self.decide(slice, *lender, idx)?;
                match decision {
                    Decision::Pay => self.pay_item(slice, *lender, idx, false)?,
                    Decision::Refund(r) => self.refund_item(slice, *lender, idx, r)?,
                    Decision::Defer => {
                        deferred = true;
                        continue;
                    }
                    Decision::Dispute | Decision::Await => {
                        let awaiting = matches!(decision, Decision::Await);
                        let l = self.line_mut(slice, *lender)?;
                        l.pending = sub(l.pending, item.amount, "pending")?;
                        l.disputed = add(l.disputed, item.amount, "disputed")?;
                        l.items[idx].status = ItemStatus::Disputed;
                        l.items[idx].awaiting_delivery = awaiting;
                        self.audit.push(if awaiting {
                            AuditEvent::ItemAwaitingDelivery {
                                slice,
                                lender: *lender,
                                kind: item.kind,
                                amount: item.amount,
                            }
                        } else {
                            AuditEvent::ItemDisputed {
                                slice,
                                lender: *lender,
                                kind: item.kind,
                                amount: item.amount,
                            }
                        });
                    }
                }
                changed = true;
            }
        }
        // JOB-R35: while an item waits for proof, the slice stays closed until the deadline at
        // most. CE-06: same while a contribution still waits for its output, since it may go back
        // to pending.
        let before_deadline = self.now < s.closed_at.unwrap_or(0) + self.cfg.evaluation_deadline;
        let awaiting = self.slices[&slice]
            .lines
            .values()
            .any(|l| l.items.iter().any(|i| i.awaiting_delivery));
        if deferred || (before_deadline && awaiting) {
            return Ok(if changed {
                Outcome::Applied
            } else {
                Outcome::AlreadyApplied
            });
        }
        let disputed = self.slices[&slice].lines.values().any(|l| l.disputed > 0);
        let to = if disputed {
            SliceStatus::Disputed
        } else {
            SliceStatus::Final
        };
        self.set_slice(slice, to, "JOB-S04")?;
        self.maybe_return_earmark(slice.job, slice.attempt)?;
        Ok(Outcome::Applied)
    }

    /// JOB-S06: arbitrates a disputed line.
    fn arbitrate(&mut self, slice: SliceId, lender: AccountId, pay: bool) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        if s.status != SliceStatus::Disputed {
            return Err(DomainError::InvalidSliceTransition {
                from: s.status,
                rule: "JOB-S06",
            });
        }
        let line = s
            .lines
            .get(&lender)
            .ok_or(DomainError::Precondition("no line"))?;
        let idxs: Vec<usize> = line
            .items
            .iter()
            .enumerate()
            // JOB-R30: a contribution waiting for delivery follows its output, never arbitrated on
            // its own.
            .filter(|(_, i)| i.status == ItemStatus::Disputed && !i.awaiting_delivery)
            .map(|(k, _)| k)
            .collect();
        if idxs.is_empty() {
            return Err(DomainError::Precondition("line not disputed"));
        }
        for idx in idxs {
            if pay {
                self.pay_item(slice, lender, idx, true)?;
            } else {
                self.refund_item(slice, lender, idx, RefundReason::Arbitration)?;
            }
        }
        if self.slices[&slice].lines.values().all(|l| l.disputed == 0) {
            self.set_slice(slice, SliceStatus::Final, "JOB-S06")?;
            self.maybe_return_earmark(slice.job, slice.attempt)?;
        }
        Ok(Outcome::Applied)
    }

    fn resume(&mut self, job: JobId, topup: Amount) -> R<Outcome> {
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

    fn terminate(&mut self, job: JobId, to: ExecStatus, rule: &'static str) -> R<Outcome> {
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

    /// JOB-S12: returns everything left to the borrower; escrow ends at zero.
    fn settle(&mut self, job: JobId) -> R<Outcome> {
        let j = self.job(job)?.clone();
        if j.settle != SettleStatus::Finalizing {
            return Err(DomainError::Precondition("JOB-S12: not finalizing"));
        }
        if !self
            .slices_of(job, None)
            .iter()
            .all(|s| self.slices[s].status == SliceStatus::Final)
        {
            return Err(DomainError::Precondition("JOB-S12: slices not final"));
        }
        // JOB-R29: provisional deliveries are resolved before escrow is settled.
        if self
            .charges
            .iter()
            .any(|(o, ch)| o.job == job && !ch.definitive)
        {
            return Err(DomainError::Precondition(
                "JOB-S12: provisional outputs pending",
            ));
        }
        // CE-02: unspent pool relay goes back to the pool; everything else to the borrower. The
        // ledger takes both destinations from the escrow record.
        let pool_unspent = sub(j.pool_recovery_funded, j.recovery_paid_pool, "pool relay")?;
        self.ledger_op(LedgerOp::SettleJob {
            job: job_acct(job),
            pool_unspent,
        })
        .map_err(|e| match e {
            DomainError::Ledger(LedgerApiError::Invalid(m)) => DomainError::Internal(m.into()),
            other => other,
        })?;
        self.set_settle(job, SettleStatus::Closed, "JOB-S12")?;
        Ok(Outcome::Applied)
    }

    fn release_reward(&mut self, slice: SliceId, lender: AccountId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        let Some(final_at) = s.final_at else {
            return Err(DomainError::Precondition("JOB-R22: slice not final"));
        };
        if self.now < final_at + self.cfg.reward_window {
            return Err(DomainError::Precondition("JOB-R22: contest window open"));
        }
        let held = s.lines.get(&lender).map_or(0, |l| l.held);
        if held == 0 {
            return Err(DomainError::Precondition("nothing held"));
        }
        let LedgerOutcome::Released {
            to_lender,
            commission,
        } = self.ledger_op(LedgerOp::ReleaseReward {
            line: line_ref(slice, lender),
            key: format!("{:?}/{}", slice, lender.0),
        })?
        else {
            return Err(DomainError::Internal("release outcome".into()));
        };
        let l = self.line_mut(slice, lender)?;
        l.held = 0;
        l.released = add(l.released, held, "released")?;
        for it in l.items.iter_mut().filter(|i| i.status == ItemStatus::Paid) {
            it.reward_done = true;
        }
        self.audit.push(AuditEvent::RewardReleased {
            slice,
            lender,
            amount: to_lender,
            commission,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-R22: a contest refunds the borrower from held rewards; it never creates credits or
    /// touches the lender's balance.
    fn contest_reward(&mut self, slice: SliceId, lender: AccountId) -> R<Outcome> {
        let s = self
            .slices
            .get(&slice)
            .ok_or(DomainError::UnknownSlice(slice))?;
        if let Some(final_at) = s.final_at {
            if self.now >= final_at + self.cfg.reward_window {
                return Err(DomainError::Precondition("JOB-R22: contest window closed"));
            }
        }
        let held = s.lines.get(&lender).map_or(0, |l| l.held);
        if held == 0 {
            return Err(DomainError::Precondition("nothing held"));
        }
        // CE-02: each payer gets its own share back (the pool for the recovery it funded).
        let to_pool = s.lines[&lender]
            .items
            .iter()
            .filter(|i| i.status == ItemStatus::Paid && !i.reward_done)
            .try_fold(0u64, |acc, i| acc.checked_add(i.pool_part))
            .ok_or(DomainError::Overflow("pool part"))?;
        self.ledger_op(LedgerOp::ContestReward {
            line: line_ref(slice, lender),
            key: format!("{:?}/{}", slice, lender.0),
            pool_part: to_pool,
        })?;
        let j = self.job_mut(slice.job)?;
        j.recovery_contested_pool = add(j.recovery_contested_pool, to_pool, "contested pool")?;
        let l = self.line_mut(slice, lender)?;
        l.held = 0;
        l.contested = add(l.contested, held, "contested")?;
        for it in l.items.iter_mut().filter(|i| i.status == ItemStatus::Paid) {
            it.reward_done = true;
        }
        self.audit.push(AuditEvent::RewardContested {
            slice,
            lender,
            amount: held,
        });
        Ok(Outcome::Applied)
    }

    /// JOB-R20: applies every automatic transition that is due. Each stays atomic; reconciliation
    /// is idempotent.
    fn reconcile(&mut self, ctx: &AuthContext) -> R<Outcome> {
        let mut changed = false;
        for _ in 0..64 {
            let mut todo: Vec<Command> = Vec::new();
            let now = self.now;
            let c = &self.cfg;
            for j in self.jobs.values() {
                let since = now.saturating_sub(j.exec_since);
                match j.exec {
                    ExecStatus::Queued if since >= c.queued_wait => {
                        todo.push(Command::RejectQueued { job: j.id })
                    }
                    ExecStatus::Reserved if since >= c.reserved_wait => {
                        todo.push(Command::Cancel {
                            job: j.id,
                            expected_version: None,
                        })
                    }
                    ExecStatus::Placing
                        if since >= c.placing_timeout
                            || j.current().is_some_and(|a| now >= a.lease_expires_at) =>
                    {
                        todo.push(Command::PlacementFailed { job: j.id })
                    }
                    ExecStatus::Recovering if since >= c.recovery_timeout => {
                        todo.push(Command::RecoveryTimeout { job: j.id })
                    }
                    ExecStatus::Paused if since >= c.pause_max => {
                        todo.push(Command::ExpirePause { job: j.id })
                    }
                    ExecStatus::Running => {
                        // JOB-R31: expired lease means lost node.
                        if j.current().is_some_and(|a| now >= a.lease_expires_at) {
                            todo.push(Command::NodeLost {
                                job: j.id,
                                expected_version: None,
                            });
                        }
                        let window = j.current().is_some_and(|a| a.produced != j.validated);
                        if window && now.saturating_sub(j.last_ack_at) >= c.client_silence {
                            todo.push(Command::Pause {
                                job: j.id,
                                reason: PauseReason::ClientSilent,
                                expected_version: None,
                            });
                        }
                    }
                    ExecStatus::Settling => todo.push(Command::CompleteSettling { job: j.id }),
                    _ => {}
                }
                if j.settle == SettleStatus::Finalizing {
                    todo.push(Command::Settle { job: j.id });
                }
                if !self.window_due(j.id).is_empty() {
                    todo.push(Command::ExpireDeliveryWindow { job: j.id });
                }
                let contest_due = self.charges.iter().any(|(o, ch)| {
                    o.job == j.id && !ch.definitive && ch.contest.is_some_and(|k| now >= k.deadline)
                });
                if contest_due {
                    todo.push(Command::ResolveContests { job: j.id });
                }
            }
            for s in self.slices.values() {
                match s.status {
                    SliceStatus::Draining if now >= s.receipt_deadline.unwrap_or(0) => {
                        todo.push(Command::CloseSlice { slice: s.id })
                    }
                    SliceStatus::Closed
                        if now >= s.closed_at.unwrap_or(0) + c.evaluation_deadline =>
                    {
                        todo.push(Command::Evaluate { slice: s.id })
                    }
                    SliceStatus::Disputed
                        if now >= s.closed_at.unwrap_or(0) + c.dispute_deadline =>
                    {
                        for (lender, l) in &s.lines {
                            let arbitrable = l
                                .items
                                .iter()
                                .any(|i| i.status == ItemStatus::Disputed && !i.awaiting_delivery);
                            if arbitrable {
                                todo.push(Command::Arbitrate {
                                    slice: s.id,
                                    lender: *lender,
                                    pay: false,
                                });
                            }
                        }
                    }
                    // JOB-R22: automatic release at the end of the window.
                    SliceStatus::Final
                        if s.final_at.is_some_and(|f| now >= f + c.reward_window) =>
                    {
                        for (lender, l) in &s.lines {
                            if l.held > 0 {
                                todo.push(Command::ReleaseReward {
                                    slice: s.id,
                                    lender: *lender,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            let mut progressed = false;
            for cmd in todo {
                match self.execute(ctx, &cmd) {
                    Ok(Outcome::Applied) => progressed = true,
                    // Reconciliation never swallows an internal error; it would silently block the
                    // job (CE-04).
                    Err(DomainError::Internal(m)) => {
                        return Err(DomainError::Internal(format!("reconcile {cmd:?}: {m}")))
                    }
                    // A due transition the reconciler may not run is a permission matrix bug: it
                    // would stay due forever.
                    Err(DomainError::Unauthorized(m)) => {
                        return Err(DomainError::Internal(format!("reconcile {cmd:?}: {m}")))
                    }
                    _ => {}
                }
            }
            if !progressed {
                break;
            }
            changed = true;
        }
        Ok(if changed {
            Outcome::Applied
        } else {
            Outcome::AlreadyApplied
        })
    }
}

enum Decision {
    Pay,
    Refund(RefundReason),
    Dispute,
    /// Output still provisional (JOB-R30).
    Await,
    /// Refund for missing proof, deferred to the deadline (JOB-R35).
    Defer,
}

/// FNV-1a over 64-bit words (symbolic digests in the model).
fn fnv(words: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in words {
        for b in w.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}
