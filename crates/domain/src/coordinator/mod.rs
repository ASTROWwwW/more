//! Coordinator (Job Orchestrator trust domain): applies commands as atomic transitions.
//! `execute` authorizes a command, runs it on a full copy of the state and keeps the copy only if
//! the whole transition succeeds, the in-memory equivalent of JOB-R01's single transaction.
//!
//! The ledger is reached only through typed operations and the orchestrator's own credential
//! (`ledger_op`); delivery state and the pool registry live in their own books, with private
//! fields.

use std::collections::BTreeMap;

use gpu_ledger::{
    Account, Amount, EscrowBucket, IssueTo, Ledger, LedgerApiError, LedgerError, LedgerOp,
    LedgerOutcome, LedgerService, LineRef, LineSource,
};
use more_identity::{AuthContext, ServiceCredential, ServiceRole};

use crate::authorization::authorize;
use crate::command::{Command, IssueTarget, Outcome};
use crate::config::{Config, MAX_TIME};
use crate::delivery_book::DeliveryBook;
use crate::error::DomainError;
use crate::ids::*;
use crate::model::*;
use crate::registry::{PoolMode, Registry};

mod audit;
mod claims;
mod contests;
mod delivery;
mod dispatch;
mod evaluation;
mod lifecycle;
mod placement;
mod receipts;
mod reconciliation;
mod rewards;

pub use audit::AuditEvent;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinator {
    cfg: Config,
    now: Time,
    /// Ledger service. Private: reached only through typed operations, with the orchestrator's
    /// own credential (`ledger_op`).
    ledger: LedgerService,
    /// The orchestrator's credential towards the ledger (role `Orchestrator`).
    cred: ServiceCredential,
    /// Model Registry: pools, members, catalog.
    registry: Registry,
    /// Delivery state: charges, contests, witness commitments.
    delivery: DeliveryBook,
    jobs: BTreeMap<JobId, Job>,
    slices: BTreeMap<SliceId, Slice>,
    /// Reserved or paid contribution to its slice (JOB-R21).
    contributions: BTreeMap<ContributionId, SliceId>,
    /// Reserved or paid recovery work to its slice (JOB-R18).
    recovery_items: BTreeMap<RecoveryWorkId, SliceId>,
    /// Payments admitted on uncommitted receipts, per account: (time, amount). Gross amounts; a
    /// refund does not restore quota (JOB-R19).
    uncommitted_paid: BTreeMap<AccountId, Vec<(Time, Amount)>>,
    /// Receipt commitment history: (covered up to, time, seq) (JOB-R15).
    commit_log: CommitLog,
    /// Logical sequence number: total order of applied commands (CE-03).
    seq: u64,
    audit: Vec<AuditEvent>,
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
            registry: Registry::default(),
            delivery: DeliveryBook::default(),
            jobs: BTreeMap::new(),
            slices: BTreeMap::new(),
            contributions: BTreeMap::new(),
            recovery_items: BTreeMap::new(),
            uncommitted_paid: BTreeMap::new(),
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

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Coordinator clock (JOB-R09).
    pub fn now(&self) -> Time {
        self.now
    }

    /// Position of the last applied command in the log (CE-03).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn audit_log(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn delivery(&self) -> &DeliveryBook {
        &self.delivery
    }

    pub fn jobs(&self) -> &BTreeMap<JobId, Job> {
        &self.jobs
    }

    pub fn slices(&self) -> &BTreeMap<SliceId, Slice> {
        &self.slices
    }

    pub fn contributions(&self) -> &BTreeMap<ContributionId, SliceId> {
        &self.contributions
    }

    pub fn recovery_items(&self) -> &BTreeMap<RecoveryWorkId, SliceId> {
        &self.recovery_items
    }

    pub fn uncommitted_paid(&self) -> &BTreeMap<AccountId, Vec<(Time, Amount)>> {
        &self.uncommitted_paid
    }

    pub fn commit_log(&self) -> &CommitLog {
        &self.commit_log
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
        Ok(self.registry.pool(pool)?.is_credits())
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

    fn require_exec(&self, job: JobId, want: ExecStatus, rule: &'static str) -> R {
        let from = self.job(job)?.exec;
        if from != want {
            return Err(DomainError::InvalidTransition { from, rule });
        }
        Ok(())
    }
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
