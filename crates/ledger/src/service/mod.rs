//! Ledger service: the only way to change balances (trust domain "Ledger").
//!
//! Callers present their own [`ServiceCredential`]. Each request is a typed operation with fixed
//! source and destination account kinds; there is no generic transfer. The Ledger does not take
//! the orchestrator's word for who worked or what anything costs: it keeps the terms the owner
//! signed, the attempts their lenders signed, the receipts their recipients signed and the
//! provenance of every reserve, and computes prices, shares, recovery splits and settlement
//! itself. Every request is counted, every denial is logged, and an operation that needs several
//! entries is written entirely or not at all.

use std::collections::BTreeMap;

use more_identity::{
    CredentialVerifier, Domain, KeyDirectory, ServiceCertificate, ServiceCredential, ServiceRole,
};

use crate::{Account, Amount, Ledger};

mod book;
mod funds;
mod lines;
mod types;
mod work;

pub use book::{AttemptRec, Corroboration, Escrow, ItemRec, ItemState, OutputRec};
pub use types::{
    Assignment, Denial, EscrowBucket, IssueTo, ItemId, JobTerms, LedgerApiError, LedgerLimits,
    LedgerOp, LedgerOutcome, LineRef, OutputRef,
};

/// Most denials kept in memory; older ones are only counted.
const DENIAL_LOG: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerService {
    ledger: Ledger,
    verifier: CredentialVerifier,
    /// The deployment every signed statement must name (LEDGER-019).
    domain: Domain,
    keys: KeyDirectory,
    limits: LedgerLimits,
    escrows: BTreeMap<u32, Escrow>,
    /// Admin of each pool's treasury, set by the platform admin.
    pools: BTreeMap<u32, u32>,
    /// Ledger time, moved by the Clock service only (LEDGER-018).
    now: u64,
    /// Accepted operations so far: the order of the ledger's records (CE-03).
    seq: u64,
    /// Accepted requests per (role, operation).
    accepted: BTreeMap<(ServiceRole, &'static str), u64>,
    denials: Vec<Denial>,
    denied: u64,
}

type ApiResult<T = LedgerOutcome> = Result<T, LedgerApiError>;

impl LedgerService {
    pub fn new(verifier: CredentialVerifier, keys: KeyDirectory, limits: LedgerLimits) -> Self {
        LedgerService {
            ledger: Ledger::new(),
            domain: verifier.domain(),
            verifier,
            keys,
            limits,
            escrows: BTreeMap::new(),
            pools: BTreeMap::new(),
            now: 0,
            seq: 0,
            accepted: BTreeMap::new(),
            denials: Vec::new(),
            denied: 0,
        }
    }

    /// Test only: the journal fails after `after` more entries (`None` clears the fault).
    #[cfg(feature = "fault-injection")]
    pub fn inject_fault(&mut self, after: Option<u64>) {
        self.ledger.inject_fault(after);
    }

    /// Ledger time.
    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn limits(&self) -> &LedgerLimits {
        &self.limits
    }

    /// The deployment whose statements this ledger accepts.
    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// Number of operations accepted so far.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Number of requests refused so far.
    pub(crate) fn denied(&self) -> u64 {
        self.denied
    }

    /// Runs one operation for `caller`. Nothing is written unless every check passes and every
    /// entry of the operation succeeds: each operation checks first, writes its entries, and only
    /// then updates the job records, so rolling back the journal is enough.
    pub fn execute(&mut self, caller: &ServiceCredential, op: LedgerOp) -> ApiResult {
        self.execute_as(&caller.certificate(), op)
    }

    /// Same, for a caller known by its certificate. Only for a peer that has proved it holds
    /// the certified key: that is what the link's handshake establishes.
    pub fn execute_as(&mut self, caller: &ServiceCertificate, op: LedgerOp) -> ApiResult {
        let kind = op.kind();
        let role = match self.verifier.verify_certificate(caller) {
            Ok(r) => r,
            Err(e) => return Err(self.deny(None, kind, LedgerApiError::Unauthenticated(e))),
        };
        if role != op.required_role() {
            let e = LedgerApiError::Forbidden { role, op: kind };
            return Err(self.deny(Some(role), kind, e));
        }
        let mark = self.ledger.mark();
        match self.run(op) {
            Ok(out) => {
                self.seq += 1;
                *self.accepted.entry((role, kind)).or_default() += 1;
                Ok(out)
            }
            Err(e) => {
                self.ledger.rollback(mark);
                Err(self.deny(Some(role), kind, e))
            }
        }
    }

    fn deny(
        &mut self,
        caller: Option<ServiceRole>,
        op: &'static str,
        e: LedgerApiError,
    ) -> LedgerApiError {
        self.denied += 1;
        if self.denials.len() < DENIAL_LOG {
            self.denials.push(Denial {
                caller,
                op,
                error: e.clone(),
            });
        }
        e
    }

    /// Balance of one of a job's accounts, for the orchestrator.
    pub fn job_balance(&self, caller: &ServiceCredential, account: Account) -> ApiResult<Amount> {
        self.job_balance_as(&caller.certificate(), account)
    }

    /// Same, for a peer that proved it holds the certified key.
    pub fn job_balance_as(
        &self,
        caller: &ServiceCertificate,
        account: Account,
    ) -> ApiResult<Amount> {
        let role = self
            .verifier
            .verify_certificate(caller)
            .map_err(LedgerApiError::Unauthenticated)?;
        let job_scoped = matches!(
            account,
            Account::EscrowWork(_)
                | Account::EscrowRecovery(_)
                | Account::OutputHold(_)
                | Account::SliceLine { .. }
                | Account::PendingReward { .. }
        );
        if role != ServiceRole::Orchestrator || !job_scoped {
            return Err(LedgerApiError::Forbidden {
                role,
                op: "job_balance",
            });
        }
        Ok(self.ledger.available(account))
    }

    /// Full read-only view (journal, every balance), for the Auditor role only.
    pub fn audit_view(&self, caller: &ServiceCredential) -> ApiResult<&Ledger> {
        self.audit_view_as(&caller.certificate())
    }

    /// Same, for a peer that proved it holds the certified key.
    pub fn audit_view_as(&self, caller: &ServiceCertificate) -> ApiResult<&Ledger> {
        let role = self
            .verifier
            .verify_certificate(caller)
            .map_err(LedgerApiError::Unauthenticated)?;
        if role != ServiceRole::Auditor {
            return Err(LedgerApiError::Forbidden {
                role,
                op: "audit_view",
            });
        }
        Ok(&self.ledger)
    }

    /// Job records (terms, attempts, receipts, items), for the Auditor role only.
    pub fn audit_escrows(&self, caller: &ServiceCredential) -> ApiResult<&BTreeMap<u32, Escrow>> {
        self.audit_view(caller)?;
        Ok(&self.escrows)
    }

    pub fn audit_denials(&self, caller: &ServiceCredential) -> ApiResult<(&[Denial], u64)> {
        self.audit_view(caller)?;
        Ok((&self.denials, self.denied))
    }

    fn amount_ok(&self, amount: Amount) -> ApiResult<()> {
        if amount > self.limits.max_amount {
            return Err(LedgerApiError::LimitExceeded(
                "amount above the per-entry limit",
            ));
        }
        Ok(())
    }

    fn escrow(&self, job: u32) -> ApiResult<&Escrow> {
        self.escrows
            .get(&job)
            .ok_or(LedgerApiError::UnknownEscrow(job))
    }

    /// An escrow that is not settled yet (LEDGER-014).
    fn live_escrow(&self, job: u32) -> ApiResult<&Escrow> {
        let e = self.escrow(job)?;
        if e.settled {
            return Err(LedgerApiError::EscrowSettled(job));
        }
        Ok(e)
    }

    fn live_escrow_mut(&mut self, job: u32) -> ApiResult<&mut Escrow> {
        let e = self
            .escrows
            .get_mut(&job)
            .ok_or(LedgerApiError::UnknownEscrow(job))?;
        if e.settled {
            return Err(LedgerApiError::EscrowSettled(job));
        }
        Ok(e)
    }

    fn run(&mut self, op: LedgerOp) -> ApiResult {
        match op {
            LedgerOp::Advance { now } => {
                if now < self.now {
                    return Err(LedgerApiError::Invalid("the clock never goes back"));
                }
                self.now = now;
                Ok(LedgerOutcome::Done)
            }
            LedgerOp::Issue { key, to, amount } => self.issue(key, to, amount),
            LedgerOp::OpenEscrow {
                job,
                owner,
                pool,
                terms,
                signature,
            } => self.open_escrow(job, owner, pool, terms, &signature),
            LedgerOp::Reserve {
                job,
                bucket,
                key,
                amount,
            } => self.reserve(job, bucket, key, amount),
            LedgerOp::RegisterPool { pool, admin } => {
                if self.pools.contains_key(&pool) {
                    return Err(LedgerApiError::Invalid("pool already registered"));
                }
                self.pools.insert(pool, admin);
                Ok(LedgerOutcome::Done)
            }
            LedgerOp::FundRecovery {
                job,
                amount,
                signature,
            } => self.fund_recovery(job, amount, &signature),
            LedgerOp::RegisterAttempt { assignment } => self.register_attempt(assignment),
            LedgerOp::AcceptLease {
                job,
                attempt,
                stage,
                signature,
            } => self.accept_lease(job, attempt, stage, &signature),
            LedgerOp::LeaseReady {
                job,
                attempt,
                stage,
                restored,
                state,
                segments,
                signature,
            } => self.lease_ready(job, attempt, stage, (restored, state, segments), &signature),
            LedgerOp::RecordRestore {
                job,
                attempt,
                producer,
                segments,
                signature,
            } => self.record_restore(job, attempt, producer, segments, &signature),
            LedgerOp::RevokeAttempt { job, attempt } => self.revoke_attempt(job, attempt),
            LedgerOp::RecordReceipt {
                job,
                attempt,
                producer,
                wt,
                upto,
                digest,
                signature,
            } => self.record_receipt(job, attempt, producer, (wt, upto, digest), &signature),
            LedgerOp::ChargeOutput {
                job,
                attempt,
                output,
                gen,
            } => self.charge_output(job, attempt, output, gen),
            LedgerOp::VoidOutput { job, output, gen } => self.void_output(job, output, gen),
            LedgerOp::ReserveContribution {
                line,
                output,
                gen,
                stage,
            } => self.reserve_contribution(line, output, gen, stage),
            LedgerOp::ReserveRecovery {
                line,
                segment,
                amount,
            } => self.reserve_recovery(line, segment, amount),
            LedgerOp::PayLine { line, item } => self.pay_line(line, item),
            LedgerOp::RefundLine { line, item } => self.refund_line(line, item),
            LedgerOp::ReleaseReward { line } => self.release_reward(line),
            LedgerOp::ContestReward { line } => self.contest_reward(line),
            LedgerOp::ReturnEarmark { job, attempt } => self.return_earmark(job, attempt),
            LedgerOp::SettleJob { job } => self.settle_job(job),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use more_identity::{mandate_message, IdentityAuthority, UserKey};

    use super::*;

    /// An operation with several entries is written entirely or not at all. Keys are derived by
    /// the ledger, so the collision that makes the second entry fail is planted from inside.
    #[test]
    fn failed_multi_entry_operation_writes_nothing() {
        let mut auth = IdentityAuthority::new([5; 32]);
        let keys = KeyDirectory::new();
        let owner = UserKey::from_seed([1; 32]);
        keys.register(1, owner.public()).unwrap();
        let mut s = LedgerService::new(auth.verifier(), keys, LedgerLimits::default());
        let (treasury, orch) = (
            auth.issue(ServiceRole::Treasury),
            auth.issue(ServiceRole::Orchestrator),
        );
        let issue = LedgerOp::Issue {
            key: "i".into(),
            to: IssueTo::User(1),
            amount: 100,
        };
        s.execute(&treasury, issue).unwrap();
        let terms = JobTerms {
            model: 1,
            layers: 1,
            price: [0, 1, 0],
            max_outputs: [0, 1, 0],
            max_budget: 50,
        };
        let signature = owner.sign(&mandate_message(&s.domain(), 1, 1, 1, &terms));
        let open = LedgerOp::OpenEscrow {
            job: 1,
            owner: 1,
            pool: 1,
            terms,
            signature,
        };
        s.execute(&orch, open).unwrap();
        let reserve = LedgerOp::Reserve {
            job: 1,
            bucket: EscrowBucket::Work,
            key: "r".into(),
            amount: 40,
        };
        s.execute(&orch, reserve).unwrap();
        // Settlement writes `settle/1/recovery-pool` (nothing here), then `settle/1/work`,
        // `settle/1/recovery` and `settle/1/hold`. Put credits in the hold and take its key.
        s.ledger
            .transfer(
                "x",
                Account::EscrowWork(1),
                Account::OutputHold(1),
                10,
                "test",
            )
            .unwrap();
        s.ledger
            .transfer("settle/1/hold", Account::User(1), Account::Burn, 1, "test")
            .unwrap();
        let before = s.clone();
        let e = s
            .execute(&orch, LedgerOp::SettleJob { job: 1 })
            .unwrap_err();
        assert!(matches!(
            e,
            LedgerApiError::Ledger(crate::LedgerError::DuplicateKey(_))
        ));
        // The first entry (work escrow back to the owner) was undone, and the job is not closed.
        assert_eq!(s.ledger, before.ledger);
        assert_eq!(s.escrows, before.escrows);
    }
}
