//! Ledger service: the only way to change balances (trust domain "Ledger").
//!
//! Callers present their own [`ServiceCredential`]. Each request is a typed operation with fixed
//! source and destination account kinds; there is no generic transfer. Before writing, the service
//! checks the caller's credential and role, the accounts (same job, its owner, its pool, its
//! lenders), the borrower's signed mandate and the amount limits. Every request is counted, every
//! denial is logged, and an operation that needs several entries is written entirely or not at all.

use std::collections::BTreeMap;
use std::fmt;

use more_identity::{
    mandate_message, AuthError, CredentialVerifier, KeyDirectory, ServiceCredential, ServiceRole,
};

use crate::{Account, Amount, Ledger, LedgerError};

/// Bounds enforced on every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerLimits {
    /// Largest amount a single entry may move.
    pub max_amount: Amount,
    /// Largest single issuance.
    pub max_issue: Amount,
    /// Total credits that may ever be issued.
    pub supply_cap: Amount,
    /// Commission taken on release, in basis points (LEDGER-008). Set here so the orchestrator
    /// cannot change what lenders receive.
    pub commission_bps: u64,
}

impl Default for LedgerLimits {
    fn default() -> Self {
        LedgerLimits {
            max_amount: 1_000_000_000_000,
            max_issue: 1_000_000_000_000,
            supply_cap: 1_000_000_000_000_000,
            commission_bps: 1_000,
        }
    }
}

/// Escrow of one job: who owns it, which pool it runs in, and how much its owner agreed to lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub owner: u32,
    pub pool: u32,
    /// Budget signed by the owner.
    pub mandate: Amount,
    /// Credits already taken from the owner for this job.
    pub locked: Amount,
    pub settled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowBucket {
    Work,
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTo {
    User(u32),
    Pool(u32),
}

/// Line `(job, attempt, slice, lender)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineRef {
    pub job: u32,
    pub attempt: u32,
    pub slice: u32,
    pub lender: u32,
}

impl LineRef {
    fn line(self) -> Account {
        Account::SliceLine {
            job: self.job,
            attempt: self.attempt,
            slice: self.slice,
            lender: self.lender,
        }
    }

    fn reward(self) -> Account {
        Account::PendingReward {
            job: self.job,
            attempt: self.attempt,
            slice: self.slice,
            lender: self.lender,
        }
    }
}

/// Where a line's reserve comes from and goes back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineSource {
    OutputHold,
    Recovery,
}

/// Typed ledger operations. Keys are the caller's idempotency keys (LEDGER-001).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerOp {
    /// LEDGER-003. Treasury only.
    Issue {
        key: String,
        to: IssueTo,
        amount: Amount,
    },
    /// Records the owner of a job's escrow and the budget the owner signed.
    OpenEscrow {
        job: u32,
        owner: u32,
        pool: u32,
        max_budget: Amount,
        signature: [u8; 64],
    },
    /// Owner's balance to the job escrow (JOB-T02, JOB-T12), within the signed budget.
    Reserve {
        job: u32,
        bucket: EscrowBucket,
        key: String,
        amount: Amount,
    },
    /// Pool relay of the recovery budget (JOB-R18): the job's own pool only.
    FundRecovery {
        job: u32,
        key: String,
        amount: Amount,
    },
    /// Work escrow to output hold (JOB-R23, JOB-R27).
    ChargeOutput {
        job: u32,
        key: String,
        amount: Amount,
    },
    /// Output hold back to work escrow (JOB-R29, LEDGER-010).
    VoidOutput {
        job: u32,
        key: String,
        amount: Amount,
    },
    /// JOB-S03.
    ReserveLine {
        line: LineRef,
        source: LineSource,
        key: String,
        amount: Amount,
    },
    /// JOB-S04: line reserve to held reward.
    PayLine {
        line: LineRef,
        key: String,
        amount: Amount,
    },
    /// JOB-S04: line reserve back to where it came from.
    RefundLine {
        line: LineRef,
        to: LineSource,
        key: String,
        amount: Amount,
    },
    /// JOB-R22, LEDGER-008: the whole held reward to the lender of the line, minus commission.
    ReleaseReward { line: LineRef, key: String },
    /// JOB-R22: the whole held reward back to the job's pool (`pool_part`) and owner (the rest).
    ContestReward {
        line: LineRef,
        key: String,
        pool_part: Amount,
    },
    /// JOB-S12: unspent pool relay to the job's pool, everything else to the owner. Destinations
    /// are taken from the escrow record, never from the request.
    SettleJob { job: u32, pool_unspent: Amount },
}

impl LedgerOp {
    pub fn kind(&self) -> &'static str {
        match self {
            LedgerOp::Issue { .. } => "Issue",
            LedgerOp::OpenEscrow { .. } => "OpenEscrow",
            LedgerOp::Reserve { .. } => "Reserve",
            LedgerOp::FundRecovery { .. } => "FundRecovery",
            LedgerOp::ChargeOutput { .. } => "ChargeOutput",
            LedgerOp::VoidOutput { .. } => "VoidOutput",
            LedgerOp::ReserveLine { .. } => "ReserveLine",
            LedgerOp::PayLine { .. } => "PayLine",
            LedgerOp::RefundLine { .. } => "RefundLine",
            LedgerOp::ReleaseReward { .. } => "ReleaseReward",
            LedgerOp::ContestReward { .. } => "ContestReward",
            LedgerOp::SettleJob { .. } => "SettleJob",
        }
    }

    /// Permission matrix: the one role allowed to request each operation.
    fn required_role(&self) -> ServiceRole {
        match self {
            LedgerOp::Issue { .. } => ServiceRole::Treasury,
            _ => ServiceRole::Orchestrator,
        }
    }
}

/// What an accepted operation did, when the caller needs the amounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerOutcome {
    Done,
    Released {
        to_lender: Amount,
        commission: Amount,
    },
    Contested {
        to_pool: Amount,
        to_owner: Amount,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerApiError {
    /// The credential is not valid or was revoked.
    Unauthenticated(AuthError),
    /// The caller's role may not request this operation or read this data.
    Forbidden {
        role: ServiceRole,
        op: &'static str,
    },
    UnknownEscrow(u32),
    EscrowExists(u32),
    EscrowSettled(u32),
    /// The mandate signature does not verify against the owner's registered key.
    BadMandate,
    /// The owner never agreed to lock that much for this job.
    MandateExceeded {
        job: u32,
        mandate: Amount,
        requested_total: u128,
    },
    LimitExceeded(&'static str),
    Invalid(&'static str),
    Ledger(LedgerError),
}

impl LedgerApiError {
    pub fn code(&self) -> &'static str {
        match self {
            LedgerApiError::Unauthenticated(_) => "UNAUTHENTICATED",
            LedgerApiError::Forbidden { .. } => "FORBIDDEN",
            LedgerApiError::LimitExceeded(_) => "LIMIT_EXCEEDED",
            _ => "LEDGER_REJECTED",
        }
    }
}

impl From<LedgerError> for LedgerApiError {
    fn from(e: LedgerError) -> Self {
        LedgerApiError::Ledger(e)
    }
}

impl fmt::Display for LedgerApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerApiError {}

/// A refused request, kept for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub caller: Option<ServiceRole>,
    pub op: &'static str,
    pub error: LedgerApiError,
}

/// Most denials kept in memory; older ones are only counted.
const DENIAL_LOG: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerService {
    ledger: Ledger,
    verifier: CredentialVerifier,
    keys: KeyDirectory,
    limits: LedgerLimits,
    escrows: BTreeMap<u32, Escrow>,
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
            verifier,
            keys,
            limits,
            escrows: BTreeMap::new(),
            accepted: BTreeMap::new(),
            denials: Vec::new(),
            denied: 0,
        }
    }

    pub fn limits(&self) -> &LedgerLimits {
        &self.limits
    }

    /// Runs one operation for `caller`. Nothing is written unless every check passes and every
    /// entry of the operation succeeds.
    pub fn execute(&mut self, caller: &ServiceCredential, op: LedgerOp) -> ApiResult {
        let kind = op.kind();
        let role = match self.verifier.verify(caller) {
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
        let role = self
            .verifier
            .verify(caller)
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
        let role = self
            .verifier
            .verify(caller)
            .map_err(LedgerApiError::Unauthenticated)?;
        if role != ServiceRole::Auditor {
            return Err(LedgerApiError::Forbidden {
                role,
                op: "audit_view",
            });
        }
        Ok(&self.ledger)
    }

    /// Escrow records and request counters, for the Auditor role only.
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

    fn live_escrow(&self, job: u32) -> ApiResult<&Escrow> {
        let e = self.escrow(job)?;
        if e.settled {
            return Err(LedgerApiError::EscrowSettled(job));
        }
        Ok(e)
    }

    fn run(&mut self, op: LedgerOp) -> ApiResult {
        match op {
            LedgerOp::Issue { key, to, amount } => {
                if amount > self.limits.max_issue {
                    return Err(LedgerApiError::LimitExceeded(
                        "issuance above the per-issue limit",
                    ));
                }
                let issued = u128::try_from(-self.ledger.balance(Account::Issuance)).unwrap_or(0);
                if issued + u128::from(amount) > u128::from(self.limits.supply_cap) {
                    return Err(LedgerApiError::LimitExceeded("supply cap"));
                }
                let dest = match to {
                    IssueTo::User(u) => Account::User(u),
                    IssueTo::Pool(p) => Account::PoolReserve(p),
                };
                self.ledger.transfer(
                    key,
                    Account::Issuance,
                    dest,
                    amount,
                    "LEDGER-003 issuance",
                )?;
            }
            LedgerOp::OpenEscrow {
                job,
                owner,
                pool,
                max_budget,
                signature,
            } => {
                if self.escrows.contains_key(&job) {
                    return Err(LedgerApiError::EscrowExists(job));
                }
                self.amount_ok(max_budget)?;
                let msg = mandate_message(job, pool, owner, max_budget);
                self.keys
                    .verify(owner, &msg, &signature)
                    .map_err(|_| LedgerApiError::BadMandate)?;
                self.escrows.insert(
                    job,
                    Escrow {
                        owner,
                        pool,
                        mandate: max_budget,
                        locked: 0,
                        settled: false,
                    },
                );
            }
            LedgerOp::Reserve {
                job,
                bucket,
                key,
                amount,
            } => {
                self.amount_ok(amount)?;
                let e = self.live_escrow(job)?;
                let total = u128::from(e.locked) + u128::from(amount);
                if total > u128::from(e.mandate) {
                    return Err(LedgerApiError::MandateExceeded {
                        job,
                        mandate: e.mandate,
                        requested_total: total,
                    });
                }
                let owner = e.owner;
                let (to, reason) = match bucket {
                    EscrowBucket::Work => (Account::EscrowWork(job), "JOB-T02 work escrow"),
                    EscrowBucket::Recovery => {
                        (Account::EscrowRecovery(job), "JOB-T02 recovery budget")
                    }
                };
                self.ledger
                    .transfer(key, Account::User(owner), to, amount, reason)?;
                if let Some(e) = self.escrows.get_mut(&job) {
                    // `total` fits: it is bounded by the mandate, itself an Amount.
                    e.locked =
                        u64::try_from(total).map_err(|_| LedgerApiError::Invalid("locked"))?;
                }
            }
            LedgerOp::FundRecovery { job, key, amount } => {
                self.amount_ok(amount)?;
                let pool = self.live_escrow(job)?.pool;
                self.ledger.transfer(
                    key,
                    Account::PoolReserve(pool),
                    Account::EscrowRecovery(job),
                    amount,
                    "JOB-R18 pool relay",
                )?;
            }
            LedgerOp::ChargeOutput { job, key, amount } => {
                self.amount_ok(amount)?;
                self.live_escrow(job)?;
                let reason = "JOB-R23/R27 charge output";
                self.ledger.transfer(
                    key,
                    Account::EscrowWork(job),
                    Account::OutputHold(job),
                    amount,
                    reason,
                )?;
            }
            LedgerOp::VoidOutput { job, key, amount } => {
                self.amount_ok(amount)?;
                self.live_escrow(job)?;
                let reason = "JOB-R29 void provisional output";
                self.ledger.transfer(
                    key,
                    Account::OutputHold(job),
                    Account::EscrowWork(job),
                    amount,
                    reason,
                )?;
            }
            LedgerOp::ReserveLine {
                line,
                source,
                key,
                amount,
            } => {
                self.amount_ok(amount)?;
                self.live_escrow(line.job)?;
                let (from, reason) = match source {
                    LineSource::OutputHold => (
                        Account::OutputHold(line.job),
                        "JOB-S03 reserve contribution",
                    ),
                    LineSource::Recovery => (
                        Account::EscrowRecovery(line.job),
                        "JOB-S03 reserve recovery",
                    ),
                };
                self.ledger
                    .transfer(key, from, line.line(), amount, reason)?;
            }
            LedgerOp::PayLine { line, key, amount } => {
                self.amount_ok(amount)?;
                self.escrow(line.job)?;
                self.ledger.transfer(
                    key,
                    line.line(),
                    line.reward(),
                    amount,
                    "JOB-S04 held payment",
                )?;
            }
            LedgerOp::RefundLine {
                line,
                to,
                key,
                amount,
            } => {
                self.amount_ok(amount)?;
                self.escrow(line.job)?;
                let dest = match to {
                    LineSource::OutputHold => Account::OutputHold(line.job),
                    LineSource::Recovery => Account::EscrowRecovery(line.job),
                };
                self.ledger
                    .transfer(key, line.line(), dest, amount, "JOB-S04 refund")?;
            }
            LedgerOp::ReleaseReward { line, key } => {
                self.escrow(line.job)?;
                let held = self.ledger.available(line.reward());
                if held == 0 {
                    return Err(LedgerApiError::Invalid("nothing held"));
                }
                let commission = u64::try_from(
                    u128::from(held) * u128::from(self.limits.commission_bps) / 10_000,
                )
                .map_err(|_| LedgerApiError::Invalid("commission"))?;
                let to_lender = held - commission.min(held);
                let reward = line.reward();
                self.ledger.transfer(
                    format!("release/{key}"),
                    reward,
                    Account::User(line.lender),
                    to_lender,
                    "JOB-R22 release",
                )?;
                self.ledger.transfer(
                    format!("commission/{key}"),
                    reward,
                    Account::Commission,
                    held - to_lender,
                    "JOB-R22 commission",
                )?;
                return Ok(LedgerOutcome::Released {
                    to_lender,
                    commission: held - to_lender,
                });
            }
            LedgerOp::ContestReward {
                line,
                key,
                pool_part,
            } => {
                let e = self.escrow(line.job)?;
                let (owner, pool) = (e.owner, e.pool);
                let held = self.ledger.available(line.reward());
                if held == 0 {
                    return Err(LedgerApiError::Invalid("nothing held"));
                }
                if pool_part > held {
                    return Err(LedgerApiError::Invalid("pool share above the held reward"));
                }
                let reward = line.reward();
                self.ledger.transfer(
                    format!("contest/{key}/pool"),
                    reward,
                    Account::PoolReserve(pool),
                    pool_part,
                    "JOB-R22 contest (pool share)",
                )?;
                self.ledger.transfer(
                    format!("contest/{key}"),
                    reward,
                    Account::User(owner),
                    held - pool_part,
                    "JOB-R22 contest",
                )?;
                return Ok(LedgerOutcome::Contested {
                    to_pool: pool_part,
                    to_owner: held - pool_part,
                });
            }
            LedgerOp::SettleJob { job, pool_unspent } => {
                let e = self.live_escrow(job)?;
                let (owner, pool) = (e.owner, e.pool);
                let rec = self.ledger.available(Account::EscrowRecovery(job));
                if pool_unspent > rec {
                    return Err(LedgerApiError::Invalid(
                        "pool share exceeds recovery escrow",
                    ));
                }
                self.ledger.transfer(
                    format!("settle/{job}/recovery-pool"),
                    Account::EscrowRecovery(job),
                    Account::PoolReserve(pool),
                    pool_unspent,
                    "JOB-S12 return to pool",
                )?;
                for (acct, tag) in [
                    (Account::EscrowWork(job), "work"),
                    (Account::EscrowRecovery(job), "recovery"),
                    (Account::OutputHold(job), "hold"),
                ] {
                    let amount = self.ledger.available(acct);
                    self.ledger.transfer(
                        format!("settle/{job}/{tag}"),
                        acct,
                        Account::User(owner),
                        amount,
                        "JOB-S12 return",
                    )?;
                }
                if let Some(e) = self.escrows.get_mut(&job) {
                    e.settled = true;
                }
            }
        }
        Ok(LedgerOutcome::Done)
    }
}
