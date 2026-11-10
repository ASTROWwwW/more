//! Per-command, per-resource authorization (SEC-001, SEC-003). Runs before any mutation: a command
//! refused here leaves the state untouched. The matrix is documented in
//! `docs/SECURITY_ARCHITECTURE.md`, section 3.
//!
//! Identity is not decided here. The caller's [`AuthContext`] was built by `more-identity` from a
//! verified signature or a service credential; this module only decides what that identity may do
//! with the resource the command names (account, pool, job, attempt, slice, lease).

use more_identity::{AuthContext, ServiceRole};

use crate::command::Command;
use crate::coordinator::Coordinator;
use crate::error::DomainError;
use crate::ids::*;
use crate::model::{Attempt, Job, PauseReason};

type R<T = ()> = Result<T, DomainError>;

/// Who is calling, from the domain's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caller {
    Account(AccountId),
    Service(ServiceRole),
}

fn caller(ctx: &AuthContext) -> Caller {
    match (ctx.account_no(), ctx.service_role()) {
        (Some(a), _) => Caller::Account(AccountId(a)),
        (None, Some(r)) => Caller::Service(r),
        // AuthContext always holds exactly one principal.
        (None, None) => Caller::Service(ServiceRole::Auditor),
    }
}

fn deny(why: &'static str) -> DomainError {
    DomainError::Unauthorized(why)
}

fn service(c: Caller, allowed: &[ServiceRole], why: &'static str) -> R {
    match c {
        Caller::Service(r) if allowed.contains(&r) => Ok(()),
        _ => Err(deny(why)),
    }
}

fn account(c: Caller) -> Option<AccountId> {
    match c {
        Caller::Account(a) => Some(a),
        Caller::Service(_) => None,
    }
}

const DRIVERS: &[ServiceRole] = &[ServiceRole::Scheduler, ServiceRole::Reconciler];

/// The borrower of `job`.
fn borrower_of(c: Caller, job: &Job) -> R {
    if account(c) == Some(job.borrower) {
        Ok(())
    } else {
        Err(deny("only the job's borrower"))
    }
}

/// A lender of `attempt`. A missing attempt is left to the transition, which reports it.
fn lender_of(c: Caller, job: &Job, attempt: u32) -> R {
    let Some(a) = job.attempts.get(&attempt) else {
        return Ok(());
    };
    match account(c) {
        Some(acc) if a.lenders.contains(&acc) => Ok(()),
        _ => Err(deny("only a lender of the attempt")),
    }
}

fn output_node_of(c: Caller, a: Option<&Attempt>) -> R {
    let Some(a) = a else { return Ok(()) };
    match account(c) {
        Some(acc) if a.output_node() == Some(acc) => Ok(()),
        _ => Err(deny("only the attempt's output node")),
    }
}

fn witness_of(c: Caller, job: &Job, attempt: u32) -> R {
    let Some(a) = job.attempts.get(&attempt) else {
        return Ok(());
    };
    match account(c) {
        Some(acc) if acc == a.witness => Ok(()),
        _ => Err(deny("only the attempt's witness")),
    }
}

fn pool_admin(c: &Coordinator, who: Caller, pool: PoolId) -> R {
    let p = c.registry().pool(pool)?;
    match who {
        Caller::Service(ServiceRole::PlatformAdmin) => Ok(()),
        Caller::Account(a) if p.is_admin(a) => Ok(()),
        _ => Err(deny("only an admin of the pool")),
    }
}

/// Checks that `ctx` may send `cmd`. Never mutates anything.
pub(crate) fn authorize(c: &Coordinator, ctx: &AuthContext, cmd: &Command) -> R {
    use Command::*;
    let who = caller(ctx);
    let job = |id: &JobId| c.job(*id);
    match cmd {
        Tick { .. } => service(who, &[ServiceRole::Clock], "only the clock"),
        Issue { .. } => service(who, &[ServiceRole::Treasury], "only the treasury issues"),
        CreatePool { .. } => service(
            who,
            &[ServiceRole::PlatformAdmin],
            "only the platform admin",
        ),
        SetRights { pool, .. } | RegisterModel { pool, .. } => pool_admin(c, who, *pool),
        JoinPool { account: acc, .. } => match account(who) {
            Some(a) if a == *acc => Ok(()),
            _ => Err(deny("an account joins for itself only")),
        },
        Submit { borrower, pool, .. } => {
            if account(who) != Some(*borrower) {
                return Err(deny("a job is submitted by its borrower"));
            }
            let p = c.registry().pool(*pool)?;
            if !p.rights(*borrower).borrow {
                return Err(deny("no borrow right in this pool"));
            }
            Ok(())
        }
        Reserve { .. }
        | RejectQueued { .. }
        | CloseSlice { .. }
        | Evaluate { .. }
        | NodeLost { .. }
        | RecoveryTimeout { .. }
        | CompleteSettling { .. }
        | Settle { .. }
        | ExpirePause { .. }
        | ExpireDeliveryWindow { .. }
        | ResolveContests { .. }
        | Fail { .. } => service(who, DRIVERS, "scheduler or reconciler only"),
        // Reconciliation runs every due transition under its own identity; a scheduler running it
        // would be refused some of them and leave them due.
        Reconcile => service(who, &[ServiceRole::Reconciler], "only the reconciler"),
        Place { .. } => service(who, &[ServiceRole::Scheduler], "only the scheduler places"),
        // JOB-R38, JOB-R39: a lender speaks for its own lease only.
        AcceptLease {
            job: id,
            attempt,
            lender,
            ..
        }
        | LeaseLoaded {
            job: id,
            attempt,
            lender,
            ..
        }
        | AttemptReady {
            job: id,
            attempt,
            lender,
            ..
        }
        | Heartbeat {
            job: id,
            attempt,
            lender,
        } => {
            if account(who) != Some(*lender) {
                return Err(deny("a lender speaks for its own lease only"));
            }
            lender_of(who, job(id)?, *attempt)
        }
        WitnessHeartbeat {
            job: id,
            attempt,
            witness,
        } => {
            if account(who) != Some(*witness) {
                return Err(deny("the witness renews its own lease only"));
            }
            witness_of(who, job(id)?, *attempt)
        }
        // The producer presents a receipt about its own output; the recipient's signature inside
        // is checked by the transition and the ledger.
        PresentReceipt { lender, .. } => {
            if account(who) == Some(*lender) {
                Ok(())
            } else {
                Err(deny("a producer presents its own receipts only"))
            }
        }
        PlacementFailed { job: id } => {
            if service(who, DRIVERS, "").is_ok() {
                return Ok(());
            }
            let j = job(id)?;
            lender_of(who, j, j.attempt)
        }
        Produce {
            job: id, attempt, ..
        } => output_node_of(who, job(id)?.attempts.get(attempt)),
        Finish { job: id, .. } => {
            if service(who, &[ServiceRole::Scheduler], "").is_ok() {
                return Ok(());
            }
            output_node_of(who, job(id)?.current())
        }
        Ack { job: id, .. }
        | ConfirmDelivery { job: id, .. }
        | ClientHeartbeat { job: id }
        | Resume { job: id, .. } => borrower_of(who, job(id)?),
        Cancel { job: id, .. } => {
            if service(who, &[ServiceRole::Reconciler], "").is_ok() {
                return Ok(());
            }
            borrower_of(who, job(id)?)
        }
        Pause {
            job: id, reason, ..
        } => match reason {
            PauseReason::Requested => borrower_of(who, job(id)?),
            PauseReason::ClientSilent => service(
                who,
                &[ServiceRole::Reconciler],
                "silence is declared by reconciliation",
            ),
            PauseReason::Preempted | PauseReason::LowEscrow => service(
                who,
                &[ServiceRole::Scheduler],
                "only the scheduler preempts",
            ),
        },
        // The witness signs for itself; whether it is the assigned one is a proof question
        // (JOB-R26, `INADMISSIBLE_PROOF`), checked by the transition.
        Deliver { witness, .. } | WitnessCommit { witness, .. } => {
            if account(who) == Some(*witness) {
                Ok(())
            } else {
                Err(deny("an attestation is signed by its witness"))
            }
        }
        WitnessLost { job: id, attempt } | PurgeBuffer { job: id, attempt } => {
            if service(who, &[ServiceRole::Reconciler], "").is_ok() {
                return Ok(());
            }
            witness_of(who, job(id)?, *attempt)
        }
        CommitReceipts {
            job: id,
            attempt,
            lender,
            ..
        }
        | CorroborateRestore {
            job: id,
            attempt,
            lender,
            ..
        } => {
            let j = job(id)?;
            let Some(a) = j.attempts.get(attempt) else {
                return Ok(());
            };
            // SEC-004, JOB-R18: only the recipient of the producer's output commits its receipts
            // or corroborates its restoration; the producer never does it for itself. An unknown producer is refused by the transition.
            let Some(stage) = a.stage_of(*lender) else {
                return Ok(());
            };
            match (account(who), a.recipient_of(stage)) {
                (Some(acc), Some(rcpt)) if acc == rcpt => Ok(()),
                _ => Err(deny("only the recipient of the producer's output")),
            }
        }
        Claim { lender, .. } | SupplementEvidence { lender, .. } => {
            if account(who) == Some(*lender) {
                Ok(())
            } else {
                Err(deny("a lender claims for itself only"))
            }
        }
        Arbitrate { slice, pay, .. } => {
            // Default ruling (refund) is applied by reconciliation; paying a disputed line is an
            // economic decision of the pool.
            if !*pay && service(who, &[ServiceRole::Reconciler], "").is_ok() {
                return Ok(());
            }
            pool_admin(c, who, job(&slice.job)?.pool)
        }
        FundRecovery { job: id, .. } => pool_admin(c, who, job(id)?.pool),
        ReleaseReward { lender, .. } => {
            if service(who, &[ServiceRole::Reconciler], "").is_ok() || account(who) == Some(*lender)
            {
                Ok(())
            } else {
                Err(deny("released by reconciliation or by the lender"))
            }
        }
        ContestReward { slice, .. } => {
            let j = job(&slice.job)?;
            if borrower_of(who, j).is_ok() {
                return Ok(());
            }
            pool_admin(c, who, j.pool)
        }
    }
}
