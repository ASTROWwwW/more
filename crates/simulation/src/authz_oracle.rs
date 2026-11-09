//! TEST-P29 oracle: who may send what, restated here from the permission matrix
//! (`docs/SECURITY_ARCHITECTURE.md`, section 3) without calling the domain's authorization code.
//!
//! Hypothesis: the caller's identity is already authenticated (`AuthContext`). Scope: every
//! command, every principal, every resource the command names.

use gpu_domain::*;

fn is(ctx: &AuthContext, roles: &[ServiceRole]) -> bool {
    ctx.service_role().is_some_and(|r| roles.contains(&r))
}

fn acct(ctx: &AuthContext) -> Option<AccountId> {
    ctx.account_no().map(AccountId)
}

fn admin(c: &Coordinator, ctx: &AuthContext, pool: PoolId) -> bool {
    is(ctx, &[ServiceRole::PlatformAdmin])
        || c.pools
            .get(&pool)
            .zip(acct(ctx))
            .is_some_and(|(p, a)| p.admins.contains(&a))
}

/// True when the matrix allows `ctx` to send `cmd` in state `c`. When the resource does not exist,
/// the answer does not matter: the command cannot succeed.
pub fn allowed(c: &Coordinator, ctx: &AuthContext, cmd: &Command) -> bool {
    use Command::*;
    use ServiceRole as S;
    let me = acct(ctx);
    let job = |id: &JobId| c.jobs.get(id);
    let borrower = |id: &JobId| job(id).is_some_and(|j| Some(j.borrower) == me);
    let att = |id: &JobId, n: u32| job(id).and_then(|j| j.attempts.get(&n));
    let drivers = [S::Scheduler, S::Reconciler];
    match cmd {
        Tick { .. } => is(ctx, &[S::Clock]),
        Issue { .. } => is(ctx, &[S::Treasury]),
        CreatePool { .. } => is(ctx, &[S::PlatformAdmin]),
        SetRights { pool, .. } | RegisterModel { pool, .. } => admin(c, ctx, *pool),
        JoinPool { account, .. } => me == Some(*account),
        Submit {
            borrower: b, pool, ..
        } => {
            me == Some(*b)
                && c.pools
                    .get(pool)
                    .and_then(|p| p.members.get(b))
                    .is_some_and(|r| r.borrow)
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
        | Fail { .. } => is(ctx, &drivers),
        Reconcile => is(ctx, &[S::Reconciler]),
        Place { .. } => is(ctx, &[S::Scheduler]),
        Heartbeat { job: id, attempt }
        | AttemptReady {
            job: id, attempt, ..
        } => att(id, *attempt).is_none_or(|a| me.is_some_and(|m| a.lenders.contains(&m))),
        PlacementFailed { job: id } => {
            is(ctx, &drivers)
                || job(id)
                    .and_then(|j| j.attempts.get(&j.attempt))
                    .is_none_or(|a| me.is_some_and(|m| a.lenders.contains(&m)))
        }
        Produce {
            job: id, attempt, ..
        } => att(id, *attempt).is_none_or(|a| me.is_some() && a.lenders.last().copied() == me),
        Finish { job: id, .. } => {
            is(ctx, &[S::Scheduler])
                || job(id)
                    .and_then(|j| j.attempts.get(&j.attempt))
                    .is_none_or(|a| me.is_some() && a.lenders.last().copied() == me)
        }
        Ack { job: id, .. }
        | ConfirmDelivery { job: id, .. }
        | ClientHeartbeat { job: id }
        | Resume { job: id, .. } => borrower(id),
        Cancel { job: id, .. } => is(ctx, &[S::Reconciler]) || borrower(id),
        Pause {
            job: id, reason, ..
        } => match reason {
            PauseReason::Requested => borrower(id),
            PauseReason::ClientSilent => is(ctx, &[S::Reconciler]),
            PauseReason::Preempted | PauseReason::LowEscrow => is(ctx, &[S::Scheduler]),
        },
        Deliver { witness, .. } | WitnessCommit { witness, .. } => me == Some(*witness),
        WitnessLost { job: id, attempt } | PurgeBuffer { job: id, attempt } => {
            is(ctx, &[S::Reconciler]) || att(id, *attempt).is_none_or(|a| me == Some(a.witness))
        }
        CommitReceipts {
            job: id,
            attempt,
            lender,
            ..
        } => match att(id, *attempt) {
            None => true,
            Some(a) => match a.lenders.iter().position(|l| l == lender) {
                None => true,
                Some(k) if k + 1 < a.lenders.len() => me == Some(a.lenders[k + 1]),
                Some(_) => me == Some(a.witness),
            },
        },
        Claim { lender, .. } | SupplementEvidence { lender, .. } => me == Some(*lender),
        Arbitrate { slice, pay, .. } => {
            (!*pay && is(ctx, &[S::Reconciler]))
                || job(&slice.job).is_some_and(|j| admin(c, ctx, j.pool))
        }
        FundRecovery { job: id, .. } => job(id).is_some_and(|j| admin(c, ctx, j.pool)),
        ReleaseReward { lender, .. } => is(ctx, &[S::Reconciler]) || me == Some(*lender),
        ContestReward { slice, .. } => {
            borrower(&slice.job) || job(&slice.job).is_some_and(|j| admin(c, ctx, j.pool))
        }
    }
}
