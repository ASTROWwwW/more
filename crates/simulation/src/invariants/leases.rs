//! Per-node leases (TEST-P24, TEST-P31; JOB-R31, JOB-R38, JOB-R39), recomputed from the attempt's
//! leases without calling the domain.

use super::*;

/// Some node of `a` has an expired lease at `now`.
fn any_expired(a: &Attempt, now: Time) -> bool {
    now >= a.witness_expires_at || a.leases.iter().any(|l| now >= l.expires_at)
}

fn att_of(c: &Coordinator, job: JobId, n: u32) -> Option<&Attempt> {
    c.jobs().get(&job).and_then(|j| j.attempts.get(&n))
}

/// State (lenders only) and expiry of one lease.
type LeaseView = (Option<LeaseState>, Time);

/// Lease of `who` (a lender, or the witness) on `a`.
fn lease_of(a: &Attempt, who: AccountId) -> Option<LeaseView> {
    match a.lenders.iter().position(|l| *l == who) {
        Some(k) => a.leases.get(k).map(|l| (Some(l.state), l.expires_at)),
        None if a.witness == who => Some((None, a.witness_expires_at)),
        None => None,
    }
}

/// Every lease of the job's attempts, keyed by (attempt, node).
fn all_leases(c: &Coordinator, job: JobId) -> Vec<((u32, AccountId), LeaseView)> {
    let Some(j) = c.jobs().get(&job) else {
        return vec![];
    };
    let mut v = Vec::new();
    for (n, a) in &j.attempts {
        for (l, lease) in a.lenders.iter().zip(&a.leases) {
            v.push(((*n, *l), (Some(lease.state), lease.expires_at)));
        }
        v.push(((*n, a.witness), (None, a.witness_expires_at)));
    }
    v
}

/// TEST-P24: no lease runs past one TTL from now.
pub(super) fn state(c: &Coordinator, out: &mut Vec<Violation>) {
    let limit = c.now() + c.config().lease_ttl;
    for j in c.jobs().values() {
        let Some(a) = j.current().filter(|a| a.revoked_at.is_none()) else {
            continue;
        };
        if a.leases.len() != a.lenders.len() {
            out.push(v("TEST-P31", format!("{:?}: one lease per stage", j.id)));
        }
        if a.witness_expires_at > limit || a.leases.iter().any(|l| l.expires_at > limit) {
            out.push(v(
                "TEST-P24",
                format!("{:?} attempt {}: lease beyond now + ttl", j.id, a.no),
            ));
        }
        // JOB-R38: an attempt runs only once every stage is ready.
        let all_ready = a.leases.iter().all(|l| l.state == LeaseState::Ready);
        if a.ready != all_ready {
            out.push(v(
                "TEST-P31",
                format!(
                    "{:?} attempt {}: ready = {} but leases {:?}",
                    j.id, a.no, a.ready, a.leases
                ),
            ));
        }
    }
}

/// TEST-P24 and TEST-P31 for one step.
pub(super) fn step(
    before: &Coordinator,
    cmd: &Command,
    result: &Result<Outcome, DomainError>,
    after: &Coordinator,
) -> Vec<Violation> {
    use Command::*;
    let mut out = Vec::new();
    let applied = matches!(result, Ok(Outcome::Applied));
    if applied {
        // TEST-P24: the pipeline needs every node, so production, acks and live attestations need
        // every lease; a node's own lease must be valid for what it says about itself.
        let expired = match cmd {
            Produce { job, attempt, .. } | Ack { job, attempt, .. } => {
                attempt_any_expired(before, *job, *attempt)
            }
            Deliver { job, attempt, .. } => {
                let late = att_of(before, *job, *attempt).is_some_and(|a| a.revoked_at.is_some());
                !late && attempt_any_expired(before, *job, *attempt)
            }
            AcceptLease {
                job,
                attempt: n,
                lender,
                ..
            }
            | LeaseLoaded {
                job,
                attempt: n,
                lender,
                ..
            }
            | AttemptReady {
                job,
                attempt: n,
                lender,
                ..
            }
            | Heartbeat {
                job,
                attempt: n,
                lender,
            }
            | WitnessHeartbeat {
                job,
                attempt: n,
                witness: lender,
            } => att_of(before, *job, *n)
                .and_then(|a| lease_of(a, *lender))
                .is_none_or(|(_, exp)| before.now() >= exp),
            _ => false,
        };
        if expired {
            out.push(v(
                "TEST-P24",
                format!("{cmd:?} accepted under an expired lease"),
            ));
        }
    }
    // TEST-P31: a node changes its own lease only, one state forward at a time; nothing else
    // touches an existing lease, except the renewal of the sender's own expiry.
    let own: Option<(JobId, u32, AccountId)> = match cmd {
        AcceptLease {
            job,
            attempt,
            lender,
            ..
        }
        | LeaseLoaded {
            job,
            attempt,
            lender,
            ..
        }
        | AttemptReady {
            job,
            attempt,
            lender,
            ..
        }
        | Heartbeat {
            job,
            attempt,
            lender,
        }
        | WitnessHeartbeat {
            job,
            attempt,
            witness: lender,
        } => Some((*job, *attempt, *lender)),
        _ => None,
    };
    for job in before.jobs().keys() {
        let old: std::collections::BTreeMap<_, _> = all_leases(before, *job).into_iter().collect();
        for (key, (state, exp)) in all_leases(after, *job) {
            let Some((ostate, oexp)) = old.get(&key).copied() else {
                continue;
            };
            let mine = own.is_some_and(|(j, n, who)| j == *job && (n, who) == key);
            let forward = match (ostate, state) {
                (Some(a), Some(b)) => a == b || (mine && b as u8 == a as u8 + 1),
                _ => true,
            };
            if !forward {
                out.push(v(
                    "TEST-P31",
                    format!("{cmd:?}: lease {key:?} of {job:?} went {ostate:?} -> {state:?}"),
                ));
            }
            let renewal = mine && matches!(cmd, Heartbeat { .. } | WitnessHeartbeat { .. });
            if exp != oexp && !renewal {
                out.push(v(
                    "TEST-P31",
                    format!("{cmd:?}: lease {key:?} of {job:?} expiry changed by someone else"),
                ));
            }
        }
    }
    // TEST-P31: a job enters `running` only with every lease of its attempt ready.
    for j in after.jobs().values() {
        let was = before.jobs().get(&j.id).map(|b| b.exec);
        if j.exec == ExecStatus::Running && was == Some(ExecStatus::Placing) {
            let ready = j
                .current()
                .is_some_and(|a| a.leases.iter().all(|l| l.state == LeaseState::Ready));
            if !ready {
                out.push(v(
                    "TEST-P31",
                    format!("{cmd:?} started {:?} with a lease not ready", j.id),
                ));
            }
        }
    }
    // TEST-P24: after a reconciliation that ran, no live attempt keeps an expired lease.
    if matches!(cmd, Reconcile) && result.is_ok() {
        for j in after.jobs().values() {
            if matches!(j.exec, ExecStatus::Running | ExecStatus::Placing) {
                if let Some(a) = j.current().filter(|a| a.revoked_at.is_none()) {
                    if any_expired(a, after.now()) {
                        out.push(v(
                            "TEST-P24",
                            format!("{:?}: expired lease survived reconciliation", j.id),
                        ));
                    }
                }
            }
        }
    }
    out
}

fn attempt_any_expired(c: &Coordinator, job: JobId, n: u32) -> bool {
    att_of(c, job, n).is_none_or(|a| any_expired(a, c.now()))
}
