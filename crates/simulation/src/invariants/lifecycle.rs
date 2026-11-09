//! Lifecycle properties: allowed transitions, live attempts, leases, restarts (TEST-P01, P07, P09,
//! P24, P25).

use super::*;

/// TEST-P01.
pub(super) fn transitions(c: &Coordinator, out: &mut Vec<Violation>) {
    // TEST-P01: only transitions from the table were applied.
    for e in c.audit_log() {
        match e {
            AuditEvent::Exec {
                from: Some(f),
                to,
                rule,
                job,
            } if !ExecStatus::allowed(*f, *to) => {
                out.push(v("TEST-P01", format!("{job:?} {f:?}->{to:?} ({rule})")));
            }
            AuditEvent::SliceState {
                from: Some(f),
                to,
                slice,
                ..
            } if !SliceStatus::allowed(*f, *to) => {
                out.push(v("TEST-P01", format!("{slice:?} {f:?}->{to:?}")));
            }
            AuditEvent::Exec {
                from: Some(ExecStatus::Settling),
                to,
                job,
                ..
            } if *to != ExecStatus::Completed => {
                out.push(v("TEST-P11", format!("{job:?} settling -> {to:?}")));
            }
            _ => {}
        }
    }
}

/// TEST-P09, P24, P25, P07.
pub(super) fn attempts(c: &Coordinator, out: &mut Vec<Violation>) {
    // TEST-P09: flow budget for the live attempt.
    for j in c.jobs().values() {
        if let Some(a) = j.current() {
            for wt in WorkType::ALL {
                let t = wt.idx();
                if a.produced[t] < j.validated[t] {
                    out.push(v(
                        "TEST-P09",
                        format!("{:?} attempt {}: produced < validated", j.id, a.no),
                    ));
                } else if a.revoked_at.is_none() && a.produced[t] < j.delivered[t] {
                    out.push(v(
                        "TEST-P09",
                        format!(
                            "{:?} attempt {}: live production behind delivered",
                            j.id, a.no
                        ),
                    ));
                } else if a.revoked_at.is_none()
                    && a.produced[t] - j.validated[t] > c.config().flow_budget[t]
                {
                    out.push(v(
                        "TEST-P09",
                        format!(
                            "{:?} {wt:?}: window {} > K",
                            j.id,
                            a.produced[t] - j.validated[t]
                        ),
                    ));
                }
            }
        }
    }

    // TEST-P25: a live attempt is built on outputs that exist; its start never exceeds delivered
    // positions (a rewind below it must revoke it, JOB-R29).
    for j in c.jobs().values() {
        let Some(a) = j.current() else { continue };
        if a.revoked_at.is_some() {
            continue;
        }
        let start = c.audit_log().iter().rev().find_map(|e| match e {
            AuditEvent::AttemptStarted {
                job,
                attempt,
                restored,
                ..
            } if *job == j.id && *attempt == a.no => Some(*restored),
            _ => None,
        });
        // While placing, production still equals the start point.
        let start = start.unwrap_or(a.produced);
        if (0..3).any(|t| start[t] > j.delivered[t]) {
            out.push(v(
                "TEST-P25",
                format!(
                    "{:?} attempt {} built from {start:?} beyond delivered {:?}",
                    j.id, a.no, j.delivered
                ),
            ));
        }
    }

    // TEST-P24: a lease is never extended beyond one TTL.
    for j in c.jobs().values() {
        if let Some(a) = j.current() {
            if a.revoked_at.is_none() && a.lease_expires_at > c.now() + c.config().lease_ttl {
                out.push(v(
                    "TEST-P24",
                    format!("{:?} attempt {}: lease beyond now + ttl", j.id, a.no),
                ));
            }
        }
    }

    // TEST-P07, TEST-P25: every (re)start begins exactly at the last delivered position; delivered
    // output is replayed, never regenerated.
    for e in c.audit_log() {
        if let AuditEvent::AttemptStarted {
            job,
            attempt,
            restored,
            validated,
            delivered,
            ..
        } = e
        {
            if restored != delivered {
                out.push(v("TEST-P07", format!("{job:?} attempt {attempt} started at {restored:?}, delivered {delivered:?}")));
            }
            if (0..3).any(|t| validated[t] > delivered[t]) {
                out.push(v(
                    "TEST-P07",
                    format!("{job:?} attempt {attempt}: validated > delivered at start"),
                ));
            }
        }
    }
}
