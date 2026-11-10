//! Invariant checker (spec section 9). `check_state` holds in every reachable state; `check_step`
//! checks one transition (before, command, after). Each violation carries its TEST-Pxx id. The
//! checker recomputes what it can from the ledger and the audit log, without calling the domain.

use gpu_domain::*;

mod accounting;
mod delivery;
mod fairness;
mod leases;
mod lifecycle;
mod payments;
mod proofs;
mod security;

pub use fairness::check_fairness;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub property: &'static str,
    pub detail: String,
}

pub(super) fn v(property: &'static str, detail: impl Into<String>) -> Violation {
    Violation {
        property,
        detail: detail.into(),
    }
}

pub(super) fn line_acct(s: SliceId, lender: AccountId) -> Account {
    Account::SliceLine {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

pub(super) fn pending_acct(s: SliceId, lender: AccountId) -> Account {
    Account::PendingReward {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

/// JOB-R12 (a) recomputed without calling the domain: the commitment must come before the attempt's
/// revocation or the slice's closure, in log order.
pub(super) fn committed_before_independent(
    c: &Coordinator,
    slice: SliceId,
    lender: AccountId,
    wt: WorkType,
    pos: u32,
) -> bool {
    let job = &c.jobs()[&slice.job];
    let attempt = &job.attempts[&slice.attempt];
    // No receipt is accepted after closure, so the bound is the earlier of revocation and closure.
    let closed = c.slices()[&slice].closed_seq.unwrap_or(c.seq());
    let cutoff = attempt.revoked_seq.map_or(closed, |r| r.min(closed));
    c.commit_log()
        .get(&(slice.job, slice.attempt, lender, wt))
        .is_some_and(|log| {
            log.iter()
                .any(|(upto, _, seq)| *upto > pos && *seq < cutoff)
        })
}

/// FNV-1a recomputed here, without calling the domain.
pub(super) fn fnv_words(words: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in words {
        for b in w.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// Expected digest of frames `0..upto` (JOB-R34), recomputed independently.
pub(super) fn digest_independent(c: &Coordinator, job: JobId, wt: WorkType, upto: u32) -> u64 {
    let Some(j) = c.jobs().get(&job) else {
        return 0;
    };
    let mut h = fnv_words(&[
        u64::from(job.0),
        j.stream,
        u64::from(j.model.0),
        wt.idx() as u64,
    ]);
    for pos in 0..upto {
        let o = OutputId { job, wt, pos };
        let gen = match c.delivery().charges().get(&o) {
            Some(ch) => ch.gen,
            None => c.delivery().charge_gens().get(&o).copied().unwrap_or(0),
        };
        h = fnv_words(&[h, u64::from(pos), u64::from(gen)]);
    }
    h
}

pub fn check_state(c: &Coordinator, auditor: &ServiceCredential) -> Vec<Violation> {
    let mut out = Vec::new();
    let Ok(ledger) = c.audit_ledger(auditor) else {
        return vec![v("TEST-P02", "the auditor cannot read the ledger")];
    };
    accounting::accounts(c, ledger, &mut out);
    lifecycle::transitions(c, &mut out);
    delivery::charges(c, &mut out);
    payments::payments(c, ledger, &mut out);
    lifecycle::attempts(c, &mut out);
    leases::state(c, &mut out);
    proofs::state(c, ledger, auditor, &mut out);
    proofs::recovery(c, &mut out);
    out
}

/// Properties of one step: `before`, the command, its result and `after`.
pub fn check_step(
    before: &Coordinator,
    ctx: &AuthContext,
    cmd: &Command,
    result: &Result<Outcome, DomainError>,
    after: &Coordinator,
    auditor: &ServiceCredential,
) -> Vec<Violation> {
    let mut out = Vec::new();
    // TEST-P29: an accepted command came from a principal the matrix allows; an allowed principal
    // is never refused as unauthorized. Combined with TEST-P16 (a refusal changes nothing), an
    // unauthorized sender never changes state, credits, positions, leases or the audit log.
    let allowed = security::allowed(before, ctx, cmd);
    match result {
        Ok(_) if !allowed => out.push(v(
            "TEST-P29",
            format!("{cmd:?} accepted from {:?}", ctx.principal()),
        )),
        Err(DomainError::Unauthorized(why)) if allowed => out.push(v(
            "TEST-P29",
            format!("{cmd:?} from {:?} refused: {why}", ctx.principal()),
        )),
        _ => {}
    }
    match result {
        // JOB-R01: a rejection leaves no trace.
        Err(e) => {
            if before != after {
                out.push(v(
                    "TEST-P16",
                    format!("{cmd:?} refused ({e:?}) but state changed"),
                ));
            }
            if let DomainError::Internal(msg) = e {
                out.push(v("TEST-P16", format!("internal error on {cmd:?}: {msg}")));
            }
        }
        Ok(Outcome::AlreadyApplied) if !matches!(cmd, Command::Reconcile) => {
            if before != after {
                out.push(v(
                    "TEST-P16",
                    format!("{cmd:?} reported idempotent but state changed"),
                ));
            }
        }
        Ok(_) => {}
    }
    out.extend(delivery::check_charge_basis(before, cmd, after));
    out.extend(leases::step(before, cmd, result, after));
    out.extend(proofs::receipts_step(before, after));
    out.extend(proofs::finality_step(before, cmd, after, auditor));
    // TEST-P04: production and acks only on the live attempt.
    if result.is_ok() {
        if let Command::Produce { job, attempt, .. } | Command::Ack { job, attempt, .. } = cmd {
            if let Ok(j) = before.job(*job) {
                let live = j.attempt == *attempt
                    && j.current()
                        .is_some_and(|a| a.revoked_at.is_none() && a.ready)
                    && j.exec == ExecStatus::Running;
                if !live && before != after {
                    out.push(v(
                        "TEST-P04",
                        format!("{cmd:?} accepted on a non-live attempt"),
                    ));
                }
            }
        }
    }
    for (id, ja) in after.jobs() {
        if let Some(jb) = before.jobs().get(id) {
            // execution_intent is monotonic (JOB-T04, JOB-T12).
            if jb.intent == Intent::Resume && ja.intent == Intent::Initial {
                out.push(v(
                    "TEST-P07",
                    format!("{id:?}: execution_intent went back to initial on {cmd:?}"),
                ));
            }
            // TEST-P05: validated positions never go back.
            for t in 0..3 {
                if ja.validated[t] < jb.validated[t] {
                    out.push(v(
                        "TEST-P05",
                        format!("{id:?}: validated decreased on {cmd:?}"),
                    ));
                }
            }
        }
    }
    // The ledger is append-only (LEDGER-002).
    let (Ok(lb), Ok(la)) = (before.audit_ledger(auditor), after.audit_ledger(auditor)) else {
        out.push(v("TEST-P02", "the auditor cannot read the ledger"));
        return out;
    };
    let n = lb.entries().len();
    if la.entries().len() < n || la.entries()[..n] != lb.entries()[..] {
        out.push(v(
            "TEST-P02",
            format!("ledger history rewritten by {cmd:?}"),
        ));
    }
    out
}
