//! What the Ledger holds against the orchestrator (TEST-P30; LEDGER-013 to LEDGER-016): every
//! reserve has a provenance and a lessee who signed, every paid contribution a recipient's receipt,
//! every recovery a lender that signed ready, and a settled job leaves nothing behind. Recovery is
//! paid segment by segment, on corroborations recorded before the revocation (TEST-P32, TEST-P34).

use gpu_ledger::{Escrow, ItemId, ItemState};

use super::*;

fn p30(out: &mut Vec<Violation>, detail: String) {
    out.push(v("TEST-P30", detail));
}

/// TEST-P30, on the Ledger's own records.
pub(super) fn state(
    c: &Coordinator,
    ledger: &Ledger,
    auditor: &ServiceCredential,
    out: &mut Vec<Violation>,
) {
    let Ok(escrows) = c.ledger_service().audit_escrows(auditor) else {
        return p30(out, "the auditor cannot read the job records".into());
    };
    for (job, e) in escrows {
        items(*job, e, out);
        let line_total: i128 = ledger
            .accounts()
            .filter(|(a, _)| matches!(a, Account::SliceLine { job: j, .. } if j == job))
            .map(|(_, b)| *b)
            .sum();
        let reserved: i128 = e
            .items
            .values()
            .filter(|i| i.state == ItemState::Reserved)
            .map(|i| i128::from(i.amount))
            .sum();
        if line_total != reserved {
            p30(
                out,
                format!("job {job}: lines hold {line_total}, reserved items {reserved}"),
            );
        }
        if e.recovery_paid_pool > e.pool_funded || e.recovery_paid_owner > e.owner_recovery {
            p30(
                out,
                format!("job {job}: recovery paid beyond what each payer put in"),
            );
        }
        if e.settled {
            for a in [
                Account::EscrowWork(*job),
                Account::EscrowRecovery(*job),
                Account::OutputHold(*job),
            ] {
                if ledger.balance(a) != 0 {
                    p30(
                        out,
                        format!("job {job} settled with {a:?} = {}", ledger.balance(a)),
                    );
                }
            }
            // The pool got back exactly what it relayed and the Ledger did not pay out.
            let back: Amount = ledger
                .entries()
                .iter()
                .filter(|en| en.key == format!("settle/{job}/recovery-pool"))
                .map(|en| en.amount)
                .sum();
            if e.pool_funded.checked_sub(e.recovery_paid_pool) != Some(back) {
                p30(
                    out,
                    format!(
                        "job {job}: pool relayed {}, paid out {}, got back {back}",
                        e.pool_funded, e.recovery_paid_pool
                    ),
                );
            }
        }
        // The coordinator and the Ledger agree on who paid for recovery.
        if let Some(j) = c.jobs().get(&JobId(*job)) {
            if j.pool_recovery_funded != e.pool_funded
                || j.recovery_paid_pool != e.recovery_paid_pool
            {
                p30(
                    out,
                    format!("job {job}: coordinator and ledger disagree on the pool relay"),
                );
            }
        }
    }
}

fn items(job: u32, e: &Escrow, out: &mut Vec<Violation>) {
    for (id, it) in &e.items {
        if it.state == ItemState::Refunded {
            continue;
        }
        let Some(a) = e.attempts.get(&it.line.attempt) else {
            p30(out, format!("job {job}: {id:?} on an unregistered attempt"));
            continue;
        };
        let stage = a
            .assignment
            .lenders
            .iter()
            .position(|l| *l == it.line.lender);
        let Some(s) = stage.filter(|s| a.accepted[*s]) else {
            p30(
                out,
                format!("job {job}: {id:?} for a lender that never accepted the lease"),
            );
            continue;
        };
        match id {
            ItemId::Contribution { output, gen, stage } => {
                if *stage as usize != s {
                    p30(out, format!("job {job}: {id:?} on another stage's line"));
                }
                let price = e.terms.price[usize::from(output.wt)];
                let share = u128::from(price) * u128::from(a.assignment.layout[s])
                    / u128::from(e.terms.layers);
                if u128::from(it.amount) != share {
                    p30(
                        out,
                        format!(
                            "job {job}: {id:?} reserved {} for a share of {share}",
                            it.amount
                        ),
                    );
                }
                let covered = e
                    .receipts
                    .get(&(it.line.attempt, it.line.lender, output.wt))
                    .is_some_and(|r| r.keys().any(|u| *u > output.pos));
                if it.state == ItemState::Paid && !covered {
                    p30(
                        out,
                        format!("job {job}: {id:?} paid without the recipient's receipt"),
                    );
                }
                let charged = e.outputs.get(output).and_then(|o| o.charged);
                if it.state == ItemState::Reserved && charged != Some((it.line.attempt, *gen)) {
                    p30(
                        out,
                        format!("job {job}: {id:?} reserved on a charge not in force"),
                    );
                }
            }
            ItemId::Recovery { segment, .. } => {
                if !a.ready.iter().all(|r| *r) {
                    p30(
                        out,
                        format!(
                            "job {job}: {id:?} on an attempt not every lender signed ready for"
                        ),
                    );
                }
                // Paid only for a segment its recipient named, in a corroboration the ledger
                // recorded before the attempt's revocation.
                let proven = a.corroborates(s, *segment)
                    && a.corroborated[s]
                        .as_ref()
                        .is_some_and(|c| a.revoked.is_none_or(|r| c.seq < r));
                if it.state == ItemState::Paid && !proven {
                    p30(
                        out,
                        format!("job {job}: {id:?} paid without a corroborated restoration"),
                    );
                }
            }
        }
    }
}

/// TEST-P32 (JOB-R18), from the coordinator's log: recovery is paid only to a lender whose
/// restoration its recipient corroborated, by evaluation or by ruling alike.
pub(super) fn recovery(c: &Coordinator, out: &mut Vec<Violation>) {
    for e in c.audit_log() {
        let AuditEvent::ItemPaid {
            slice,
            lender,
            kind: ItemKind::Recovery(rid),
            ..
        } = e
        else {
            continue;
        };
        let corroborated = c
            .jobs()
            .get(&rid.job)
            .and_then(|j| j.attempts.get(&rid.attempt))
            .and_then(|a| {
                let s = a.lenders.iter().position(|l| l == lender)?;
                let c = a.leases[s].corroborated.as_ref()?;
                // CE-03: on record before the attempt's revocation, for this very segment.
                let before = a.revoked_seq.is_none_or(|r| c.seq < r);
                Some(a.ready && before && c.segments.contains(&rid.segment))
            })
            .unwrap_or(false);
        if !corroborated {
            out.push(v(
                "TEST-P32",
                format!("{slice:?}/{lender:?}: {rid:?} paid without a corroborated restoration"),
            ));
        }
    }
}

/// TEST-P23: an uncommitted contribution refunded for want of a receipt really had none.
pub(super) fn receipts_step(before: &Coordinator, after: &Coordinator) -> Vec<Violation> {
    let mut out = Vec::new();
    for e in after.audit_log().iter().skip(before.audit_log().len()) {
        let AuditEvent::ItemRefunded {
            slice,
            lender,
            kind: ItemKind::Contribution(cid),
            reason: RefundReason::EvidenceNotFound,
            ..
        } = e
        else {
            continue;
        };
        let uncommitted = after.slices()[slice].lines[lender]
            .items
            .iter()
            .any(|i| i.kind == ItemKind::Contribution(*cid) && i.evidence == Evidence::Uncommitted);
        let key = (slice.job, slice.attempt, *lender, cid.output.wt);
        let had = before
            .presented_receipts()
            .get(&key)
            .is_some_and(|u| *u > cid.output.pos)
            || before
                .commit_log()
                .get(&key)
                .is_some_and(|log| log.iter().any(|(u, _, _)| *u > cid.output.pos));
        if uncommitted && had {
            out.push(v(
                "TEST-P23",
                format!(
                    "{slice:?}/{lender:?}: {cid:?} refunded although its receipt was presented"
                ),
            ));
        }
    }
    out
}

/// TEST-P33 (LEDGER-018), on the ledger's records before and after one command: a recorded proof
/// is never replaced, a payment never undone, and a held payment leaves only through its own
/// cycle: released after its hold, contested before its limit, by the ledger's own clock.
pub(super) fn finality_step(
    before: &Coordinator,
    cmd: &Command,
    after: &Coordinator,
    auditor: &ServiceCredential,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let (Ok(old), Ok(new)) = (
        before.ledger_service().audit_escrows(auditor),
        after.ledger_service().audit_escrows(auditor),
    ) else {
        return out;
    };
    let now = before.ledger_service().now();
    let limits = before.ledger_service().limits();
    let mut p33 = |detail: String| out.push(v("TEST-P33", detail));
    for (job, a) in old {
        let Some(b) = new.get(job) else {
            p33(format!("job {job}: records dropped by {cmd:?}"));
            continue;
        };
        for (key, receipts) in &a.receipts {
            for (upto, digest) in receipts {
                if b.receipts.get(key).and_then(|r| r.get(upto)) != Some(digest) {
                    p33(format!(
                        "job {job}: receipt {key:?}/{upto} replaced by {cmd:?}"
                    ));
                }
            }
        }
        for (n, x) in &a.attempts {
            let Some(y) = b.attempts.get(n) else {
                p33(format!("job {job}: attempt {n} dropped by {cmd:?}"));
                continue;
            };
            for s in 0..x.accepted.len() {
                let kept = (!x.accepted[s] || y.accepted[s])
                    && (!x.ready[s] || (y.ready[s] && y.state[s] == x.state[s]))
                    && (x.corroborated[s].is_none() || y.corroborated[s] == x.corroborated[s]);
                if !kept {
                    p33(format!(
                        "job {job}: signed lease {n}/{s} changed by {cmd:?}"
                    ));
                }
            }
        }
        let mut left: Vec<u64> = Vec::new();
        for (id, i) in &a.items {
            let Some(j) = b.items.get(id) else {
                p33(format!("job {job}: {id:?} dropped by {cmd:?}"));
                continue;
            };
            let ok = match i.state {
                ItemState::Reserved => true,
                ItemState::Refunded => j.state == ItemState::Refunded,
                ItemState::Paid => {
                    if j.rewarded && !i.rewarded {
                        left.extend(i.paid_at);
                    }
                    j.state == ItemState::Paid
                        && (j.amount, j.paid_at) == (i.amount, i.paid_at)
                        && (j.rewarded || !i.rewarded)
                }
            };
            if !ok {
                p33(format!("job {job}: decided {id:?} changed by {cmd:?}"));
            }
        }
        // Each payment leaves on its own window, counted from that payment.
        for paid_at in left {
            match cmd {
                Command::ReleaseReward { .. } | Command::Reconcile => {
                    if now < paid_at + limits.reward_hold {
                        p33(format!(
                            "job {job}: a payment released inside its own contest window"
                        ));
                    }
                }
                Command::ContestReward { .. } => {
                    if now >= paid_at + limits.contest_limit {
                        p33(format!("job {job}: a payment contested past its own limit"));
                    }
                }
                other => p33(format!("job {job}: {other:?} closed a held reward")),
            }
        }
        // A revoked attempt takes no new signed statement.
        for (n, x) in &a.attempts {
            let Some(y) = b.attempts.get(n).filter(|_| x.revoked.is_some()) else {
                continue;
            };
            if (&y.accepted, &y.ready, &y.corroborated, y.revoked)
                != (&x.accepted, &x.ready, &x.corroborated, x.revoked)
            {
                p33(format!(
                    "job {job}: {cmd:?} added a proof to revoked attempt {n}"
                ));
            }
        }
    }
    out
}

/// TEST-P34 (JOB-R18, CE-03), judged on the state before the command: a corroboration is taken on
/// record only while the attempt is not revoked, the producer's and the recipient's own leases
/// are in force, both still hold the right their place relies on, and for segments the producer
/// committed to. Whatever is recorded afterwards on a revoked attempt is not a corroboration.
pub(super) fn anteriority_step(
    before: &Coordinator,
    cmd: &Command,
    after: &Coordinator,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut p34 = |detail: String| out.push(v("TEST-P34", detail));
    for (id, j) in after.jobs() {
        for (n, a) in &j.attempts {
            let old = before.jobs().get(id).and_then(|j| j.attempts.get(n));
            for (s, lease) in a.leases.iter().enumerate() {
                let was = old.and_then(|o| o.leases.get(s)?.corroborated.as_ref());
                let (Some(c), None) = (lease.corroborated.as_ref(), was) else {
                    continue;
                };
                let Some(o) = old else {
                    p34(format!("{id:?}/{n}: corroborated as it was placed"));
                    continue;
                };
                if !matches!(cmd, Command::CorroborateRestore { .. }) {
                    p34(format!("{id:?}/{n}/{s}: corroborated by {cmd:?}"));
                }
                if o.revoked_seq.is_some() || a.revoked_seq.is_some_and(|r| r <= c.seq) {
                    p34(format!("{id:?}/{n}/{s}: corroborated after the revocation"));
                }
                let now = before.now();
                let recipient_expiry = o
                    .leases
                    .get(s + 1)
                    .map_or(o.witness_expires_at, |l| l.expires_at);
                if now >= o.leases[s].expires_at || now >= recipient_expiry {
                    p34(format!("{id:?}/{n}/{s}: corroborated on an expired lease"));
                }
                let lost = |who, witness| {
                    before
                        .registry()
                        .right_lost_since(j.pool, who, witness, o.placed_seq)
                };
                let last = s + 1 == o.lenders.len();
                let recipient = o.lenders.get(s + 1).copied().unwrap_or(o.witness);
                if lost(o.lenders[s], false) || lost(recipient, last) {
                    p34(format!(
                        "{id:?}/{n}/{s}: corroborated after a right was withdrawn"
                    ));
                }
                let committed = o.leases[s]
                    .restored
                    .as_ref()
                    .map_or(0, |r| r.segments.len());
                let named = c.segments.windows(2).all(|w| w[0] < w[1])
                    && c.segments.iter().all(|k| (*k as usize) < committed);
                if c.segments.is_empty() || !named {
                    p34(format!(
                        "{id:?}/{n}/{s}: corroborated segments nobody committed to"
                    ));
                }
            }
        }
    }
    out
}
