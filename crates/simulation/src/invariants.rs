//! Invariant checker (spec section 9). `check_state` holds in every reachable state; `check_step`
//! checks one transition (before, command, after). Each violation carries its TEST-Pxx id.

use std::collections::BTreeMap;

use gpu_domain::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub property: &'static str,
    pub detail: String,
}

fn v(property: &'static str, detail: impl Into<String>) -> Violation {
    Violation {
        property,
        detail: detail.into(),
    }
}

fn line_acct(s: SliceId, lender: AccountId) -> Account {
    Account::SliceLine {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

fn pending_acct(s: SliceId, lender: AccountId) -> Account {
    Account::PendingReward {
        job: s.job.0,
        attempt: s.attempt,
        slice: s.slice,
        lender: lender.0,
    }
}

/// JOB-R12 (a) recomputed without calling the domain: the commitment must come before the attempt's
/// revocation or the slice's closure, in log order.
fn committed_before_independent(
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
fn fnv_words(words: &[u64]) -> u64 {
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
fn digest_independent(c: &Coordinator, job: JobId, wt: WorkType, upto: u32) -> u64 {
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

    // TEST-P02: ledger invariants (LEDGER-001 to 006).
    for lv in ledger.check_invariants() {
        out.push(v("TEST-P02", format!("{lv:?}")));
    }

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

    // TEST-P03, TEST-P19: an output's net charge is 0 or 1, and 1 exactly for registered outputs
    // (JOB-R17, JOB-R29).
    let mut net: BTreeMap<OutputId, i64> = BTreeMap::new();
    for e in c.audit_log() {
        match e {
            AuditEvent::OutputCharged { output, .. } => *net.entry(*output).or_default() += 1,
            AuditEvent::OutputVoided { output, .. } => *net.entry(*output).or_default() -= 1,
            _ => {}
        }
    }
    for (o, n) in &net {
        if !(0..=1).contains(n) {
            out.push(v("TEST-P03", format!("output {o:?} net charge {n}")));
        }
        if (*n == 1) != c.delivery().outputs().contains_key(o) {
            out.push(v(
                "TEST-P19",
                format!(
                    "output {o:?}: net charge {n} but registry says {}",
                    c.delivery().outputs().contains_key(o)
                ),
            ));
        }
    }
    if c.delivery().outputs().len() != c.delivery().charges().len()
        || c.delivery()
            .charges()
            .iter()
            .any(|(o, ch)| c.delivery().outputs().get(o) != Some(&ch.attempt))
    {
        out.push(v("TEST-P19", "outputs and charges disagree"));
    }
    // TEST-P05, TEST-P19: charged positions are exactly [0, delivered); validated <= delivered;
    // definitive prefix then provisional suffix; every validated position is definitive.
    for j in c.jobs().values() {
        for wt in WorkType::ALL {
            let t = wt.idx();
            let (val, del) = (j.validated[t], j.delivered[t]);
            if val > del {
                out.push(v(
                    "TEST-P05",
                    format!("{:?} {wt:?}: validated {val} > delivered {del}", j.id),
                ));
            }
            let n = c
                .delivery()
                .outputs()
                .keys()
                .filter(|o| o.job == j.id && o.wt == wt)
                .count() as u32;
            if n != del {
                out.push(v(
                    "TEST-P05",
                    format!("{:?} {wt:?}: {n} outputs charged, {del} delivered", j.id),
                ));
            }
            let mut seen_provisional = false;
            for pos in 0..del {
                let o = OutputId { job: j.id, wt, pos };
                match c.delivery().charges().get(&o) {
                    None => out.push(v(
                        "TEST-P05",
                        format!("delivered position {pos} of {:?} {wt:?} not charged", j.id),
                    )),
                    Some(ch) => {
                        if pos < val && !ch.definitive {
                            out.push(v("TEST-P19", format!("{o:?} validated but provisional")));
                        }
                        if ch.definitive && seen_provisional {
                            out.push(v(
                                "TEST-P19",
                                format!("{o:?} definitive after a provisional output"),
                            ));
                        }
                        seen_provisional |= !ch.definitive;
                    }
                }
            }
            // TEST-P21: bounded exposure, at most K outputs delivered without client signature for
            // the whole job (JOB-R13, JOB-R27).
            if del.saturating_sub(val) > c.config().flow_budget[t] {
                out.push(v(
                    "TEST-P21",
                    format!(
                        "{:?} {wt:?}: {} delivered without client signature > K",
                        j.id,
                        del - val
                    ),
                ));
            }
        }
    }

    // TEST-P03, JOB-R21: contributions paid at most once, on the right attempt, and never more than
    // the output's price in total.
    let mut paid_by_cid: BTreeMap<ContributionId, u32> = BTreeMap::new();
    let mut reserved_by_cid: BTreeMap<ContributionId, u32> = BTreeMap::new();
    let mut paid_by_output: BTreeMap<(OutputId, u32), Amount> = BTreeMap::new();
    let mut uncommitted_by_lender: BTreeMap<AccountId, Vec<(Time, Amount)>> = BTreeMap::new();
    let mut recovery_paid_by_job: BTreeMap<JobId, Amount> = BTreeMap::new();
    for e in c.audit_log() {
        match e {
            AuditEvent::ItemReserved {
                kind: ItemKind::Contribution(cid),
                ..
            } => *reserved_by_cid.entry(*cid).or_default() += 1,
            AuditEvent::ItemPaid {
                slice,
                lender,
                kind,
                amount,
                evidence,
                by_arbitration,
                at,
            } => {
                // TEST-P10: no payment without proof, except by arbitration.
                if *evidence == Evidence::None && !by_arbitration {
                    out.push(v("TEST-P10", format!("{slice:?} paid without evidence")));
                }
                if *evidence == Evidence::Uncommitted && !by_arbitration {
                    uncommitted_by_lender
                        .entry(*lender)
                        .or_default()
                        .push((*at, *amount));
                }
                match kind {
                    ItemKind::Contribution(cid) => {
                        *paid_by_cid.entry(*cid).or_default() += 1;
                        *paid_by_output.entry((cid.output, cid.charge)).or_default() += amount;
                        let in_force = c
                            .delivery()
                            .charges()
                            .get(&cid.output)
                            .is_some_and(|ch| ch.gen == cid.charge);
                        if !in_force {
                            out.push(v(
                                "TEST-P22",
                                format!("{cid:?} paid but its charge is no longer in force"),
                            ));
                        } else if c.delivery().outputs().get(&cid.output) != Some(&slice.attempt) {
                            out.push(v(
                                "TEST-P04",
                                format!(
                                    "{cid:?} paid on attempt {} but output bound to {:?}",
                                    slice.attempt,
                                    c.delivery().outputs().get(&cid.output)
                                ),
                            ));
                        }
                        if *evidence == Evidence::Committed
                            && !by_arbitration
                            && !committed_before_independent(
                                c,
                                *slice,
                                *lender,
                                cid.output.wt,
                                cid.output.pos,
                            )
                        {
                            out.push(v(
                                "TEST-P08",
                                format!("{cid:?} paid as committed without prior commitment"),
                            ));
                        }
                    }
                    ItemKind::Recovery(_) => {
                        *recovery_paid_by_job.entry(slice.job).or_default() += amount
                    }
                }
            }
            _ => {}
        }
    }
    for (cid, n) in paid_by_cid.iter().chain(reserved_by_cid.iter()) {
        if *n > 1 {
            out.push(v(
                "TEST-P03",
                format!("contribution {cid:?} counted {n} times"),
            ));
        }
    }
    for ((o, _), amt) in &paid_by_output {
        let price = c.jobs().get(&o.job).map_or(0, |j| j.price[o.wt.idx()]);
        if *amt > price {
            out.push(v(
                "TEST-P15",
                format!("output {o:?}: contributions paid {amt} > price {price}"),
            ));
        }
    }
    // TEST-P08: sliding cap recomputed from the payment log; gross amounts within any 24 h window
    // stay under the cap.
    let w = c.config().uncommitted_window;
    for (l, pays) in &uncommitted_by_lender {
        for (ti, _) in pays {
            let sum: Amount = pays
                .iter()
                .filter(|(tj, _)| tj + w > *ti && tj <= ti)
                .map(|(_, a)| a)
                .sum();
            if sum > c.config().uncommitted_cap {
                out.push(v(
                    "TEST-P08",
                    format!(
                        "{l:?}: {sum} paid on uncommitted receipts within 24 h before {ti} > cap"
                    ),
                ));
            }
        }
    }

    // TEST-P12: line invariants and consistency with the ledger.
    for s in c.slices().values() {
        for (lender, l) in &s.lines {
            if l.claimed != l.pending + l.paid + l.refunded + l.disputed {
                out.push(v("TEST-P12", format!("{:?}/{lender:?}: claimed {} != pending {} + paid {} + refunded {} + disputed {}", s.id, l.claimed, l.pending, l.paid, l.refunded, l.disputed)));
            }
            if l.paid != l.held + l.released + l.contested {
                out.push(v(
                    "TEST-P12",
                    format!(
                        "{:?}/{lender:?}: paid {} != held {} + released {} + contested {}",
                        s.id, l.paid, l.held, l.released, l.contested
                    ),
                ));
            }
            if s.status == SliceStatus::Final && (l.pending != 0 || l.disputed != 0) {
                out.push(v(
                    "TEST-P12",
                    format!("{:?}/{lender:?}: final with pending/disputed", s.id),
                ));
            }
            let bal = ledger.balance(line_acct(s.id, *lender));
            if bal != i128::from(l.pending + l.disputed) {
                out.push(v(
                    "TEST-P12",
                    format!(
                        "{:?}/{lender:?}: line account {bal} != pending+disputed",
                        s.id
                    ),
                ));
            }
            let held = ledger.balance(pending_acct(s.id, *lender));
            if held != i128::from(l.held) {
                out.push(v(
                    "TEST-P12",
                    format!(
                        "{:?}/{lender:?}: pending account {held} != held {}",
                        s.id, l.held
                    ),
                ));
            }
            let item_sum: Amount = l.items.iter().map(|i| i.amount).sum();
            if item_sum != l.claimed {
                out.push(v(
                    "TEST-P12",
                    format!(
                        "{:?}/{lender:?}: items {item_sum} != claimed {}",
                        s.id, l.claimed
                    ),
                ));
            }
        }
        // TEST-P22: a waiting contribution points to a provisional output; a contribution of a
        // voided charge is refunded.
        for (lender, l) in &s.lines {
            for it in &l.items {
                if it.awaiting_delivery && it.status != ItemStatus::Disputed {
                    out.push(v(
                        "TEST-P22",
                        format!("{:?}/{lender:?}: awaiting item not disputed", s.id),
                    ));
                }
                if let ItemKind::Contribution(cid) = it.kind {
                    let ch = c
                        .delivery()
                        .charges()
                        .get(&cid.output)
                        .filter(|ch| ch.gen == cid.charge);
                    match ch {
                        None if it.status != ItemStatus::Refunded => out.push(v(
                            "TEST-P22",
                            format!("{cid:?}: charge voided but item {:?}", it.status),
                        )),
                        Some(ch) if it.awaiting_delivery && ch.definitive => out.push(v(
                            "TEST-P22",
                            format!("{cid:?}: output definitive but item still awaiting"),
                        )),
                        Some(ch) if it.status == ItemStatus::Paid && !ch.definitive => out.push(v(
                            "TEST-P22",
                            format!("{cid:?}: paid while output provisional"),
                        )),
                        _ => {}
                    }
                }
            }
        }
        if matches!(s.status, SliceStatus::Open | SliceStatus::Draining) && !s.lines.is_empty() {
            out.push(v("TEST-P12", format!("{:?}: lines before closure", s.id)));
        }
    }

    // TEST-P13: a closed settlement leaves escrow at zero.
    for j in c.jobs().values() {
        if j.settle == SettleStatus::Closed {
            for acct in [
                Account::EscrowWork(j.id.0),
                Account::EscrowRecovery(j.id.0),
                Account::OutputHold(j.id.0),
            ] {
                if ledger.balance(acct) != 0 {
                    out.push(v(
                        "TEST-P13",
                        format!("{:?} closed with {acct:?} = {}", j.id, ledger.balance(acct)),
                    ));
                }
            }
            for s in c.slices().values().filter(|s| s.id.job == j.id) {
                if s.status != SliceStatus::Final {
                    out.push(v(
                        "TEST-P13",
                        format!("{:?} closed with slice {:?} {:?}", j.id, s.id, s.status),
                    ));
                }
            }
        }
        if j.settle == SettleStatus::Closed && !j.exec.is_terminal() {
            out.push(v(
                "TEST-P13",
                format!("{:?} settlement closed while executing", j.id),
            ));
        }
    }

    // TEST-P14: recovery paid stays within the earmarks and the credits that entered recovery
    // escrow.
    for j in c.jobs().values() {
        for a in j.attempts.values() {
            if a.recovery_reserved > a.recovery_earmark {
                out.push(v(
                    "TEST-P14",
                    format!(
                        "{:?} attempt {}: reserved {} > earmark {}",
                        j.id, a.no, a.recovery_reserved, a.recovery_earmark
                    ),
                ));
            }
        }
        let inflow: Amount = ledger
            .entries()
            .iter()
            .filter(|e| {
                e.to == Account::EscrowRecovery(j.id.0)
                    && matches!(e.from, Account::User(_) | Account::PoolReserve(_))
            })
            .map(|e| e.amount)
            .sum();
        let paid = recovery_paid_by_job.get(&j.id).copied().unwrap_or(0);
        if paid > inflow {
            out.push(v(
                "TEST-P14",
                format!("{:?}: recovery paid {paid} > funded {inflow}", j.id),
            ));
        }
    }

    // TEST-P17 (CE-02): pool credits never benefit the borrower. Borrower budget first; unspent
    // pool share goes back to the pool.
    for j in c.jobs().values() {
        let sum_entries =
            |pred: &dyn Fn(&gpu_domain::Account, &gpu_domain::Account) -> bool| -> Amount {
                ledger
                    .entries()
                    .iter()
                    .filter(|e| pred(&e.from, &e.to))
                    .map(|e| e.amount)
                    .sum()
            };
        let rec = Account::EscrowRecovery(j.id.0);
        let funded = sum_entries(&|f, t| matches!(f, Account::PoolReserve(_)) && *t == rec);
        if funded != j.pool_recovery_funded {
            out.push(v(
                "TEST-P17",
                format!(
                    "{:?}: pool funded {funded} in ledger, {} in job",
                    j.id, j.pool_recovery_funded
                ),
            ));
        }
        let paid = recovery_paid_by_job.get(&j.id).copied().unwrap_or(0);
        if j.recovery_paid_borrower + j.recovery_paid_pool != paid {
            out.push(v(
                "TEST-P17",
                format!(
                    "{:?}: recovery attribution {}+{} != paid {paid}",
                    j.id, j.recovery_paid_borrower, j.recovery_paid_pool
                ),
            ));
        }
        if j.recovery_paid_borrower > j.recovery_budget || j.recovery_paid_pool > funded {
            out.push(v(
                "TEST-P17",
                format!("{:?}: recovery attribution exceeds its source", j.id),
            ));
        }
        if j.recovery_paid_pool > 0 && j.recovery_paid_borrower != j.recovery_budget {
            out.push(v(
                "TEST-P17",
                format!(
                    "{:?}: pool relay used before borrower budget was exhausted",
                    j.id
                ),
            ));
        }
        if j.settle == SettleStatus::Closed {
            let borrower = Account::User(j.borrower.0);
            let put_in = sum_entries(&|f, t| *f == borrower && *t == rec);
            let to_borrower = sum_entries(&|f, t| *f == rec && *t == borrower);
            let to_pool = sum_entries(&|f, t| *f == rec && matches!(t, Account::PoolReserve(_)));
            if to_borrower != put_in - j.recovery_paid_borrower {
                out.push(v(
                    "TEST-P17",
                    format!(
                        "{:?}: borrower got {to_borrower} back from recovery escrow, expected {}",
                        j.id,
                        put_in - j.recovery_paid_borrower
                    ),
                ));
            }
            if to_pool != funded - j.recovery_paid_pool {
                out.push(v(
                    "TEST-P17",
                    format!(
                        "{:?}: pool got {to_pool} back, expected {}",
                        j.id,
                        funded - j.recovery_paid_pool
                    ),
                ));
            }
        }
    }

    // TEST-P18: the live attempt's unbilled window is covered by work escrow (JOB-R25), so a charge
    // never lacks funds.
    for j in c.jobs().values() {
        if let Some(a) = j.current() {
            if a.revoked_at.is_none() {
                let window: Amount = (0..3)
                    .map(|i| {
                        j.price[i] * Amount::from(a.produced[i].saturating_sub(j.delivered[i]))
                    })
                    .sum();
                let escrow = ledger.balance(Account::EscrowWork(j.id.0));
                if i128::from(window) > escrow {
                    out.push(v(
                        "TEST-P18",
                        format!("{:?}: unvalidated window {window} > escrow {escrow}", j.id),
                    ));
                }
            }
        }
    }

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
    out
}

/// Admissible basis for each billing event of a step (TEST-P20).
fn check_charge_basis(before: &Coordinator, cmd: &Command, after: &Coordinator) -> Vec<Violation> {
    let mut out = Vec::new();
    let new = &after.audit_log()[before.audit_log().len().min(after.audit_log().len())..];
    let from_reconcile = matches!(
        cmd,
        Command::Reconcile | Command::ExpireDeliveryWindow { .. }
    );
    for e in new {
        match e {
            AuditEvent::OutputCharged {
                output,
                provisional: true,
                ..
            } => {
                // Only an attestation from the assigned, independent witness charges provisionally.
                let ok = match cmd {
                    Command::Deliver {
                        job,
                        attempt,
                        witness,
                        wt,
                        upto,
                        digest,
                    } => before.jobs().get(job).is_some_and(|j| {
                        j.attempts.get(attempt).is_some_and(|a| {
                            let independent = a.witness == *witness
                                && !a.witness_lost
                                && !a.buffer_purged
                                && !a.lenders.contains(witness)
                                && *witness != j.borrower;
                            // JOB-R34: frames from the right stream, not substituted.
                            let frames = *digest == digest_independent(before, *job, *wt, *upto);
                            // JOB-R32: late means a commitment before revocation, during draining,
                            // with no newer attempt.
                            let timely = match (a.revoked_at, a.revoked_seq) {
                                (None, _) => true,
                                (Some(r), Some(rs)) => {
                                    j.attempt == *attempt
                                        && before.now() <= r + before.config().drain_window
                                        && before
                                            .delivery()
                                            .witness_commits()
                                            .get(&(*job, *attempt, *wt))
                                            .is_some_and(|l| {
                                                l.iter().any(|(u, sq)| *u >= *upto && *sq < rs)
                                            })
                                }
                                _ => false,
                            };
                            independent && frames && timely
                        })
                    }),
                    _ => false,
                };
                if !ok {
                    out.push(v(
                        "TEST-P20",
                        format!("{output:?} provisionally charged by {cmd:?}"),
                    ));
                }
            }
            AuditEvent::OutputCharged {
                output,
                provisional: false,
                ..
            } => {
                if !matches!(cmd, Command::Ack { .. }) {
                    out.push(v(
                        "TEST-P20",
                        format!(
                            "{output:?} definitively charged without client signature ({cmd:?})"
                        ),
                    ));
                }
            }
            AuditEvent::OutputConfirmed { output, basis } => {
                let contested = before
                    .delivery()
                    .charges()
                    .get(output)
                    .is_some_and(|ch| ch.contest.is_some());
                let ok = match basis {
                    // TEST-P27: only a client signature COVERING the position (cumulative ack or
                    // stream-bound statement) makes it definitive.
                    ChargeBasis::ClientSigned => match cmd {
                        Command::Ack { wt, upto, .. } => output.wt == *wt && output.pos < *upto,
                        Command::ConfirmDelivery {
                            job,
                            wt,
                            confirmed,
                            digest,
                        } => {
                            output.wt == *wt
                                && output.pos < *confirmed
                                && *digest == digest_independent(before, *job, *wt, *confirmed)
                        }
                        _ => false,
                    },
                    ChargeBasis::WindowExpired => {
                        // Recomputed independently: producing attempt revoked for at least the
                        // window, and never a contested output.
                        from_reconcile
                            && !contested
                            && after.delivery().charges().get(output).is_some_and(|ch| {
                                after.jobs()[&output.job].attempts[&ch.attempt]
                                    .revoked_at
                                    .is_some_and(|r| {
                                        after.now() >= r + after.config().delivery_window
                                    })
                            })
                    }
                    ChargeBasis::Witnessed => false,
                };
                if contested && *basis != ChargeBasis::ClientSigned {
                    out.push(v(
                        "TEST-P27",
                        format!("contested {output:?} closed as {basis:?} by {cmd:?}"),
                    ));
                }
                if !ok {
                    out.push(v(
                        "TEST-P20",
                        format!("{output:?} confirmed as {basis:?} by {cmd:?}"),
                    ));
                }
            }
            AuditEvent::OutputVoided { output, .. } => {
                let was_provisional = before
                    .delivery()
                    .charges()
                    .get(output)
                    .is_some_and(|ch| !ch.definitive);
                // Voiding: lost buffer on a client statement, or deadline of an uncovered contest
                // on this position or an earlier one.
                let by_deadline =
                    matches!(cmd, Command::Reconcile | Command::ResolveContests { .. })
                        && before.delivery().charges().iter().any(|(o, ch)| {
                            o.job == output.job
                                && o.wt == output.wt
                                && o.pos <= output.pos
                                && !ch.definitive
                                && ch.contest.is_some_and(|k| after.now() >= k.deadline)
                        });
                let by_client = matches!(cmd, Command::ConfirmDelivery { .. });
                if !(by_client || by_deadline) || !was_provisional {
                    out.push(v(
                        "TEST-P20",
                        format!(
                            "{output:?} voided by {cmd:?} (provisional before: {was_provisional})"
                        ),
                    ));
                }
            }
            AuditEvent::ContestOpened { output, deadline } => {
                // TEST-P27: a contest opens on a signed client statement, once, on a provisional
                // output of a revoked attempt, within the window.
                let ok = match cmd {
                    Command::ConfirmDelivery { confirmed, wt, .. } => {
                        output.wt == *wt
                            && output.pos >= *confirmed
                            && before.delivery().charges().get(output).is_some_and(|ch| {
                                !ch.definitive
                                    && ch.contest.is_none()
                                    && before.jobs()[&output.job].attempts[&ch.attempt]
                                        .revoked_at
                                        .is_some_and(|r| {
                                            after.now() < r + after.config().delivery_window
                                        })
                            })
                    }
                    _ => false,
                };
                if !ok || *deadline != after.now() + after.config().contest_resolution {
                    out.push(v(
                        "TEST-P27",
                        format!("contest on {output:?} opened by {cmd:?}"),
                    ));
                }
            }
            AuditEvent::BufferPurged { job, attempt } => {
                // TEST-P26: buffer kept during the window and while any output of the attempt is
                // provisional or contested.
                let a = &before.jobs()[job].attempts[attempt];
                let retention_over = a
                    .revoked_at
                    .is_some_and(|r| after.now() >= r + after.config().delivery_window);
                let pending = before
                    .delivery()
                    .charges()
                    .iter()
                    .any(|(o, ch)| o.job == *job && ch.attempt == *attempt && !ch.definitive);
                if !retention_over || pending {
                    out.push(v(
                        "TEST-P26",
                        format!("{job:?} attempt {attempt}: buffer purged too early"),
                    ));
                }
            }
            AuditEvent::EvidenceSupplemented { slice, .. } => {
                // TEST-P28: supplementary proof only before the deadline.
                let s = &before.slices()[slice];
                if after.now() >= s.closed_at.unwrap_or(0) + after.config().evaluation_deadline {
                    out.push(v(
                        "TEST-P28",
                        format!("{slice:?}: evidence supplemented after deadline"),
                    ));
                }
            }
            AuditEvent::ItemRefunded {
                slice,
                reason: RefundReason::NoEvidence | RefundReason::EvidenceNotFound,
                ..
            } => {
                // TEST-P28: refunds for missing proof only at the deadline.
                let s = &after.slices()[slice];
                if after.now() < s.closed_at.unwrap_or(0) + after.config().evaluation_deadline {
                    out.push(v(
                        "TEST-P28",
                        format!("{slice:?}: refunded for missing proof before deadline"),
                    ));
                }
            }
            AuditEvent::ItemPaid {
                kind: ItemKind::Contribution(cid),
                ..
            } => {
                // TEST-P22: never paid while its output is provisional.
                let ok = after
                    .delivery()
                    .charges()
                    .get(&cid.output)
                    .is_some_and(|ch| ch.gen == cid.charge && ch.definitive);
                if !ok {
                    out.push(v(
                        "TEST-P22",
                        format!("{cid:?} paid while its output is not definitive"),
                    ));
                }
            }
            AuditEvent::Produced {
                job, wt, from, to, ..
            } => {
                // TEST-P25: a charged position is never recomputed.
                for pos in *from..*to {
                    if before.delivery().outputs().contains_key(&OutputId {
                        job: *job,
                        wt: *wt,
                        pos,
                    }) {
                        out.push(v(
                            "TEST-P25",
                            format!("{job:?} {wt:?} position {pos} regenerated while charged"),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// TEST-P23, fairness, checked after draining: every honest, proven, funded contribution ends paid
/// with its reward released or contested; no valid claim is lost at closure; an uncommitted receipt
/// is only refunded by arbitration.
pub fn check_fairness(
    c: &Coordinator,
    claims: &[(SliceId, AccountId, ContributionId)],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let in_force = |cid: &ContributionId| {
        c.delivery()
            .charges()
            .get(&cid.output)
            .is_some_and(|ch| ch.gen == cid.charge && ch.definitive)
    };
    for (slice, lender, cid) in claims {
        if in_force(cid) && !c.contributions().contains_key(cid) {
            out.push(v(
                "TEST-P23",
                format!("{slice:?}/{lender:?}: valid claim for {cid:?} lost at closure"),
            ));
        }
    }
    let refund_reason = |slice: SliceId, lender: AccountId, kind: ItemKind| {
        c.audit_log().iter().find_map(|e| match e {
            AuditEvent::ItemRefunded {
                slice: s,
                lender: l,
                kind: k,
                reason,
                ..
            } if *s == slice && *l == lender && *k == kind => Some(*reason),
            _ => None,
        })
    };
    for s in c.slices().values() {
        for (lender, l) in &s.lines {
            for it in &l.items {
                let ItemKind::Contribution(cid) = it.kind else {
                    continue;
                };
                if !in_force(&cid) {
                    continue;
                }
                let proven = match it.evidence {
                    Evidence::Committed => committed_before_independent(
                        c,
                        s.id,
                        *lender,
                        cid.output.wt,
                        cid.output.pos,
                    ),
                    _ => false,
                };
                if proven && it.status != ItemStatus::Paid {
                    out.push(v(
                        "TEST-P23",
                        format!(
                            "{:?}/{lender:?}: proven contribution {cid:?} ended {:?}",
                            s.id, it.status
                        ),
                    ));
                }
                if it.status == ItemStatus::Paid && !it.reward_done {
                    out.push(v(
                        "TEST-P23",
                        format!(
                            "{:?}/{lender:?}: reward of {cid:?} never released nor contested",
                            s.id
                        ),
                    ));
                }
                if it.evidence == Evidence::Uncommitted && it.status == ItemStatus::Refunded {
                    let r = refund_reason(s.id, *lender, it.kind);
                    if r != Some(RefundReason::Arbitration) {
                        out.push(v(
                            "TEST-P23",
                            format!("{:?}/{lender:?}: uncommitted {cid:?} refunded without arbitration ({r:?})", s.id),
                        ));
                    }
                }
            }
        }
    }
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
    let allowed = crate::authz_oracle::allowed(before, ctx, cmd);
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
    out.extend(check_charge_basis(before, cmd, after));
    // TEST-P24: nothing accepted under an expired lease; after reconciliation no live attempt has
    // an expired lease.
    if let Ok(Outcome::Applied) = result {
        if let Command::Produce { job, attempt, .. }
        | Command::Ack { job, attempt, .. }
        | Command::Deliver { job, attempt, .. }
        | Command::AttemptReady { job, attempt, .. }
        | Command::Heartbeat { job, attempt } = cmd
        {
            // Late attestation: governed by JOB-R32 (TEST-P20), not by the lease.
            let late = matches!(cmd, Command::Deliver { .. })
                && before
                    .jobs()
                    .get(job)
                    .and_then(|j| j.attempts.get(attempt))
                    .is_some_and(|a| a.revoked_at.is_some());
            let expired = !late
                && before
                    .jobs()
                    .get(job)
                    .and_then(|j| j.attempts.get(attempt))
                    .is_none_or(|a| before.now() >= a.lease_expires_at);
            if expired {
                out.push(v(
                    "TEST-P24",
                    format!("{cmd:?} accepted under an expired lease"),
                ));
            }
        }
    }
    // Only a reconciliation that actually ran (a refused one changes nothing, TEST-P16).
    if matches!(cmd, Command::Reconcile) && result.is_ok() {
        for (o, ch) in after.delivery().charges() {
            if !ch.definitive && ch.contest.is_some_and(|k| after.now() >= k.deadline) {
                out.push(v(
                    "TEST-P27",
                    format!("{o:?}: contest past its deadline survived reconciliation"),
                ));
            }
        }
        for j in after.jobs().values() {
            if matches!(j.exec, ExecStatus::Running | ExecStatus::Placing) {
                if let Some(a) = j.current() {
                    if a.revoked_at.is_none() && after.now() >= a.lease_expires_at {
                        out.push(v(
                            "TEST-P24",
                            format!("{:?}: expired lease survived reconciliation", j.id),
                        ));
                    }
                }
            }
        }
    }
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
