//! Accounting properties: ledger, lines, settlement, escrow coverage (TEST-P02, P12, P13,
//! P18).

use super::*;

/// TEST-P02, P12, P13, P18.
pub(super) fn accounts(c: &Coordinator, ledger: &Ledger, out: &mut Vec<Violation>) {
    // TEST-P02: ledger invariants (LEDGER-001 to 006).
    for lv in ledger.check_invariants() {
        out.push(v("TEST-P02", format!("{lv:?}")));
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
}
