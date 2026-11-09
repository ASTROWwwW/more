//! Payment properties: one payment per contribution, sliding cap, recovery within its funding
//! and the pool relay
//! (TEST-P03, P08, P10, P14, P15, P17, P22).

use std::collections::BTreeMap;

use super::*;

/// TEST-P03, P08, P10, P14, P15, P17, P22.
pub(super) fn payments(c: &Coordinator, ledger: &Ledger, out: &mut Vec<Violation>) {
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
}
