//! Fairness at the end of the drain (TEST-P23).

use gpu_domain::*;

use super::*;

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
