//! Delivery properties: charges, positions, basis of every billing event (TEST-P03, P05, P19 to
//! P22, P25 to P28).

use std::collections::BTreeMap;

use super::*;

/// TEST-P03, P05, P19.
pub(super) fn charges(c: &Coordinator, out: &mut Vec<Violation>) {
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
}

/// Admissible basis for each billing event of a step (TEST-P20).
pub(super) fn check_charge_basis(
    before: &Coordinator,
    cmd: &Command,
    after: &Coordinator,
) -> Vec<Violation> {
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
