#!/usr/bin/env python3
"""Mutation testing for the test suite.

Each mutation puts a known (or plausible) bug back into the model. The suite must fail;
if it passes, the checker has a blind spot.
Usage: python3 scripts/mutation.py [--check] [--shard=K/N] [M07 M12 ...]   (from the workspace root)
`--check` only verifies that every anchor still matches; ids restrict the run; `--shard=K/N`
runs every N-th mutation starting at the K-th (K from 0), so N machines cover the table.
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Mutation anchors are searched in these trees; each anchor must match exactly once.
SOURCES = ["crates/domain/src", "crates/ledger/src", "crates/ledgerd/src", "crates/protocol/src", "crates/identity/src"]
COORD = MODEL = None  # kept for readability of the table: the file is found by its anchor
REGRESSIONS = "tests/properties/proptest-regressions.txt"

# (id, description, file, [(old, new), ...])
MUTATIONS = [
    ("M01", "v2.1 bug: JOB-T04 resets execution_intent to initial", COORD,
     [("        j.placing_from = Some(from);", "        j.placing_from = Some(from);\n        if from == ExecStatus::Reserved { j.intent = Intent::Initial; }")]),
    ("M02", "v2.1 bug: contribution payable on another attempt", COORD,
     [("&& self.delivery.outputs().get(&output) == Some(&slice.attempt);", "&& self.delivery.outputs().contains_key(&output);")]),
    ("M03", "v2.2 bug: contribution id without layer range", COORD,
     [("charge: self.delivery.generation(output), layer_start: ls, layer_end: le,", "charge: self.delivery.generation(output), layer_start: 0 * ls, layer_end: 0 * le,")]),
    ("M04", "v2.2 bug: no pending_evaluation at closure", COORD,
     [("line.pending = add(line.pending, amount, \"pending\")?;", "")]),
    ("M05", "Contest that creates credits", COORD,
     [("format!(\"contest/{tag}\"),\n reward,", "format!(\"contest/{tag}\"),\n Account::Issuance,")]),
    ("M06", "Cancel allowed while settling", COORD,
     [("        if j.exec == ExecStatus::Settling {\n            return Err(DomainError::JobSettling);\n        }", "")]),
    ("M06b", "Cancel allowed while settling (transition table too)", COORD,
     [("        if j.exec == ExecStatus::Settling {\n            return Err(DomainError::JobSettling);\n        }", "")]),
    ("M07", "Flow control disabled", COORD,
     [("if unacked > self.cfg.flow_budget[t] {\n return Err(DomainError::FlowBudgetExceeded);\n }", "")]),
    ("M08", "Anti-collusion cap ignored", COORD,
     [("if add(recent, item.amount, \"sliding cap\")? <= self.cfg.uncommitted_cap {", "if add(recent, item.amount, \"sliding cap\")? <= u64::MAX {")]),
    ("M09", "Late commitment accepted as prior", COORD,
     [("let cutoff = a.revoked_seq.map_or(closed, |r| r.min(closed));", "let cutoff = u64::MAX + 0 * closed;")]),
    ("M09b", "CE-03 back: bound = revocation, not slice closure", COORD,
     [("let cutoff = a.revoked_seq.map_or(closed, |r| r.min(closed));", "let cutoff = a.revoked_seq.unwrap_or(self.seq) + 0 * closed;")]),
    ("M10", "Settlement forgets OutputHold", COORD,
     [("(Account::OutputHold(job), \"hold\"),\n ] {", "] {")]),
    ("M11", "CE-01 back: pool relay without active escrow", COORD,
     [("if j.settle != SettleStatus::Active {", "if j.exec.is_terminal() {")]),
    ("M12", "CE-02 back: pool share returned to the borrower", COORD,
     [("let to_pool = e.pool_funded.checked_sub(e.recovery_paid_pool).ok_or(LedgerApiError::Invalid(\"pool relay overspent\"))?;", "let to_pool = 0 * e.pool_funded;")]),
    ("M13", "Resume without state restore", COORD,
     [("if restored != j.delivered {", "if false && restored != j.delivered {")]),
    ("M14", "Work accepted on a revoked attempt", COORD,
     [("if attempt != j.attempt || a.revoked_at.is_some() || !a.ready || j.exec != ExecStatus::Running {",
       "if attempt != j.attempt || !a.ready {")]),
    ("M15", "Reconciliation without default dispute arbitration", COORD,
     [("                    SliceStatus::Disputed if now >= s.closed_at.unwrap_or(0) + c.dispute_deadline => {", "                    SliceStatus::Disputed if false => {")]),
    ("M16", "Unvalidated window coverage disabled (JOB-R25)", COORD,
     [("if window > self.escrow_work(job)? {\n return Err(DomainError::WindowNotCovered);\n }", "")]),
    ("M17", "Pool relay used before the borrower budget", COORD,
     [("let from_borrower = amount.min(left);", "let from_borrower = amount.saturating_sub(j.pool_recovery_funded - j.recovery_paid_pool).min(left);")]),
    ("M18", "Recovery not capped by the earmark", COORD,
     [("let fits = recovery_reserved.checked_add(amount).is_some_and(|t| t <= a.recovery_earmark);", "let fits = true;")]),
    # ---- delivery, replay, fairness, leases
    ("M19", "Flow budget measured from delivered positions (colluding witness unbounded)", COORD,
     [("let unacked = upto\n .checked_sub(j.validated[t])", "let unacked = upto\n .checked_sub(j.delivered[t])")]),
    ("M20", "Attestation from someone other than the assigned witness accepted", COORD,
     [("if witness != a.witness || a.witness_lost || a.buffer_purged {", "if (a.witness_lost || a.buffer_purged) && witness != a.witness {")]),
    ("M21", "Non-independent witness accepted at placement", COORD,
     [("if witness == j.borrower || lenders.contains(&witness) {", "if false && (witness == j.borrower || lenders.contains(&witness)) {")]),
    ("M22", "Contribution evaluated while its output is provisional", COORD,
     [("(ItemKind::Contribution(cid), _)\n if !self.delivery.charge(cid.output).is_some_and(|c| c.definitive) =>", "(ItemKind::Contribution(cid), _)\n if false && !self.delivery.charge(cid.output).is_some_and(|c| c.definitive) =>")]),
    ("M23", "Rewind without cascade: only the lost position is voided", COORD,
     [("for pos in (to..from).rev() {", "for pos in (to..(to + 1).min(from)).rev() {")]),
    ("M24", "Rewind without revoking the live attempt", COORD,
     [("        if live {\n            match j.exec {", "        if false && live {\n            match j.exec {")]),
    ("M25", "Work accepted under an expired lease", COORD,
     [("        if a.any_expired(self.now) {\n            return Err(DomainError::LeaseExpired);\n        }\n        Ok(a)", "        Ok(a)")]),
    ("M26", "Reconciliation does not revoke expired leases", COORD,
     [("                        if j.current().is_some_and(|a| a.any_expired(now)) {\n                            todo.push(Command::NodeLost {", "                        if false {\n                            todo.push(Command::NodeLost {")]),
    ("M27", "Heartbeat renews an expired lease", COORD,
     [("if now >= expires_at {\n return Err(DomainError::LeaseExpired);\n }", "")]),
    ("M28", "Delivery window closed without waiting for revocation", COORD,
     [(".revoked_at\n                    .is_some_and(|r| now >= r + w);", ".revoked_at\n                    .is_none_or(|r| now >= r + w);")]),
    ("M29", "Client may confirm beyond delivered", COORD,
     [("        if confirmed > delivered {\n            return Err(DomainError::Precondition(\n                \"JOB-R28: confirmed beyond delivered\",\n            ));\n        }", "")]),
    ("M30", "Resume from validated positions: delivered ones are regenerated", COORD,
     [("let produced = j.delivered;", "let produced = j.validated;")]),
    ("M31", "CE-04 back: already decided item evaluated twice", COORD,
     [("                if item.status != ItemStatus::PendingEvaluation {\n                    continue;\n                }", "")]),
    ("M32", "CE-05 back: zero reward never closed", COORD,
     [("l.items[idx].reward_done = amount == 0;", "")]),
    ("M33", "Closure loses claims (fairness)", COORD,
     [("for StagedClaim { lender, item } in &s.staged {", "for StagedClaim { lender, item } in s.staged.iter().take(1) {")]),
    ("M34", "Proven contribution refunded when its output becomes definitive (fairness)", COORD,
     [("                Decision::Pay => self.pay_item(slice, lender, idx, false)?,", "                Decision::Pay => self.refund_item(slice, lender, idx, RefundReason::EvidenceNotFound)?,")]),
    ("M35", "Automatic reward release disabled", COORD,
     [("                    SliceStatus::Final\n                        if s.final_at.is_some_and(|f| now >= f + c.reward_window) =>", "                    SliceStatus::Final if false =>")]),
    ("M36", "Attestation beyond produced accepted", COORD,
     [("        if upto > a.produced[t] {\n            return Err(DomainError::Precondition(\n                \"JOB-R27: attestation beyond produced\",\n            ));\n        }", "")]),
    # ---- contests, frame digests, late attestations, buffer, supplementary proof, sliding cap
    ("M37", "Contest closed by the replay alone", COORD,
     [("self.audit.push(AuditEvent::ContestOpened { output, deadline });", "self.audit.push(AuditEvent::ContestOpened { output, deadline });\n            self.make_definitive(output, ChargeBasis::ClientSigned)?;")]),
    ("M38", "Client liveness signal resolves contests", COORD,
     [("                self.job(*job)?;\n                Ok(Outcome::AlreadyApplied)", "                self.job(*job)?;\n                let os: Vec<OutputId> = self.delivery.charges().iter().filter(|(o, c)| o.job == *job && c.contest.is_some()).map(|(o, _)| *o).collect();\n                for o in &os { self.make_definitive(*o, ChargeBasis::ClientSigned)?; }\n                Ok(if os.is_empty() { Outcome::AlreadyApplied } else { Outcome::Applied })")]),
    ("M39", "Frame digest not checked on attestation", COORD,
     [("if digest != self.frame_digest(job, wt, upto) {", "if false && digest != self.frame_digest(job, wt, upto) {")]),
    ("M40", "Client declaration not bound to the stream", COORD,
     [("if digest != self.frame_digest(job, wt, confirmed) {", "if false && digest != self.frame_digest(job, wt, confirmed) {")]),
    ("M41", "Late attestation without prior commitment", COORD,
     [("if !self\n .delivery\n .witness_committed_before((job, attempt, wt), upto, cutoff)\n {\n return Err(DomainError::InadmissibleProof);\n }", "")]),
    ("M42", "Commitment accepted after revocation and counted as prior", COORD,
     [("let a = self.current_live_attempt(job, attempt)?;\n        if witness != a.witness || a.witness_lost {", "let a = self.job(job)?.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;\n        if witness != a.witness || a.witness_lost {")]),
    ("M43", "Buffer purged despite an open contest", COORD,
     [("if self.delivery.has_provisional(job, Some(attempt)) {", "if false {")]),
    ("M44", "Per-calendar-day cap instead of a sliding window", COORD,
     [(".filter(|(t, _)| t + w > now)", ".filter(|(t, _)| t / w == now / w)")]),
    ("M45", "Refund restores the quota (net amounts)", COORD,
     [("j.recovery_contested_pool = add(j.recovery_contested_pool, to_pool, \"contested pool\")?;", "j.recovery_contested_pool = add(j.recovery_contested_pool, to_pool, \"contested pool\")?;\n self.uncommitted_paid.remove(&lender);")]),
    ("M46", "Refund for missing proof before the deadline", COORD,
     [("if before_deadline {\n Decision::Defer\n } else {\n Decision::Refund(r)", "if false && before_deadline {\n Decision::Defer\n } else {\n Decision::Refund(r)")]),
    ("M47", "Expired window ignores contests", COORD,
     [("if ch.contest.is_some() || !expired {", "if !expired {")]),
    ("M48", "Contest deadline never enforced", COORD,
     [("                if contest_due {", "                if false && contest_due {")]),
    ("M49", "CE-06 back: slice finished before the deadline with an awaiting contribution", COORD,
     [("if deferred || (before_deadline && awaiting) {", "if deferred || (false && before_deadline && awaiting) {")]),
    ("M50", "Supplementary proof accepted after the deadline", COORD,
     [("            && now < s.closed_at.unwrap_or(0) + deadline;", "            && now < u64::MAX + 0 * (s.closed_at.unwrap_or(0) + deadline);")]),
    # ---- trust boundaries: authorization, ledger API, identity, replay guard, input bounds
    ("M51", "Authorization skipped before execution", COORD,
     [("authorize(self, ctx, cmd)?;", "")]),
    ("M52", "Ledger accepts any service role for any operation", COORD,
     [("if role != op.required_role() {", "if false {")]),
    ("M53", "Ledger opens an escrow without checking the borrower's mandate", COORD,
     [(".map_err(|_| LedgerApiError::BadMandate)?;", ".ok();")]),
    ("M54", "Ledger lets reservations exceed the signed mandate", COORD,
     [("if total > u128::from(e.terms.max_budget) {", "if false {")]),
    ("M55", "Receipts committed by anyone, the producer included", COORD,
     [("(Some(acc), Some(rcpt)) if acc == rcpt => Ok(()),", "_ => Ok(()),")]),
    ("M56", "Exact retransmission runs the command again", COORD,
     [("if let Admission::Retransmission(answer) = guard.admit(env)? {\n        return answer;\n    }", "guard.admit(env)?;")]),
    ("M57", "One lender may hold several ranges of an attempt", COORD,
     [("if !lenders.iter().all(|l| seen.insert(*l)) {", "if false && !lenders.iter().all(|l| seen.insert(*l)) {")]),
    ("M58", "Tariff above MAX_PRICE accepted", COORD,
     [("if spec.price.iter().any(|x| *x > MAX_PRICE) {", "if false {")]),
    ("M59", "Clock allowed beyond MAX_TIME", COORD,
     [(".filter(|t| *t <= MAX_TIME)", "")]),
    ("M60", "Signature checked but its result ignored", COORD,
     [("key.verify(message, &Signature::from_bytes(signature))\n            .map_err(|_| AuthError::BadSignature)?;", "let _ = key.verify(message, &Signature::from_bytes(signature));")]),
    ("M61", "Coordinator accepts revoked or forged service credentials", COORD,
     [(".map_err(|_| DomainError::Unauthorized(\"invalid or revoked service credential\"))?;", ".ok();")]),
    ("M62", "Service credential accepted without checking the authority's signature", COORD,
     [("&Signature::from_bytes(&cred.tag),\n )\n .map_err(|_| AuthError::InvalidCredential)?;", "&Signature::from_bytes(&cred.tag),\n )\n .ok();")]),
    # ---- second audit: what the ledger holds against the orchestrator, per-node leases
    ("M63", "Finding 1: a recovery reserve refunded to the output hold", COORD,
     [("source(line.job, item),\n it.amount,\n \"JOB-S04 refund\",", "Account::OutputHold(line.job),\n it.amount,\n \"JOB-S04 refund\",")]),
    ("M64", "Finding 2: settlement accepted with an undecided item", COORD,
     [("if e.has_open_items() {\n return Err(LedgerApiError::OpenItems(job));\n }\n let (owner, pool)", "let (owner, pool)")]),
    ("M65", "Finding 2: a refund still accepted after settlement", COORD,
     [("fn reserved_item(&self, line: LineRef, item: ItemId) -> ApiResult<ItemRec> {\n let it = *self\n .live_escrow(line.job)?", "fn reserved_item(&self, line: LineRef, item: ItemId) -> ApiResult<ItemRec> {\n let it = *self\n .escrow(line.job)?")]),
    ("M66", "Finding 3: lease accepted without the lender's signature", COORD,
     [(".map_err(|_| proof(\"lease not signed by the stage's lender\"))?;", ".ok();")]),
    ("M67", "Finding 3: line reserved for a lender that never accepted", COORD,
     [("if !rec.accepted[s] {\n return Err(proof(\"lender never accepted the lease\"));\n }", "")]),
    ("M68", "Finding 3: line reserved for an account outside the attempt's stage", COORD,
     [("if usize::try_from(stage).ok() != Some(s) {", "if false && usize::try_from(stage).ok() != Some(s) {")]),
    ("M69", "Finding 3: contribution paid without the recipient's receipt", COORD,
     [("if !e.receipt_covers(key.0, key.1, key.2, output.pos) {", "if false && !e.receipt_covers(key.0, key.1, key.2, output.pos) {")]),
    ("M70", "Finding 3: receipt kept whoever signed it", COORD,
     [(".map_err(|_| proof(\"receipt not signed by the producer's recipient\"))?;", ".ok();")]),
    ("M71", "Finding 3: the caller's share replaces the signed terms (double share)", COORD,
     [("let share = u128::from(price) * u128::from(width) / u128::from(e.terms.layers.max(1));", "let share = 2 * u128::from(price) * u128::from(width) / u128::from(e.terms.layers.max(1));")]),
    ("M72", "Recovery reserved before every lender signed ready", COORD,
     [("if !rec.ready[s] || !rec.ready.iter().all(|r| *r) {", "if false {")]),
    ("M73", "Recovery reserved above the attempt's earmark", COORD,
     [(".filter(|r| *r <= rec.assignment.recovery_earmark)", "")]),
    ("M74", "Pool relay accepted without its admin's signature", COORD,
     [(".map_err(|_| LedgerApiError::BadProof(\"relay not signed by the pool's admin\"))?;", ".ok();")]),
    ("M75", "Ledger splits recovery pool first", COORD,
     [("pool_part = it.amount - it.amount.min(left);", "pool_part = it.amount.min(e.pool_funded - e.recovery_paid_pool) + 0 * left;")]),
    ("M76", "Output voided while its shares are still reserved", COORD,
     [("if busy {\n return Err(LedgerApiError::Invalid(", "if false && busy {\n return Err(LedgerApiError::Invalid(")]),
    ("M77", "Finding 4: one ready lender starts the cluster", COORD,
     [("if a.leases.iter().any(|l| l.state != LeaseState::Ready) {\n return Ok(Outcome::Applied);\n }", "")]),
    ("M78", "Finding 4: lease steps can be skipped", COORD,
     [("if lease.state != from {", "if false && lease.state != from {")]),
    ("M79", "Finding 4: a stage loaded with the wrong configuration", COORD,
     [("if self.config_digest(job, attempt, stage) != Some(config) {", "if false && self.config_digest(job, attempt, stage) != Some(config) {")]),
    ("M80", "Finding 5: a heartbeat renews every lease of the attempt", COORD,
     [("self.attempt_mut(job, attempt)?.leases[stage].expires_at = now + ttl;", "for l in self.attempt_mut(job, attempt)?.leases.iter_mut() { l.expires_at = now + ttl; }")]),
    ("M81", "Finding 5: the attempt lives while one lease is still valid", COORD,
     [("now >= self.witness_expires_at || self.leases.iter().any(|l| now >= l.expires_at)", "now >= self.witness_expires_at && self.leases.iter().all(|l| now >= l.expires_at)")]),
    ("M82", "Finding 5: the witness's lease never expires", COORD,
     [("now >= self.witness_expires_at || self.leases.iter().any(|l| now >= l.expires_at)", "self.leases.iter().any(|l| now >= l.expires_at)")]),
    ("M83", "A lender renews or readies another lender's lease", COORD,
     [("if account(who) != Some(*lender) {\n return Err(deny(\"a lender speaks for its own lease only\"));\n }", "")]),
    ("M84", "Uncommitted claim decided without looking for the receipt", COORD,
     [("if !self.receipt_covers(\n slice.job,\n slice.attempt,\n lender,\n cid.output.wt,\n cid.output.pos,\n ) =>", "if false =>")]),
    ("M85", "Attempt registered with a layout that does not cover the signed model", COORD,
     [("if covered != e.terms.layers {", "if false && covered != e.terms.layers {")]),
    ("M86", "A pool's admin can be registered again at the ledger", COORD,
     [("if self.pools.contains_key(&pool) {", "if false && self.pools.contains_key(&pool) {")]),
    # ---- JOB-R18 after the second audit, and the fault found by the restart test
    ("M87", "CE-08 back: reconciliation skips a transition the ledger failed", COORD,
     [("Err(DomainError::Ledger(e)) => {\n return Err(DomainError::Internal(format!(\n \"reconcile {cmd:?}: ledger {e:?}\"\n )))\n }", "Err(DomainError::Ledger(_)) => {}")]),
    ("M88", "Ledger pays recovery without a corroborated restoration", COORD,
     [("if !rec.corroborates(s, segment) {", "if false && !rec.corroborates(s, segment) {")]),
    ("M89", "Restoration corroborated by any signer", COORD,
     [(".map_err(|_| proof(\"restoration not corroborated by the producer's recipient\"))?;", ".ok();")]),
    ("M90", "A ruling pays recovery nobody corroborated", COORD,
     [("ItemKind::Recovery(rid) => self.restore_corroborated(rid, lender),\n ItemKind::Contribution(_) => true,", "ItemKind::Recovery(_) => true,\n ItemKind::Contribution(_) => true,")]),
    ("M91", "Evaluation pays recovery on the lender's word alone", COORD,
     [("if attempt_ready && !self.restore_corroborated(rid, lender) =>", "if false && attempt_ready && !self.restore_corroborated(rid, lender) =>")]),
    ("M92", "Corroboration accepted for a segment the lender never committed to", COORD,
     [("c.map(|c| (*k, *c))", "Some((*k, c.copied().unwrap_or(0)))")]),
    ("M93", "Recovery held before the deadline instead of waiting for its corroboration", COORD,
     [("if before_deadline {\n Decision::Defer\n } else {\n Decision::Dispute", "if false && before_deadline {\n Decision::Defer\n } else {\n Decision::Dispute")]),
    # ---- verifications asked before validating: content binding, finality, bounded contests
    ("M94", "A corroboration can be replaced by another one", COORD,
     [("if !rec.ready[s] || rec.corroborated[s].is_some() || segments.is_empty() {", "if !rec.ready[s] || segments.is_empty() {")]),
    ("M95", "Recovery paid for a segment the corroboration does not cover", COORD,
     [("if !rec.corroborates(s, segment) {", "if rec.corroborated[s].is_none() {")]),
    ("M96", "A recorded receipt replaced by a contradictory one", COORD,
     [(".is_some_and(|d| *d != digest)", ".is_some_and(|d| false && *d != digest)")]),
    ("M97", "A payment released inside its own contest window", COORD,
     [("let due = |paid_at: u64| paid_at.checked_add(hold).is_some_and(|t| now >= t);", "let due = |paid_at: u64| paid_at.checked_add(hold).is_some_and(|t| now >= t) || now >= paid_at;")]),
    ("M98", "A payment contested past its own limit", COORD,
     [("let open = |paid_at: u64| paid_at.checked_add(limit).is_none_or(|t| now < t);", "let open = |paid_at: u64| paid_at.checked_add(limit).is_none_or(|t| now < t) || now >= paid_at;")]),
    ("M99", "The ledger's clock can go back", COORD,
     [("if now < self.now {", "if false && now < self.now {")]),
    ("M100", "Coordinator lets a second corroboration through", COORD,
     [("Some(c) if c.segments == segments => return Ok(Outcome::AlreadyApplied),\n Some(_) => {\n return Err(DomainError::Precondition(\n \"JOB-R18: restoration already corroborated\",\n ))\n }", "Some(c) if c.segments == segments => return Ok(Outcome::AlreadyApplied),\n Some(_) => {}")]),
    ("M101", "Corroboration signature does not cover the state commitment", COORD,
     [("let e = r.restored.iter().fold(e, |e, x| e.u32(*x)).u64(r.state);", "let e = r.restored.iter().fold(e, |e, x| e.u32(*x));")]),
    ("M102", "Corroboration signature does not cover the layer range", COORD,
     [(".u32(r.producer)\n .u32(r.layers.0)\n .u32(r.layers.1);", ".u32(r.producer);")]),
    ("M103", "Corroboration signature does not cover the segments", COORD,
     [(".fold(e.len(r.segments.len()), |e, (k, c)| e.u32(*k).u64(*c))", ".fold(e, |e, _| e)")]),
    ("M104", "Coordinator ignores the contest limit", COORD,
     [("let open = |paid_at: Time| paid_at.checked_add(limit).is_none_or(|t| now < t);", "let open = |paid_at: Time| paid_at.checked_add(limit).is_none_or(|t| now < t) || now >= paid_at;")]),
    ("M105", "Coordinator pays recovery beyond the corroborated segments", COORD,
     [(".is_some_and(|c| c.segments.contains(&rid.segment))", ".is_some()")]),
    # ---- third review: per-payment windows, named segments, deployment domain, anteriority
    ("M106", "Ledger closes every payment of the line on a release or a contest", COORD,
     [("for id in ids {\n if let Some(i) = e.items.get_mut(id) {\n i.rewarded = true;\n }\n }", "let _ = ids;\n for i in e.items.values_mut() {\n if i.state == ItemState::Paid {\n i.rewarded = true;\n }\n }")]),
    ("M107", "Coordinator closes every payment of the line on a contest", COORD,
     [("l.contested = add(l.contested, amount, \"contested\")?;\n for k in idxs {\n l.items[k].reward_done = true;\n }", "l.contested = add(l.contested, amount, \"contested\")?;\n let _ = idxs;\n for it in l.items.iter_mut() {\n it.reward_done = true;\n }")]),
    ("M108", "Ledger records a corroboration after the attempt's revocation", COORD,
     [("if rec.revoked.is_some() {\n return Err(proof(\"corroboration after the attempt's revocation\"));\n }", "")]),
    ("M109", "Ledger records a lease acceptance on a revoked attempt", COORD,
     [("if rec.accepted[s] || rec.revoked.is_some() {", "if rec.accepted[s] {")]),
    ("M110", "Ledger records a readiness on a revoked attempt", COORD,
     [("if rec.revoked.is_some() {\n return Err(invalid(\"attempt revoked\"));\n }", "")]),
    ("M111", "Coordinator takes a corroboration after the revocation", COORD,
     [("if a.revoked_seq.is_some() {\n return Err(DomainError::InadmissibleProof);\n }", "")]),
    ("M112", "Revocation not recorded at the ledger", COORD,
     [("self.ledger_op(LedgerOp::RevokeAttempt {\n job: job_acct(job),\n attempt,\n })?;", "")]),
    ("M113", "Corroboration taken on the producer's expired lease", COORD,
     [("if self.now >= lease.expires_at || self.now >= recipient_expiry {", "if self.now >= recipient_expiry {")]),
    ("M114", "Corroboration taken on the recipient's expired lease", COORD,
     [("if self.now >= lease.expires_at || self.now >= recipient_expiry {", "if self.now >= lease.expires_at {")]),
    ("M115", "Witness's expiry ignored when it is the recipient", COORD,
     [("None => a.witness_expires_at,", "None => u64::MAX,")]),
    ("M116", "Producer's withdrawn right ignored", COORD,
     [("if lost(lender, false) || lost(recipient, last) {", "if lost(recipient, last) {")]),
    ("M117", "Recipient's withdrawn right ignored", COORD,
     [("if lost(lender, false) || lost(recipient, last) {", "if lost(lender, false) {")]),
    ("M118", "Granting a right again erases its withdrawal", COORD,
     [("if had && !has {\n self.lost.insert((pool, account, witness), seq);\n }", "if had && !has {\n self.lost.insert((pool, account, witness), seq);\n } else if has {\n self.lost.remove(&(pool, account, witness));\n }")]),
    ("M119", "Any withdrawn right of the producer voids its restoration", COORD,
     [("if lost(lender, false) || lost(recipient, last) {", "if lost(lender, false) || lost(lender, true) || lost(recipient, last) {")]),
    ("M120", "Statements not bound to the deployment", COORD,
     [("v.extend_from_slice(&d.0);", "let _ = d;")]),
    ("M121", "Corroboration does not bind each segment's commitment", COORD,
     [(".fold(e.len(r.segments.len()), |e, (k, c)| e.u32(*k).u64(*c))", ".fold(e.len(r.segments.len()), |e, (k, _)| e.u32(*k))")]),
    ("M122", "Readiness does not bind the segment commitments", COORD,
     [(".u64(r.state)\n .list64(&r.segments)\n .0", ".u64(r.state)\n .0")]),
    ("M123", "Ledger takes a segment named twice or out of order", COORD,
     [("if !segments.windows(2).all(|w| w[0] < w[1]) {\n return Err(invalid(\"segments named once each, in increasing order\"));\n }", "")]),
    ("M124", "No limit on the segments a lender commits to", COORD,
     [("if segments.len() > self.limits.max_segments {\n return Err(LedgerApiError::LimitExceeded(\"too many recovery segments\"));\n }", "")]),
    ("M125", "A revocation can be recorded twice", COORD,
     [("if rec.revoked.is_some() {\n return Err(invalid(\"attempt already revoked\"));\n }", "")]),
    ("M126", "Ledger records carry no order", COORD,
     [("Ok(out) => {\n self.seq += 1;", "Ok(out) => {")]),
    ("M127", "Coordinator lets an unordered segment list through", COORD,
     [("if segments.is_empty() || !segments.windows(2).all(|w| w[0] < w[1]) {", "if segments.is_empty() {")]),
    ("M128", "Witness's withdrawn right looked up as a right to lend", COORD,
     [("if lost(lender, false) || lost(recipient, last) {", "if lost(lender, false) || lost(recipient, false) {")]),
    ("M129", "Envelope signed for another deployment accepted", COORD,
     [("if env.domain != coord.domain() {\n return Err(ProtoError::WrongDeployment);\n }", "")]),
    ("M130", "Envelope signature does not cover the deployment", COORD,
     [("out.extend_from_slice(self.domain.as_bytes());", "")]),
    ("M131", "Limits that can strand a payment accepted", COORD,
     [("if self.contest_limit < self.reward_hold {", "if false && self.contest_limit < self.reward_hold {")]),
    ("M132", "Coordinator runs on another deployment's ledger", COORD,
     [("if verifier.domain() != ledger.domain() {", "if false && verifier.domain() != ledger.domain() {")]),
    # ---- the ledger in its own process: identities with keys, the link, transactions, the daemon
    ("M133", "A checked certificate vouches for another key", COORD,
     [("let key = (cred.id.0, cred.role as u8, cred.key, cred.tag);", "let key = (cred.id.0, cred.role as u8, [0u8; 32], cred.tag);")]),
    ("M134", "The authority's signature does not cover the service's key", COORD,
     [("msg.push(role as u8);\n msg.extend_from_slice(key);", "msg.push(role as u8);\n let _ = key;")]),
    ("M135", "An identity file may carry a key that is not the certified one", COORD,
     [("(key.verifying_key().to_bytes() == cert.key).then_some(ServiceCredential { cert, key })", "Some(ServiceCredential { cert, key })")]),
    ("M136", "A revocation is accepted without the authority's signature", COORD,
     [(".verify(&revocation_message(id), &Signature::from_bytes(signature))\n .map_err(|_| AuthError::BadSignature)?;", ".verify(&revocation_message(id), &Signature::from_bytes(signature))\n .ok();")]),
    ("M137", "Link: a certificate opens a connection without proof of its key", COORD,
     [("if cert.verify(&expected, &signature).is_err() {", "if false && cert.verify(&expected, &signature).is_err() {")]),
    ("M138", "Link: any certificate is accepted at hello", COORD,
     [("if self.verifier.verify_certificate(&cert).is_err() {\n return self.fault(conn, Fault::Unauthenticated);\n }\n let mine", "let mine")]),
    ("M139", "Link: a hello for another deployment is accepted", COORD,
     [("if domain != self.service.domain() {\n return self.fault(conn, Fault::WrongDeployment);\n }", "")]),
    ("M140", "Link: any protocol version is accepted", COORD,
     [("if version != LINK_VERSION {\n return self.fault(conn, Fault::UnsupportedVersion);\n }", "")]),
    ("M141", "Link: a revoked service keeps its open connection", COORD,
     [("if self.verifier.verify_certificate(&cert).is_err() {\n return self.fault(conn, Fault::Unauthenticated);\n }\n conn.state = State::Ready(cert);", "conn.state = State::Ready(cert);")]),
    ("M142", "Link: request numbers are not checked", COORD,
     [("if conn.seq.checked_add(1) != Some(seq) {\n return self.fault(conn, Fault::OutOfOrder);\n }", "")]),
    ("M143", "Link: others act on a ledger held by a transaction", COORD,
     [("if age.is_none_or(|a| a < self.limits.tx_timeout_ms) {\n return Response::Refused(Refusal::Busy);\n }\n self.rollback();", "let _ = age;")]),
    ("M144", "Link: a transaction never times out", COORD,
     [("if age.is_none_or(|a| a < self.limits.tx_timeout_ms) {", "if age.is_none_or(|a| a < u64::MAX) {")]),
    ("M145", "Link: any service may open a transaction", COORD,
     [("Request::Begin if role != ServiceRole::Orchestrator => forbidden(\"Begin\"),", "")]),
    ("M146", "Link: an aborted transaction is not undone", COORD,
     [("Some(before) if !keep => self.service = before,", "Some(_) if false => {}")]),
    ("M147", "Link: a closed connection keeps its uncommitted work", COORD,
     [("if self.tx.as_ref().is_some_and(|tx| tx.conn == conn.id) {\n self.rollback();\n }", "")]),
    ("M148", "Link: no limit on the size of a transaction", COORD,
     [("if tx.ops > self.limits.max_tx_ops {", "if false && tx.ops > self.limits.max_tx_ops {")]),
    ("M149", "Link: no limit on nested transactions", COORD,
     [("Some(tx) if tx.snapshots.len() >= self.limits.max_tx_depth => {\n return Response::Refused(Refusal::TransactionTooDeep);\n }", "")]),
    ("M150", "Link: any service may register account keys", COORD,
     [("Request::RegisterKey { .. } if role != ServiceRole::Identity => {\n forbidden(\"RegisterKey\")\n }", "")]),
    ("M151", "Link: a full rollback stops at the innermost transaction", COORD,
     [("self.tx.take().and_then(|tx| tx.snapshots.into_iter().next())", "self.tx.take().and_then(|tx| tx.snapshots.into_iter().last())")]),
    ("M152", "Link: the proof does not depend on the ledger's nonce (replay)", COORD,
     [("w.bytes(client_nonce);\n w.bytes(ledger_nonce);", "w.bytes(client_nonce);\n let _ = ledger_nonce;")]),
    ("M153", "Link: the client accepts a peer that is not a ledger", COORD,
     [("if verifier.verify_certificate(&ledger) != Ok(ServiceRole::Ledger)\n || ledger.verify(&sign(true), &signature).is_err()", "if verifier.verify_certificate(&ledger).is_err()\n || ledger.verify(&sign(true), &signature).is_err()")]),
    ("M154", "Link: the client does not check the ledger's proof", COORD,
     [("if verifier.verify_certificate(&ledger) != Ok(ServiceRole::Ledger)\n || ledger.verify(&sign(true), &signature).is_err()", "if verifier.verify_certificate(&ledger) != Ok(ServiceRole::Ledger)")]),
    ("M155", "Link: bytes after a message are ignored", COORD,
     [("r.end()?;\n Ok(m)", "Ok(m)")]),
    ("M156", "Link: a list length is trusted before the bytes are there", COORD,
     [("Some(bytes) if bytes <= self.buf.len() => Ok(n),", "Some(_) => Ok(n),")]),
    ("M157", "Link: no limit on the length of a text", COORD,
     [("if n > MAX_TEXT {\n return Err(Malformed);\n }", "")]),
    ("M158", "Coordinator: no transaction around a command", COORD,
     [("LedgerLink::Remote(port, _) => with(port, |p| p.begin()),", "LedgerLink::Remote(..) => Ok(()),")]),
    ("M159", "Coordinator: a refused command is not rolled back at the ledger", COORD,
     [("if self.ledger.abort().is_err() {\n return Err(e);\n }\n Err(e)", "Err(e)")]),
    ("M160", "Coordinator: an applied command is never committed", COORD,
     [("next.ledger.commit()?;", "")]),
    ("M161", "Coordinator: a repeated command leaves its transaction open", COORD,
     [("Ok(out) => {\n self.ledger.abort()?;\n Ok(out)\n }", "Ok(out) => Ok(out),")]),
    ("M162", "Daemon: memory left readable by the same user", COORD,
     [("seal_memory().map_err(|e| format!(\"cannot seal the process memory: {e}\"))?;", "")]),
    ("M163", "Daemon: socket left with the default permissions", COORD,
     [("fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o600))\n .map_err(|e| format!(\"{}: {e}\", cfg.socket.display()))?;", "")]),
    ("M164", "Daemon: key file readable by others accepted", COORD,
     [("if mode & 0o077 != 0 {", "if false && mode & 0o077 != 0 {")]),
    ("M165", "Daemon: a dead connection keeps its transaction", COORD,
     [("host.lock()\n .unwrap_or_else(|e| e.into_inner())\n .close(&mut conn);", "let _ = &mut conn;")]),
    ("M166", "Daemon: a frame of any length is read", COORD,
     [("if n > MAX_FRAME {\n return Err(std::io::Error::other(\"frame above the limit\"));\n }", "")]),
    ("M167", "Ledger: an operation runs under another role than the connection's", COORD,
     [("if role != op.required_role() {", "if false && role != op.required_role() {")]),
]

EXTRA = {
    "M30": (None, [("if restored != j.delivered {", "if restored != j.validated {")]),
    "M42": (None, [("*u >= upto && *seq < cutoff", "*u >= upto && *seq <= u64::MAX + 0 * cutoff")]),
    "M06b": (None, [("| (Settling, Completed)   // JOB-T14", "| (Settling, Completed)   // JOB-T14\n                | (Settling, Cancelled)")]),
}


def run_suite():
    env = dict(os.environ, PROPTEST_CASES="300")
    p = subprocess.run(
        ["cargo", "test", "--release", "-q", "--workspace", "--no-fail-fast"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=1500)
    out = p.stdout + p.stderr
    # Test names may carry a module path (`lifecycle::f09_...`).
    failed = sorted(set(re.findall(r"^    ([\w:]+)$", out, re.M)))
    # The coverage check does not count as a detection: a mutation can fail it just by changing
    # which paths are reached.
    real = [f for f in failed if f != "generator_reaches_interesting_paths"]
    props = sorted(set(re.findall(r"\[(TEST-P\d+)\]", out)))
    compile_error = "error[E" in out or "could not compile" in out
    # A test binary that dies (abort, stack overflow, out of memory) fails the run without
    # listing a test: that is a detection too, reported as such.
    if p.returncode != 0 and not failed and not compile_error:
        real = failed = ["(a test binary died)"]
    return not real, failed, props, compile_error


def anchor_regex(old):
    """Whitespace-insensitive anchor, so it survives `cargo fmt`."""
    chars = [c for c in old if not c.isspace()]
    return re.compile(r"\s*".join(re.escape(c) for c in chars))


def find(old):
    """The one source file the anchor matches."""
    hits = []
    for tree in SOURCES:
        for dirpath, _, files in os.walk(os.path.join(ROOT, tree)):
            for f in files:
                if f.endswith(".rs"):
                    full = os.path.join(dirpath, f)
                    n = len(anchor_regex(old).findall(open(full).read()))
                    hits += [os.path.relpath(full, ROOT)] * n
    if len(hits) != 1:
        raise SystemExit(f"anchor matched {len(hits)} times: {old[:60]!r}")
    return hits[0]


def apply(path, reps):
    path = path or find(reps[0][0])
    full = os.path.join(ROOT, path)
    src = open(full).read()
    for old, new in reps:
        m = anchor_regex(old).search(src)
        if not m:
            raise SystemExit(f"mutation anchor not found in {path}: {old[:60]!r}")
        src = src[: m.start()] + new + src[m.end():]
    open(full, "w").write(src)


def check_anchors():
    """Every anchor matches exactly one place (`--check`)."""
    bad = 0
    for mid, _, path, reps in MUTATIONS:
        for f, r in [(path, reps)] + ([EXTRA[mid]] if mid in EXTRA else []):
            try:
                target = f or find(r[0][0])
                src = open(os.path.join(ROOT, target)).read()
                for old, _ in r:
                    if not anchor_regex(old).search(src):
                        raise SystemExit(f"anchor not found in {target}: {old[:60]!r}")
            except SystemExit as e:
                bad += 1
                print(f"{mid}: {e}")
    print(f"{len(MUTATIONS) - bad}/{len(MUTATIONS)} mutations have valid anchors")
    return 1 if bad else 0


def main():
    if "--check" in sys.argv:
        return check_anchors()
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    shard = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--shard=")), None)
    if shard:
        k, n = (int(x) for x in shard.split("/"))
        only = [m[0] for i, m in enumerate(MUTATIONS) if i % n == k and (not only or m[0] in only)]
    # The campaign is only worth what it was run on: say which commit, and refuse a dirty tree.
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if dirty:
        raise SystemExit(f"working tree not clean, refusing to mutate it:\n{dirty}")
    print(f"commit {head}" + (f", shard {shard}" if shard else ""), flush=True)
    results = []
    for mid, desc, path, reps in MUTATIONS:
        if only and mid not in only:
            continue
        backups = {}
        targets = [(path, reps)] + ([EXTRA[mid]] if mid in EXTRA else [])
        targets = [(f or find(r[0][0]), r) for f, r in targets]
        for f, _ in targets:
            backups[f] = open(os.path.join(ROOT, f)).read()
        # Seeds found against one mutant must not help detect the next: the regression file is
        # restored after each run.
        backups[REGRESSIONS] = open(os.path.join(ROOT, REGRESSIONS)).read()
        try:
            for f, r in targets:
                apply(f, r)
            ok, failed, props, cerr = run_suite()
        finally:
            for f, content in backups.items():
                open(os.path.join(ROOT, f), "w").write(content)
        # A mutant that does not compile proves nothing about the tests: it is never "caught".
        status = "COMPILE ERROR" if cerr else ("MISSED" if ok else "caught")
        results.append((mid, desc, status, failed, props))
        print(f"{mid} {status:22} {desc}\n      tests ({len(failed)}): {', '.join(failed) or '-'}\n      properties: {', '.join(props) or '-'}", flush=True)
    caught = sum(1 for r in results if r[2] == "caught")
    broken = [r[0] for r in results if r[2] == "COMPILE ERROR"]
    missed = [r[0] for r in results if r[2] == "MISSED"]
    print(f"\n{caught}/{len(results)} mutations caught by a failing test")
    print(f"compile errors (not counted): {', '.join(broken) or 'none'}")
    print(f"missed: {', '.join(missed) or 'none'}")
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
