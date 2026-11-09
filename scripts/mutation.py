#!/usr/bin/env python3
"""Mutation testing for the test suite.

Each mutation puts a known (or plausible) bug back into the model. The suite must fail;
if it passes, the checker has a blind spot.
Usage: python3 scripts/mutation.py   (from the workspace root)
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Mutation anchors are searched in these trees; each anchor must match exactly once.
SOURCES = ["crates/domain/src", "crates/ledger/src", "crates/protocol/src", "crates/identity/src"]
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
     [("format!(\"contest/{key}\"),\n reward,", "format!(\"contest/{key}\"),\n Account::Issuance,")]),
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
     [("let pool_unspent = sub(j.pool_recovery_funded, j.recovery_paid_pool, \"pool relay\")?;", "let pool_unspent = 0 * sub(j.pool_recovery_funded, j.recovery_paid_pool, \"pool relay\")?;")]),
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
     [("        if self.now >= a.lease_expires_at {\n            return Err(DomainError::LeaseExpired);\n        }\n        Ok(a)", "        Ok(a)")]),
    ("M26", "Reconciliation does not revoke expired leases", COORD,
     [("                        if j.current().is_some_and(|a| now >= a.lease_expires_at) {\n                            todo.push(Command::NodeLost {", "                        if false {\n                            todo.push(Command::NodeLost {")]),
    ("M27", "Heartbeat renews an expired lease", COORD,
     [("        // JOB-R31: an expired lease is never renewed.\n        if now >= a.lease_expires_at {\n            return Err(DomainError::LeaseExpired);\n        }", "")]),
    ("M28", "Delivery window closed without waiting for revocation", COORD,
     [(".revoked_at\n                    .is_some_and(|r| now >= r + w);", ".revoked_at\n                    .is_none_or(|r| now >= r + w);")]),
    ("M29", "Client may confirm beyond delivered", COORD,
     [("        if confirmed > delivered {\n            return Err(DomainError::Precondition(\n                \"JOB-R28: confirmed beyond delivered\",\n            ));\n        }", "")]),
    ("M30", "Resume from validated positions: delivered ones are regenerated", COORD,
     [("let produced = j.delivered;", "let produced = j.validated;"), ("if restored != j.delivered {", "if restored != j.validated {")]),
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
     [("                self.job(*job)?;\n                Ok(Outcome::AlreadyApplied)", "                self.job(*job)?;\n                let os: Vec<OutputId> = self.charges.iter().filter(|(o, c)| o.job == *job && c.contest.is_some()).map(|(o, _)| *o).collect();\n                for o in &os { self.make_definitive(*o, ChargeBasis::ClientSigned)?; }\n                Ok(if os.is_empty() { Outcome::AlreadyApplied } else { Outcome::Applied })")]),
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
     [("            if before_deadline {\n                Decision::Defer", "            if false && before_deadline {\n                Decision::Defer")]),
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
     [("if total > u128::from(e.mandate) {", "if false {")]),
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
     [(".map_err(|_| AuthError::InvalidCredential)?;", ".ok();")]),
]

EXTRA = {
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


def main():
    results = []
    for mid, desc, path, reps in MUTATIONS:
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
        status = "COMPILE ERROR" if cerr else ("MISSED" if ok else "caught")
        results.append((mid, desc, status, failed, props))
        print(f"{mid} {status:22} {desc}\n      tests: {', '.join(failed) or '-'}\n      properties: {', '.join(props) or '-'}", flush=True)
    caught = sum(1 for r in results if r[2] == "caught")
    print(f"\n{caught}/{len(results)} mutations caught")
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
