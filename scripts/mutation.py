#!/usr/bin/env python3
"""Test des tests par mutation.

Chaque mutation réintroduit un bug connu (ou plausible) dans le modèle. La
suite de conformité doit échouer : sinon, le vérificateur a un angle mort.
Usage : python3 scripts/mutation.py   (depuis la racine du workspace)
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COORD = "crates/domain/src/coordinator.rs"
MODEL = "crates/domain/src/model.rs"
REGRESSIONS = "tests/properties/proptest-regressions.txt"

# (id, description, fichier, [(ancien, nouveau), ...])
MUTATIONS = [
    ("M01", "Bug v2.1 : JOB-T04 remet execution_intent à initial", COORD,
     [("        j.placing_from = Some(from);", "        j.placing_from = Some(from);\n        if from == ExecStatus::Reserved { j.intent = Intent::Initial; }")]),
    ("M02", "Bug v2.1 : contribution payable sur une autre tentative", COORD,
     [("self.outputs.get(&output) == Some(&slice.attempt)", "self.outputs.contains_key(&output)")]),
    ("M03", "Bug v2.2 : identifiant de contribution sans plage de couches", COORD,
     [("let cid = ContributionId { output, charge: self.charges[&output].gen, layer_start: ls, layer_end: le, role: ContributionRole::Executor",
       "let cid = ContributionId { output, charge: self.charges[&output].gen, layer_start: 0 * ls, layer_end: 0 * le, role: ContributionRole::Executor")]),
    ("M04", "Bug v2.2 : pas de pending_evaluation à la clôture", COORD,
     [("                    line.pending += amount;\n", "")]),
    ("M05", "Contestation qui crée des crédits", COORD,
     [("pending_acct(slice, lender), Account::User(borrower.0), held - to_pool", "Account::Issuance, Account::User(borrower.0), held - to_pool")]),
    ("M06", "Annulation autorisée en settling", COORD,
     [("        if j.exec == ExecStatus::Settling {\n            return Err(DomainError::JobSettling);\n        }", "")]),
    ("M06b", "Annulation autorisée en settling (table de transitions aussi)", COORD,
     [("        if j.exec == ExecStatus::Settling {\n            return Err(DomainError::JobSettling);\n        }", "")]),
    ("M07", "Contrôle de flux désactivé", COORD,
     [("        if upto - j.validated[t] > self.cfg.flow_budget[t] {\n            return Err(DomainError::FlowBudgetExceeded);\n        }", "")]),
    ("M08", "Plafond anti-collusion ignoré", COORD,
     [("if recent + item.amount <= self.cfg.uncommitted_cap {", "if recent + item.amount <= u64::MAX {")]),
    ("M09", "Engagement tardif accepté comme antérieur", COORD,
     [("let cutoff = a.revoked_seq.map_or(closed, |r| r.min(closed));", "let cutoff = u64::MAX + 0 * closed;")]),
    ("M09b", "CE-03 réintroduit : borne = révocation, pas la clôture de la tranche", COORD,
     [("let cutoff = a.revoked_seq.map_or(closed, |r| r.min(closed));", "let cutoff = a.revoked_seq.unwrap_or(self.seq) + 0 * closed;")]),
    ("M10", "Règlement qui oublie OutputHold", COORD,
     [("            (Account::OutputHold(job_acct(job)), \"hold\"),\n        ] {", "        ] {")]),
    ("M11", "CE-01 réintroduit : relais du pool sans escrow actif", COORD,
     [("if j.settle != SettleStatus::Active {", "if j.exec.is_terminal() {")]),
    ("M12", "CE-02 réintroduit : part pool rendue à l'emprunteur", COORD,
     [("let pool_unspent = j.pool_recovery_funded - j.recovery_paid_pool;", "let pool_unspent = 0 * (j.pool_recovery_funded - j.recovery_paid_pool);")]),
    ("M13", "Reprise sans restauration de l'état", COORD,
     [("if restored != j.delivered {", "if false && restored != j.delivered {")]),
    ("M14", "Production acceptée sur une tentative révoquée", COORD,
     [("if attempt != j.attempt || a.revoked_at.is_some() || !a.ready || j.exec != ExecStatus::Running {",
       "if attempt != j.attempt || !a.ready {")]),
    ("M15", "Réconciliation sans arbitrage par défaut des litiges", COORD,
     [("                    SliceStatus::Disputed if now >= s.closed_at.unwrap_or(0) + c.dispute_deadline => {", "                    SliceStatus::Disputed if false => {")]),
    ("M16", "Couverture de la fenêtre non validée désactivée (JOB-R25)", COORD,
     [("        if window > self.ledger.available(Account::EscrowWork(job_acct(job))) {\n            return Err(DomainError::WindowNotCovered);\n        }", "")]),
    ("M17", "Relais du pool consommé avant le budget de l'emprunteur", COORD,
     [("let from_borrower = amount.min(j.recovery_budget - j.recovery_paid_borrower);", "let from_borrower = amount.saturating_sub(j.pool_recovery_funded - j.recovery_paid_pool).min(j.recovery_budget - j.recovery_paid_borrower);")]),
    ("M18", "Récupération non plafonnée par l'enveloppe", COORD,
     [("let fits = recovery_reserved.checked_add(amount).is_some_and(|t| t <= a.recovery_earmark);", "let fits = true;")]),
    # ---- v2.4 : livraison et rejeu (I-03), équité, autorisations datées
    ("M19", "Budget de flux mesuré depuis les positions livrées (témoin complice sans limite)", COORD,
     [("if upto - j.validated[t] > self.cfg.flow_budget[t] {", "if upto - j.delivered[t] > self.cfg.flow_budget[t] {")]),
    ("M20", "Attestation d'un autre que le témoin assigné acceptée", COORD,
     [("if witness != a.witness || a.witness_lost || a.buffer_purged {", "if (a.witness_lost || a.buffer_purged) && witness != a.witness {")]),
    ("M21", "Témoin non indépendant accepté au placement", COORD,
     [("if witness == j.borrower || lenders.contains(&witness) {", "if false && (witness == j.borrower || lenders.contains(&witness)) {")]),
    ("M22", "Contribution évaluée alors que sa sortie est provisoire", COORD,
     [("(ItemKind::Contribution(cid), _) if !self.charges[&cid.output].definitive => {", "(ItemKind::Contribution(cid), _) if false && !self.charges[&cid.output].definitive => {")]),
    ("M23", "Retour arrière sans cascade : seule la position perdue est annulée", COORD,
     [("for pos in (to..from).rev() {", "for pos in (to..(to + 1).min(from)).rev() {")]),
    ("M24", "Retour arrière sans révocation de la tentative vivante", COORD,
     [("        if live {\n            match j.exec {", "        if false && live {\n            match j.exec {")]),
    ("M25", "Travail accepté sous une autorisation expirée", COORD,
     [("        if self.now >= a.lease_expires_at {\n            return Err(DomainError::LeaseExpired);\n        }\n        Ok(a)", "        Ok(a)")]),
    ("M26", "Réconciliation qui ne révoque pas les autorisations expirées", COORD,
     [("                        if j.current().is_some_and(|a| now >= a.lease_expires_at) {\n                            todo.push(Command::NodeLost {", "                        if false {\n                            todo.push(Command::NodeLost {")]),
    ("M27", "Heartbeat qui renouvelle une autorisation expirée", COORD,
     [("        // JOB-R31 : une autorisation expirée ne se renouvelle pas.\n        if now >= a.lease_expires_at {\n            return Err(DomainError::LeaseExpired);\n        }", "")]),
    ("M28", "Fenêtre de livraison close sans attendre la révocation", COORD,
     [(".revoked_at\n                    .is_some_and(|r| now >= r + w);", ".revoked_at\n                    .is_none_or(|r| now >= r + w);")]),
    ("M29", "Client autorisé à confirmer au-delà du livré", COORD,
     [("        if confirmed > delivered {\n            return Err(DomainError::Precondition(\n                \"JOB-R28: confirmed beyond delivered\",\n            ));\n        }", "")]),
    ("M30", "Reprise depuis les positions validées : les livrées sont régénérées", COORD,
     [("let produced = j.delivered;", "let produced = j.validated;"), ("if restored != j.delivered {", "if restored != j.validated {")]),
    ("M31", "CE-04 réintroduit : élément déjà tranché évalué une seconde fois", COORD,
     [("                if item.status != ItemStatus::PendingEvaluation {\n                    continue;\n                }", "")]),
    ("M32", "CE-05 réintroduit : récompense nulle jamais close", COORD,
     [("l.items[idx].reward_done = amount == 0;", "")]),
    ("M33", "Clôture qui perd des réclamations (équité)", COORD,
     [("for StagedClaim { lender, item } in &s.staged {", "for StagedClaim { lender, item } in s.staged.iter().take(1) {")]),
    ("M34", "Contribution prouvée remboursée quand sa sortie devient définitive (équité)", COORD,
     [("                Decision::Pay => self.pay_item(slice, lender, idx, false)?,", "                Decision::Pay => self.refund_item(slice, lender, idx, RefundReason::EvidenceNotFound)?,")]),
    ("M35", "Libération automatique des récompenses désactivée", COORD,
     [("                    SliceStatus::Final\n                        if s.final_at.is_some_and(|f| now >= f + c.reward_window) =>", "                    SliceStatus::Final if false =>")]),
    ("M36", "Attestation au-delà du produit acceptée", COORD,
     [("        if upto > a.produced[t] {\n            return Err(DomainError::Precondition(\n                \"JOB-R27: attestation beyond produced\",\n            ));\n        }", "")]),
    # ---- v2.5 : contestation, empreintes, attestations tardives, tampon, preuves, plafond glissant
    ("M37", "Contestation close par le simple rejeu", COORD,
     [("self.audit.push(AuditEvent::ContestOpened { output, deadline });", "self.audit.push(AuditEvent::ContestOpened { output, deadline });\n            self.make_definitive(output, ChargeBasis::ClientSigned)?;")]),
    ("M38", "Signe de vie du client qui résout les contestations", COORD,
     [("                self.job(*job)?;\n                Ok(Outcome::AlreadyApplied)", "                self.job(*job)?;\n                let os: Vec<OutputId> = self.charges.iter().filter(|(o, c)| o.job == *job && c.contest.is_some()).map(|(o, _)| *o).collect();\n                for o in &os { self.make_definitive(*o, ChargeBasis::ClientSigned)?; }\n                Ok(if os.is_empty() { Outcome::AlreadyApplied } else { Outcome::Applied })")]),
    ("M39", "Empreinte des trames non vérifiée à l'attestation", COORD,
     [("if digest != self.frame_digest(job, wt, upto) {", "if false && digest != self.frame_digest(job, wt, upto) {")]),
    ("M40", "Déclaration du client non liée au flux", COORD,
     [("if digest != self.frame_digest(job, wt, confirmed) {", "if false && digest != self.frame_digest(job, wt, confirmed) {")]),
    ("M41", "Attestation tardive sans engagement antérieur", COORD,
     [("            if !committed {\n                return Err(DomainError::InadmissibleProof);\n            }", "")]),
    ("M42", "Engagement accepté après révocation et compté comme antérieur", COORD,
     [("let a = self.current_live_attempt(job, attempt)?;\n        if witness != a.witness || a.witness_lost {", "let a = self.job(job)?.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;\n        if witness != a.witness || a.witness_lost {"),
      ("*u >= upto && *seq < cutoff", "*u >= upto && *seq <= u64::MAX + 0 * cutoff")]),
    ("M43", "Tampon purgé malgré une contestation ouverte", COORD,
     [("        if self\n            .charges\n            .iter()\n            .any(|(o, ch)| o.job == job && ch.attempt == attempt && !ch.definitive)\n        {", "        if false {")]),
    ("M44", "Plafond par jour calendaire au lieu d'une fenêtre glissante", COORD,
     [(".filter(|(t, _)| t + w > now)", ".filter(|(t, _)| t / w == now / w)")]),
    ("M45", "Remboursement qui restaure le quota (montants nets)", COORD,
     [("        self.job_mut(slice.job)?.recovery_contested_pool += to_pool;", "        self.job_mut(slice.job)?.recovery_contested_pool += to_pool;\n        self.uncommitted_paid.remove(&lender);")]),
    ("M46", "Remboursement faute de preuve avant l'échéance", COORD,
     [("            if before_deadline {\n                Decision::Defer", "            if false && before_deadline {\n                Decision::Defer")]),
    ("M47", "Fenêtre expirée qui ignore les contestations", COORD,
     [("if ch.contest.is_some() || !expired {", "if !expired {")]),
    ("M48", "Échéance des contestations jamais appliquée", COORD,
     [("                if contest_due {", "                if false && contest_due {")]),
    ("M49", "CE-06 réintroduit : tranche terminée avant l'échéance avec une contribution en attente", COORD,
     [("if deferred || (before_deadline && awaiting) {", "if deferred || (false && before_deadline && awaiting) {")]),
    ("M50", "Preuve complémentaire acceptée après l'échéance", COORD,
     [("            && now < s.closed_at.unwrap_or(0) + deadline;", "            && now < u64::MAX + 0 * (s.closed_at.unwrap_or(0) + deadline);")]),
]

EXTRA = {"M06b": (MODEL, [("| (Settling, Completed)   // JOB-T14", "| (Settling, Completed)   // JOB-T14\n                | (Settling, Cancelled)")])}


def run_suite():
    env = dict(os.environ, PROPTEST_CASES="300")
    p = subprocess.run(
        ["cargo", "test", "--release", "-q", "-p", "more-conformance", "--test", "properties", "--test", "scenarios", "--test", "regressions"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=1500)
    out = p.stdout + p.stderr
    failed = sorted(set(re.findall(r"^    (\w+)$", out, re.M)))
    # Le contrôle de couverture ne compte pas comme une détection : une
    # mutation peut le faire échouer simplement en changeant les chemins atteints.
    real = [f for f in failed if f != "generator_reaches_interesting_paths"]
    props = sorted(set(re.findall(r"\[(TEST-P\d+)\]", out)))
    compile_error = "error[E" in out or "could not compile" in out
    return not real, failed, props, compile_error


def anchor_regex(old):
    """Ancre insensible aux blancs : survit à `cargo fmt`."""
    chars = [c for c in old if not c.isspace()]
    return re.compile(r"\s*".join(re.escape(c) for c in chars))


def apply(path, reps):
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
        for f, _ in targets:
            backups[f] = open(os.path.join(ROOT, f)).read()
        # Les graines trouvées contre un mutant ne doivent pas aider à détecter
        # le suivant : le fichier de non-régression est restauré après chaque essai.
        backups[REGRESSIONS] = open(os.path.join(ROOT, REGRESSIONS)).read()
        try:
            for f, r in targets:
                apply(f, r)
            ok, failed, props, cerr = run_suite()
        finally:
            for f, content in backups.items():
                open(os.path.join(ROOT, f), "w").write(content)
        status = "NON DÉTECTÉE" if ok else ("ERREUR DE COMPILATION" if cerr else "détectée")
        results.append((mid, desc, status, failed, props))
        print(f"{mid} {status:22} {desc}\n      tests: {', '.join(failed) or '-'}\n      propriétés: {', '.join(props) or '-'}", flush=True)
    caught = sum(1 for r in results if r[2] == "détectée")
    print(f"\n{caught}/{len(results)} mutations détectées")
    return 0


if __name__ == "__main__":
    sys.exit(main())
