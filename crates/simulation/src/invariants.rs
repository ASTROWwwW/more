//! Vérificateur d'invariants (spécification v2.5, section 9).
//!
//! Deux niveaux :
//! - [`check_state`] : propriétés vraies dans tout état atteignable ;
//! - [`check_step`] : propriétés d'une transition (avant, commande, après).
//!
//! Chaque violation porte l'identifiant de la propriété TEST-Pxx concernée.

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

/// Recalcul indépendant de JOB-R12 (a), sans appeler le code du domaine :
/// l'engagement doit avoir été horodaté au plus tard à la révocation de la
/// tentative ou à la clôture de la tranche, dans l'ordre du journal.
fn committed_before_independent(
    c: &Coordinator,
    slice: SliceId,
    lender: AccountId,
    wt: WorkType,
    pos: u32,
) -> bool {
    let job = &c.jobs[&slice.job];
    let attempt = &job.attempts[&slice.attempt];
    // JOB-S03 : après la clôture, plus aucun reçu n'est accepté. La borne est
    // donc la plus ancienne de la révocation et de la clôture de la tranche.
    let closed = c.slices[&slice].closed_seq.unwrap_or(c.seq);
    let cutoff = attempt.revoked_seq.map_or(closed, |r| r.min(closed));
    c.commit_log
        .get(&(slice.job, slice.attempt, lender, wt))
        .is_some_and(|log| {
            log.iter()
                .any(|(upto, _, seq)| *upto > pos && *seq < cutoff)
        })
}

/// FNV-1a recalculé ici, sans appeler le domaine.
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

/// Empreinte attendue des trames `0..upto` (JOB-R34), recalculée indépendamment.
fn digest_independent(c: &Coordinator, job: JobId, wt: WorkType, upto: u32) -> u64 {
    let Some(j) = c.jobs.get(&job) else { return 0 };
    let mut h = fnv_words(&[
        u64::from(job.0),
        j.stream,
        u64::from(j.model),
        wt.idx() as u64,
    ]);
    for pos in 0..upto {
        let o = OutputId { job, wt, pos };
        let gen = match c.charges.get(&o) {
            Some(ch) => ch.gen,
            None => c.charge_gens.get(&o).copied().unwrap_or(0),
        };
        h = fnv_words(&[h, u64::from(pos), u64::from(gen)]);
    }
    h
}

pub fn check_state(c: &Coordinator) -> Vec<Violation> {
    let mut out = Vec::new();

    // TEST-P02 : invariants du registre (LEDGER-001 à 006).
    for lv in c.ledger.check_invariants() {
        out.push(v("TEST-P02", format!("{lv:?}")));
    }

    // TEST-P01 : seules les transitions de la table ont été appliquées.
    for e in &c.audit {
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

    // TEST-P03 / TEST-P19 : facturation nette d'une sortie ∈ {0, 1} ; elle vaut
    // 1 exactement pour les sorties enregistrées (JOB-R17, JOB-R29).
    let mut net: BTreeMap<OutputId, i64> = BTreeMap::new();
    for e in &c.audit {
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
        if (*n == 1) != c.outputs.contains_key(o) {
            out.push(v(
                "TEST-P19",
                format!(
                    "output {o:?}: net charge {n} but registry says {}",
                    c.outputs.contains_key(o)
                ),
            ));
        }
    }
    if c.outputs.len() != c.charges.len()
        || c.charges
            .iter()
            .any(|(o, ch)| c.outputs.get(o) != Some(&ch.attempt))
    {
        out.push(v("TEST-P19", "outputs and charges disagree"));
    }
    // TEST-P05 / TEST-P19 : positions facturées = exactement [0, livrées) ;
    // validées ≤ livrées ; préfixe définitif puis suffixe provisoire ; toute
    // position validée est définitive.
    for j in c.jobs.values() {
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
                .outputs
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
                match c.charges.get(&o) {
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
            // TEST-P21 : exposition bornée. Au plus K sorties livrées sans
            // signature du client, pour tout le job (JOB-R13, JOB-R27).
            if del.saturating_sub(val) > c.cfg.flow_budget[t] {
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

    // TEST-P03 / JOB-R21 : contributions payées au plus une fois, sur la bonne
    // tentative, et somme par sortie ≤ prix de la sortie.
    let mut paid_by_cid: BTreeMap<ContributionId, u32> = BTreeMap::new();
    let mut reserved_by_cid: BTreeMap<ContributionId, u32> = BTreeMap::new();
    let mut paid_by_output: BTreeMap<(OutputId, u32), Amount> = BTreeMap::new();
    let mut uncommitted_by_lender: BTreeMap<AccountId, Vec<(Time, Amount)>> = BTreeMap::new();
    let mut recovery_paid_by_job: BTreeMap<JobId, Amount> = BTreeMap::new();
    for e in &c.audit {
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
                // TEST-P10 : jamais de paiement sans preuve, hors arbitrage.
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
                            .charges
                            .get(&cid.output)
                            .is_some_and(|ch| ch.gen == cid.charge);
                        if !in_force {
                            out.push(v(
                                "TEST-P22",
                                format!("{cid:?} paid but its charge is no longer in force"),
                            ));
                        } else if c.outputs.get(&cid.output) != Some(&slice.attempt) {
                            out.push(v(
                                "TEST-P04",
                                format!(
                                    "{cid:?} paid on attempt {} but output bound to {:?}",
                                    slice.attempt,
                                    c.outputs.get(&cid.output)
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
        let price = c.jobs.get(&o.job).map_or(0, |j| j.price[o.wt.idx()]);
        if *amt > price {
            out.push(v(
                "TEST-P15",
                format!("output {o:?}: contributions paid {amt} > price {price}"),
            ));
        }
    }
    // TEST-P08 (v2.5) : plafond glissant, recalculé sur le journal des
    // paiements : sur tout intervalle ]t − 24 h, t], montants bruts ≤ plafond.
    let w = c.cfg.uncommitted_window;
    for (l, pays) in &uncommitted_by_lender {
        for (ti, _) in pays {
            let sum: Amount = pays
                .iter()
                .filter(|(tj, _)| tj + w > *ti && tj <= ti)
                .map(|(_, a)| a)
                .sum();
            if sum > c.cfg.uncommitted_cap {
                out.push(v(
                    "TEST-P08",
                    format!(
                        "{l:?}: {sum} paid on uncommitted receipts within 24 h before {ti} > cap"
                    ),
                ));
            }
        }
    }

    // TEST-P12 : invariants de ligne et cohérence avec le registre.
    for s in c.slices.values() {
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
            let bal = c.ledger.balance(line_acct(s.id, *lender));
            if bal != i128::from(l.pending + l.disputed) {
                out.push(v(
                    "TEST-P12",
                    format!(
                        "{:?}/{lender:?}: line account {bal} != pending+disputed",
                        s.id
                    ),
                ));
            }
            let held = c.ledger.balance(pending_acct(s.id, *lender));
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
        // TEST-P22 : une contribution en attente concerne une sortie encore
        // provisoire ; une contribution d'une facturation annulée est remboursée.
        for (lender, l) in &s.lines {
            for it in &l.items {
                if it.awaiting_delivery && it.status != ItemStatus::Disputed {
                    out.push(v(
                        "TEST-P22",
                        format!("{:?}/{lender:?}: awaiting item not disputed", s.id),
                    ));
                }
                if let ItemKind::Contribution(cid) = it.kind {
                    let ch = c.charges.get(&cid.output).filter(|ch| ch.gen == cid.charge);
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

    // TEST-P13 : un règlement clos laisse un escrow à zéro.
    for j in c.jobs.values() {
        if j.settle == SettleStatus::Closed {
            for acct in [
                Account::EscrowWork(j.id.0),
                Account::EscrowRecovery(j.id.0),
                Account::OutputHold(j.id.0),
            ] {
                if c.ledger.balance(acct) != 0 {
                    out.push(v(
                        "TEST-P13",
                        format!(
                            "{:?} closed with {acct:?} = {}",
                            j.id,
                            c.ledger.balance(acct)
                        ),
                    ));
                }
            }
            for s in c.slices.values().filter(|s| s.id.job == j.id) {
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

    // TEST-P14 : récupération payée ≤ enveloppes et ≤ crédits entrés en escrow de récupération.
    for j in c.jobs.values() {
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
        let inflow: Amount = c
            .ledger
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

    // TEST-P17 (CE-02) : les crédits du pool ne profitent jamais à l'emprunteur.
    // Budget de l'emprunteur consommé d'abord ; part pool non consommée rendue au pool.
    for j in c.jobs.values() {
        let sum_entries =
            |pred: &dyn Fn(&gpu_domain::Account, &gpu_domain::Account) -> bool| -> Amount {
                c.ledger
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

    // TEST-P18 : la fenêtre non validée de la tentative vivante est couverte par
    // l'escrow travail (JOB-R25) — une validation ne peut jamais manquer de fonds.
    for j in c.jobs.values() {
        if let Some(a) = j.current() {
            if a.revoked_at.is_none() {
                let window: Amount = (0..3)
                    .map(|i| {
                        j.price[i] * Amount::from(a.produced[i].saturating_sub(j.delivered[i]))
                    })
                    .sum();
                let escrow = c.ledger.balance(Account::EscrowWork(j.id.0));
                if i128::from(window) > escrow {
                    out.push(v(
                        "TEST-P18",
                        format!("{:?}: unvalidated window {window} > escrow {escrow}", j.id),
                    ));
                }
            }
        }
    }

    // TEST-P09 : budget de flux, pour la tentative vivante.
    for j in c.jobs.values() {
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
                    && a.produced[t] - j.validated[t] > c.cfg.flow_budget[t]
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

    // TEST-P25 : une tentative vivante est construite sur des sorties qui
    // existent : son point de départ ne dépasse jamais les positions livrées
    // (un retour arrière sous ce point DOIT la révoquer, JOB-R29).
    for j in c.jobs.values() {
        let Some(a) = j.current() else { continue };
        if a.revoked_at.is_some() {
            continue;
        }
        let start = c.audit.iter().rev().find_map(|e| match e {
            AuditEvent::AttemptStarted {
                job,
                attempt,
                restored,
                ..
            } if *job == j.id && *attempt == a.no => Some(*restored),
            _ => None,
        });
        // En placement, la production vaut encore le point de départ.
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

    // TEST-P24 : une autorisation n'est jamais prolongée au-delà d'un TTL.
    for j in c.jobs.values() {
        if let Some(a) = j.current() {
            if a.revoked_at.is_none() && a.lease_expires_at > c.now + c.cfg.lease_ttl {
                out.push(v(
                    "TEST-P24",
                    format!("{:?} attempt {}: lease beyond now + ttl", j.id, a.no),
                ));
            }
        }
    }

    // TEST-P07 / TEST-P25 : toute (re)prise démarre exactement à la dernière
    // position livrée : ce qui a été livré est rejoué, jamais régénéré.
    for e in &c.audit {
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

/// Fondement admissible de chaque événement de facturation d'un pas (TEST-P20).
fn check_charge_basis(before: &Coordinator, cmd: &Command, after: &Coordinator) -> Vec<Violation> {
    let mut out = Vec::new();
    let new = &after.audit[before.audit.len().min(after.audit.len())..];
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
                // Seule une attestation du témoin assigné, indépendant, facture provisoirement.
                let ok = match cmd {
                    Command::Deliver {
                        job,
                        attempt,
                        witness,
                        wt,
                        upto,
                        digest,
                    } => before.jobs.get(job).is_some_and(|j| {
                        j.attempts.get(attempt).is_some_and(|a| {
                            let independent = a.witness == *witness
                                && !a.witness_lost
                                && !a.buffer_purged
                                && !a.lenders.contains(witness)
                                && *witness != j.borrower;
                            // JOB-R34 : trames du bon flux, non substituées.
                            let frames = *digest == digest_independent(before, *job, *wt, *upto);
                            // JOB-R32 : tardive = engagement antérieur à la révocation,
                            // pendant le drainage, sans tentative plus récente.
                            let timely = match (a.revoked_at, a.revoked_seq) {
                                (None, _) => true,
                                (Some(r), Some(rs)) => {
                                    j.attempt == *attempt
                                        && before.now <= r + before.cfg.drain_window
                                        && before
                                            .witness_commits
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
                    .charges
                    .get(output)
                    .is_some_and(|ch| ch.contest.is_some());
                let ok = match basis {
                    // TEST-P27 : seule une signature du client COUVRANT la position
                    // (accusé cumulatif ou déclaration liée au flux) la rend définitive.
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
                        // Recalcul indépendant : tentative productrice révoquée depuis
                        // au moins la fenêtre, et jamais une sortie contestée.
                        from_reconcile
                            && !contested
                            && after.charges.get(output).is_some_and(|ch| {
                                after.jobs[&output.job].attempts[&ch.attempt]
                                    .revoked_at
                                    .is_some_and(|r| after.now >= r + after.cfg.delivery_window)
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
                let was_provisional = before.charges.get(output).is_some_and(|ch| !ch.definitive);
                // Annulation : tampon perdu sur déclaration du client, ou échéance
                // d'une contestation non couverte (sur cette position ou une antérieure).
                let by_deadline =
                    matches!(cmd, Command::Reconcile | Command::ResolveContests { .. })
                        && before.charges.iter().any(|(o, ch)| {
                            o.job == output.job
                                && o.wt == output.wt
                                && o.pos <= output.pos
                                && !ch.definitive
                                && ch.contest.is_some_and(|k| after.now >= k.deadline)
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
                // TEST-P27 : une contestation s'ouvre sur déclaration signée du client,
                // une seule fois, sur une sortie provisoire d'une tentative révoquée,
                // pendant la fenêtre de livraison.
                let ok = match cmd {
                    Command::ConfirmDelivery { confirmed, wt, .. } => {
                        output.wt == *wt
                            && output.pos >= *confirmed
                            && before.charges.get(output).is_some_and(|ch| {
                                !ch.definitive
                                    && ch.contest.is_none()
                                    && before.jobs[&output.job].attempts[&ch.attempt]
                                        .revoked_at
                                        .is_some_and(|r| after.now < r + after.cfg.delivery_window)
                            })
                    }
                    _ => false,
                };
                if !ok || *deadline != after.now + after.cfg.contest_resolution {
                    out.push(v(
                        "TEST-P27",
                        format!("contest on {output:?} opened by {cmd:?}"),
                    ));
                }
            }
            AuditEvent::BufferPurged { job, attempt } => {
                // TEST-P26 : tampon conservé pendant la fenêtre et tant qu'une sortie
                // de la tentative est provisoire ou contestée.
                let a = &before.jobs[job].attempts[attempt];
                let retention_over = a
                    .revoked_at
                    .is_some_and(|r| after.now >= r + after.cfg.delivery_window);
                let pending = before
                    .charges
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
                // TEST-P28 : preuve complémentaire seulement avant l'échéance.
                let s = &before.slices[slice];
                if after.now >= s.closed_at.unwrap_or(0) + after.cfg.evaluation_deadline {
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
                // TEST-P28 : un remboursement faute de preuve n'arrive qu'à l'échéance.
                let s = &after.slices[slice];
                if after.now < s.closed_at.unwrap_or(0) + after.cfg.evaluation_deadline {
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
                // TEST-P22 : jamais payée tant que sa sortie est provisoire.
                let ok = after
                    .charges
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
                // TEST-P25 : une position facturée n'est jamais recalculée.
                for pos in *from..*to {
                    if before.outputs.contains_key(&OutputId {
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

/// TEST-P23 — équité, vérifiée en fin de vidage : toute contribution honnête,
/// prouvée et financée finit payée (et sa récompense libérée ou contestée) ;
/// aucune réclamation structurellement valide n'est perdue à la clôture ;
/// un reçu non engagé n'est jamais remboursé sans décision d'arbitrage.
pub fn check_fairness(
    c: &Coordinator,
    claims: &[(SliceId, AccountId, ContributionId)],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let in_force = |cid: &ContributionId| {
        c.charges
            .get(&cid.output)
            .is_some_and(|ch| ch.gen == cid.charge && ch.definitive)
    };
    for (slice, lender, cid) in claims {
        if in_force(cid) && !c.contributions.contains_key(cid) {
            out.push(v(
                "TEST-P23",
                format!("{slice:?}/{lender:?}: valid claim for {cid:?} lost at closure"),
            ));
        }
    }
    let refund_reason = |slice: SliceId, lender: AccountId, kind: ItemKind| {
        c.audit.iter().find_map(|e| match e {
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
    for s in c.slices.values() {
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

/// Propriétés d'un pas : `before`, la commande, son résultat et `after`.
pub fn check_step(
    before: &Coordinator,
    cmd: &Command,
    result: &Result<Outcome, DomainError>,
    after: &Coordinator,
) -> Vec<Violation> {
    let mut out = Vec::new();
    match result {
        // JOB-R01 : un refus ne laisse aucune trace.
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
    // TEST-P24 : rien n'est accepté sous une autorisation expirée ; après une
    // réconciliation, aucune tentative vivante n'a d'autorisation expirée.
    if let Ok(Outcome::Applied) = result {
        if let Command::Produce { job, attempt, .. }
        | Command::Ack { job, attempt, .. }
        | Command::Deliver { job, attempt, .. }
        | Command::AttemptReady { job, attempt, .. }
        | Command::Heartbeat { job, attempt } = cmd
        {
            // Attestation tardive : régie par JOB-R32 (TEST-P20), pas par l'autorisation.
            let late = matches!(cmd, Command::Deliver { .. })
                && before
                    .jobs
                    .get(job)
                    .and_then(|j| j.attempts.get(attempt))
                    .is_some_and(|a| a.revoked_at.is_some());
            let expired = !late
                && before
                    .jobs
                    .get(job)
                    .and_then(|j| j.attempts.get(attempt))
                    .is_none_or(|a| before.now >= a.lease_expires_at);
            if expired {
                out.push(v(
                    "TEST-P24",
                    format!("{cmd:?} accepted under an expired lease"),
                ));
            }
        }
    }
    if matches!(cmd, Command::Reconcile) {
        for (o, ch) in &after.charges {
            if !ch.definitive && ch.contest.is_some_and(|k| after.now >= k.deadline) {
                out.push(v(
                    "TEST-P27",
                    format!("{o:?}: contest past its deadline survived reconciliation"),
                ));
            }
        }
        for j in after.jobs.values() {
            if matches!(j.exec, ExecStatus::Running | ExecStatus::Placing) {
                if let Some(a) = j.current() {
                    if a.revoked_at.is_none() && after.now >= a.lease_expires_at {
                        out.push(v(
                            "TEST-P24",
                            format!("{:?}: expired lease survived reconciliation", j.id),
                        ));
                    }
                }
            }
        }
    }
    // TEST-P04 : production et validation seulement sur la tentative vivante.
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
    for (id, ja) in &after.jobs {
        if let Some(jb) = before.jobs.get(id) {
            // execution_intent monotone (JOB-T04, JOB-T12).
            if jb.intent == Intent::Resume && ja.intent == Intent::Initial {
                out.push(v(
                    "TEST-P07",
                    format!("{id:?}: execution_intent went back to initial on {cmd:?}"),
                ));
            }
            // TEST-P05 : les positions validées ne reculent jamais.
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
    // Le registre est en insertion seule (LEDGER-002).
    let n = before.ledger.entries().len();
    if after.ledger.entries().len() < n
        || after.ledger.entries()[..n] != before.ledger.entries()[..]
    {
        out.push(v(
            "TEST-P02",
            format!("ledger history rewritten by {cmd:?}"),
        ));
    }
    out
}
