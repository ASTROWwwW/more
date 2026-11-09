//! Mesures de couverture, calculées sur les traces réellement exécutées par
//! les tests de propriétés (une seule source pour le rapport).

use std::collections::BTreeMap;
use std::fmt::Write;

use gpu_domain::*;

use crate::world::Sim;

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub traces: u64,
    pub commands: u64,
    pub accepted: u64,
    pub counts: BTreeMap<&'static str, u64>,
    pub refusals: BTreeMap<String, u64>,
}

impl Stats {
    fn bump(&mut self, k: &'static str) {
        *self.counts.entry(k).or_default() += 1;
    }

    pub fn add(&mut self, sim: &Sim) {
        self.traces += 1;
        self.commands += (sim.applied + sim.refused) as u64;
        self.accepted += sim.applied as u64;
        for (k, n) in &sim.refusal_counts {
            *self.refusals.entry(k.clone()).or_default() += n;
        }
        for e in &sim.coord.audit {
            match e {
                AuditEvent::Exec {
                    from: Some(ExecStatus::Running),
                    to: ExecStatus::Recovering,
                    ..
                } => self.bump("reprises (running → recovering)"),
                AuditEvent::AttemptStarted { attempt, .. } if *attempt >= 2 => {
                    self.bump("tentatives ≥ 2 démarrées")
                }
                AuditEvent::OutputCharged {
                    provisional: false, ..
                } => self.bump("sorties facturées sur accusé"),
                AuditEvent::OutputCharged {
                    provisional: true, ..
                } => self.bump("sorties facturées provisoirement (témoin)"),
                AuditEvent::OutputConfirmed {
                    basis: ChargeBasis::ClientSigned,
                    ..
                } => self.bump("provisoires confirmées par le client"),
                AuditEvent::OutputConfirmed {
                    basis: ChargeBasis::WindowExpired,
                    ..
                } => self.bump("provisoires confirmées par expiration de fenêtre"),
                AuditEvent::Replayed { .. } => self.bump("sorties rejouées"),
                AuditEvent::OutputVoided { .. } => self.bump("sorties annulées (retour arrière)"),
                AuditEvent::Rewound { .. } => self.bump("retours arrière"),
                AuditEvent::ItemPaid {
                    kind: ItemKind::Contribution(_),
                    by_arbitration: false,
                    ..
                } => self.bump("paiements de contributions"),
                AuditEvent::ItemPaid {
                    kind: ItemKind::Recovery(_),
                    by_arbitration: false,
                    ..
                } => self.bump("paiements de récupération"),
                AuditEvent::ItemPaid {
                    by_arbitration: true,
                    ..
                } => self.bump("paiements par arbitrage"),
                AuditEvent::ItemRefunded {
                    reason: RefundReason::Arbitration,
                    ..
                } => self.bump("remboursements par arbitrage"),
                AuditEvent::ItemRefunded {
                    reason: RefundReason::OutputVoided,
                    ..
                } => self.bump("contributions annulées avec leur sortie"),
                AuditEvent::ItemRefunded { .. } => self.bump("éléments remboursés faute de preuve"),
                AuditEvent::ItemDisputed { .. } => self.bump("éléments contestés"),
                AuditEvent::ItemAwaitingDelivery { .. } => {
                    self.bump("contributions en attente de livraison")
                }
                AuditEvent::RewardContested { .. } => self.bump("contestations de récompense"),
                AuditEvent::RewardReleased { .. } => self.bump("récompenses libérées"),
                AuditEvent::ContestOpened { .. } => {
                    self.bump("contestations de livraison ouvertes")
                }
                AuditEvent::LateDelivery { .. } => self.bump("attestations tardives admises"),
                AuditEvent::BufferPurged { .. } => self.bump("tampons purgés après rétention"),
                AuditEvent::EvidenceSupplemented { .. } => self.bump("preuves complémentaires"),
                _ => {}
            }
        }
    }

    pub fn merge(&mut self, o: &Stats) {
        self.traces += o.traces;
        self.commands += o.commands;
        self.accepted += o.accepted;
        for (k, n) in &o.counts {
            *self.counts.entry(k).or_default() += n;
        }
        for (k, n) in &o.refusals {
            *self.refusals.entry(k.clone()).or_default() += n;
        }
    }

    pub fn render(&self, name: &str) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# {name}");
        let _ = writeln!(s, "traces\t{}", self.traces);
        let _ = writeln!(s, "commandes exécutées et vérifiées\t{}", self.commands);
        let _ = writeln!(s, "dont acceptées\t{}", self.accepted);
        for (k, n) in &self.counts {
            let _ = writeln!(s, "{k}\t{n}");
        }
        for (k, n) in &self.refusals {
            let _ = writeln!(s, "refus {k}\t{n}");
        }
        s
    }

    /// Écrit les mesures dans `target/coverage/<name>.tsv`.
    pub fn write(&self, name: &str) {
        let dir = std::path::Path::new("target/coverage");
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(dir.join(format!("{name}.tsv")), self.render(name));
    }
}
