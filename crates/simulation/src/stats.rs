//! Coverage figures, computed on the traces the property tests actually run.

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
                } => self.bump("resumes (running → recovering)"),
                AuditEvent::AttemptStarted { attempt, .. } if *attempt >= 2 => {
                    self.bump("attempts ≥ 2 started")
                }
                AuditEvent::OutputCharged {
                    provisional: false, ..
                } => self.bump("outputs charged on ack"),
                AuditEvent::OutputCharged {
                    provisional: true, ..
                } => self.bump("outputs charged provisionally (witness)"),
                AuditEvent::OutputConfirmed {
                    basis: ChargeBasis::ClientSigned,
                    ..
                } => self.bump("provisional confirmed by client"),
                AuditEvent::OutputConfirmed {
                    basis: ChargeBasis::WindowExpired,
                    ..
                } => self.bump("provisional confirmed by window expiry"),
                AuditEvent::Replayed { .. } => self.bump("outputs replayed"),
                AuditEvent::OutputVoided { .. } => self.bump("outputs voided (rewind)"),
                AuditEvent::Rewound { .. } => self.bump("rewinds"),
                AuditEvent::ItemPaid {
                    kind: ItemKind::Contribution(_),
                    by_arbitration: false,
                    ..
                } => self.bump("contribution payments"),
                AuditEvent::ItemPaid {
                    kind: ItemKind::Recovery(_),
                    by_arbitration: false,
                    ..
                } => self.bump("recovery payments"),
                AuditEvent::ItemPaid {
                    by_arbitration: true,
                    ..
                } => self.bump("payments by arbitration"),
                AuditEvent::ItemRefunded {
                    reason: RefundReason::Arbitration,
                    ..
                } => self.bump("refunds by arbitration"),
                AuditEvent::ItemRefunded {
                    reason: RefundReason::OutputVoided,
                    ..
                } => self.bump("contributions voided with their output"),
                AuditEvent::ItemRefunded { .. } => self.bump("items refunded for missing proof"),
                AuditEvent::ItemDisputed { .. } => self.bump("items disputed"),
                AuditEvent::ItemAwaitingDelivery { .. } => {
                    self.bump("contributions awaiting delivery")
                }
                AuditEvent::RewardContested { .. } => self.bump("reward contests"),
                AuditEvent::RewardReleased { .. } => self.bump("rewards released"),
                AuditEvent::ContestOpened { .. } => self.bump("delivery contests opened"),
                AuditEvent::LateDelivery { .. } => self.bump("late attestations admitted"),
                AuditEvent::BufferPurged { .. } => self.bump("buffers purged after retention"),
                AuditEvent::EvidenceSupplemented { .. } => self.bump("supplementary proofs"),
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
        let _ = writeln!(s, "commands run and checked\t{}", self.commands);
        let _ = writeln!(s, "accepted\t{}", self.accepted);
        for (k, n) in &self.counts {
            let _ = writeln!(s, "{k}\t{n}");
        }
        for (k, n) in &self.refusals {
            let _ = writeln!(s, "rejected {k}\t{n}");
        }
        s
    }

    /// Writes the figures to `target/coverage/<name>.tsv`.
    pub fn write(&self, name: &str) {
        let dir = std::path::Path::new("target/coverage");
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(dir.join(format!("{name}.tsv")), self.render(name));
    }
}
