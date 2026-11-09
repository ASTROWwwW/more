//! Délais et limites (spécification v2.5, section 3, « Délais et limites »).
//! Valeurs initiales, à calibrer sur grappe réelle.

use crate::ids::{PerType, Time};
use gpu_ledger::Amount;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Budgets de flux `K_prefill`, `K_generate`, `K_batch` (JOB-R16).
    pub flow_budget: PerType<u32>,
    /// Commission en points de base, prélevée à la libération d'une récompense.
    pub commission_bps: u64,
    /// Budget de récupération, en pourcentage du coût estimé (JOB-R18).
    pub recovery_budget_pct: u64,
    pub max_attempts: u32,
    pub max_placement_failures: u32,
    /// Plafond payable sur reçus non engagés, par compte (JOB-R19).
    pub uncommitted_cap: Amount,
    pub placing_timeout: Time,
    pub recovery_timeout: Time,
    pub queued_wait: Time,
    pub reserved_wait: Time,
    pub client_silence: Time,
    pub drain_window: Time,
    pub evaluation_deadline: Time,
    pub dispute_deadline: Time,
    pub pause_max: Time,
    /// Fenêtre unique de contestation des récompenses retenues (JOB-R22).
    pub reward_window: Time,
    /// Réserve initiale maximale de la part « travail » (JOB-T02). Au-delà, le
    /// job avance par compléments (JOB-T12). `Amount::MAX` = coût estimé complet.
    pub initial_reserve_max: Amount,
    /// Durée d'une autorisation sans renouvellement (JOB-R31).
    pub lease_ttl: Time,
    /// Fenêtre de contestation d'une livraison attestée, ouverte à la
    /// révocation de la tentative qui l'a produite (JOB-R29). C'est aussi la
    /// durée minimale de conservation du tampon de rejeu (JOB-R28).
    pub delivery_window: Time,
    /// Délai de résolution d'une contestation ouverte (JOB-R33).
    pub contest_resolution: Time,
    /// Fenêtre glissante du plafond anti-collusion (JOB-R19).
    pub uncommitted_window: Time,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            flow_budget: [1, 4, 1],
            commission_bps: 1_000,
            recovery_budget_pct: 10,
            max_attempts: 8,
            max_placement_failures: 5,
            uncommitted_cap: 50,
            placing_timeout: 60,
            recovery_timeout: 120,
            queued_wait: 900,
            reserved_wait: 900,
            client_silence: 60,
            drain_window: 120,
            evaluation_deadline: 600,
            dispute_deadline: 48 * 3600,
            pause_max: 30 * 24 * 3600,
            reward_window: 48 * 3600,
            initial_reserve_max: Amount::MAX,
            lease_ttl: 45,
            delivery_window: 24 * 3600,
            contest_resolution: 3600,
            uncommitted_window: 24 * 3600,
        }
    }
}
