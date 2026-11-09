//! Timeouts and limits (spec section 3). Initial values, to be tuned on a real cluster.

use crate::ids::{PerType, Time};
use gpu_ledger::Amount;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Flow budgets `K_prefill`, `K_generate`, `K_batch` (JOB-R16).
    pub flow_budget: PerType<u32>,
    /// Commission in basis points, taken when a reward is released.
    pub commission_bps: u64,
    /// Recovery budget, as a percentage of the estimated cost (JOB-R18).
    pub recovery_budget_pct: u64,
    pub max_attempts: u32,
    pub max_placement_failures: u32,
    /// Cap on payments backed by uncommitted receipts, per account (JOB-R19).
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
    /// Single contest window for held rewards (JOB-R22).
    pub reward_window: Time,
    /// Maximum initial work reserve (JOB-T02); beyond it the job runs on top-ups (JOB-T12).
    /// `Amount::MAX` means the full estimated cost.
    pub initial_reserve_max: Amount,
    /// Lease lifetime without renewal (JOB-R31).
    pub lease_ttl: Time,
    /// Contest window for an attested delivery, opened when the producing attempt is revoked
    /// (JOB-R29). Also the minimum replay buffer retention (JOB-R28).
    pub delivery_window: Time,
    /// Time to resolve an open contest (JOB-R33).
    pub contest_resolution: Time,
    /// Sliding window of the anti-collusion cap (JOB-R19).
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
