//! Simulation: controlled clock, random and adversarial operations, invariant checker. No network,
//! no database.

pub mod invariants;
pub mod stats;
pub mod world;

pub use invariants::{check_fairness, check_state, check_step, Violation};
pub use stats::Stats;
pub use world::{
    all_segments, assignment_of, bring_up, catalog, corroborate, layout_of, mandate, op_strategy,
    readiness_of, restoration_of, segment_commitments, setup_commands, sim_config, sim_domain,
    state_commitment, user_key, Op, Sim, SimIdentity, BORROWERS, CREDIT_POOL, FREE_POOL, JOBS,
    LENDERS, POOL_ADMIN, SEGMENTS, STRANGER, UNSET_CONFIG, UNSET_STATE, UNSIGNED, WITNESS,
};
