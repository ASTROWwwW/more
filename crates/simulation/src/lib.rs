//! Simulation: controlled clock, random and adversarial operations, invariant checker. No network,
//! no database.

pub mod invariants;
pub mod stats;
pub mod world;

pub use invariants::{check_fairness, check_state, check_step, Violation};
pub use stats::Stats;
pub use world::{
    catalog, layout_of, mandate, op_strategy, setup_commands, sim_config, user_key, Op, Sim,
    SimIdentity, BORROWERS, CREDIT_POOL, FREE_POOL, JOBS, LENDERS, POOL_ADMIN, STRANGER, WITNESS,
};
