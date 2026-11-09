//! Simulation: controlled clock, random and adversarial operations, invariant checker. No network,
//! no database.

pub mod invariants;
pub mod stats;
pub mod world;

pub use invariants::{check_fairness, check_state, check_step, Violation};
pub use stats::Stats;
pub use world::{
    op_strategy, setup_commands, sim_config, Op, Sim, BORROWERS, CREDIT_POOL, FREE_POOL, JOBS,
    LENDERS, WITNESS,
};
