//! Simulation : horloge contrôlée, opérations aléatoires et adverses,
//! vérificateur d'invariants. Aucune dépendance au réseau ni à une base.

pub mod invariants;
pub mod stats;
pub mod world;

pub use invariants::{check_fairness, check_state, check_step, Violation};
pub use stats::Stats;
pub use world::{
    op_strategy, setup_commands, sim_config, Op, Sim, BORROWERS, CREDIT_POOL, FREE_POOL, JOBS,
    LENDERS, WITNESS,
};
