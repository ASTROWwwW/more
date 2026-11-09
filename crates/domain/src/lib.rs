//! Domaine du réseau GPU P2P : machine à états des jobs (section 2.1), cycle
//! de vie des tranches (2.2), statut de règlement (2.3) et règles globales (3)
//! de la spécification v2.3.
//!
//! Aucune dépendance au réseau, à la base de données ni au moteur GPU : ce sont
//! des fonctions de transition pures, réutilisables telles quelles par le
//! futur coordinateur (qui ajoutera la persistance et l'outbox).

pub mod command;
pub mod config;
pub mod coordinator;
pub mod error;
pub mod ids;
pub mod model;

pub use command::{Command, IssueTarget, Outcome};
pub use config::Config;
pub use coordinator::{AuditEvent, Coordinator};
pub use error::DomainError;
pub use gpu_ledger::{Account, Amount, Ledger};
pub use ids::*;
pub use model::*;
