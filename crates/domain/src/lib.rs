//! Domain of More: job state machine, slice lifecycle, settlement and global rules of the spec. No
//! network, database or GPU engine: pure transition functions, meant to be reused as is by the real
//! coordinator (which will add persistence and the outbox).

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
