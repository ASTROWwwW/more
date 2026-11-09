//! Ledger trust domain (spec section 7): double-entry, append-only, hash-chained journal.
//!
//! Only this crate writes balances. The journal's `transfer` is private to the crate; every other
//! crate goes through [`LedgerService::execute`], which authenticates the calling service and only
//! accepts typed operations with fixed account flows.
//!
//! ```compile_fail
//! // A generic transfer is not reachable from outside the crate.
//! fn steal(l: &mut gpu_ledger::Ledger) {
//!     l.transfer("k", gpu_ledger::Account::User(1), gpu_ledger::Account::User(2), 5, "x");
//! }
//! ```

mod accounts;
mod hashing;
mod journal;
mod service;

pub use accounts::Account;
pub use journal::{Entry, Ledger, LedgerError, LedgerViolation};
pub use service::{
    Denial, Escrow, EscrowBucket, IssueTo, LedgerApiError, LedgerLimits, LedgerOp, LedgerOutcome,
    LedgerService, LineRef, LineSource,
};

/// Amount in the smallest credit unit. Never floats (LEDGER-009).
pub type Amount = u64;
