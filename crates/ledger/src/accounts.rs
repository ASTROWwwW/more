//! Ledger accounts (spec section 7).

/// Raw integer ids keep this crate independent of the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Account {
    /// The only account that creates credits; its balance is minus the total issued.
    Issuance,
    /// Credits removed from circulation.
    Burn,
    /// A user's available balance.
    User(u32),
    /// Pool treasury (bootstrap, recovery budget relay).
    PoolReserve(u32),
    /// Job escrow: regular work.
    EscrowWork(u32),
    /// Job escrow: recovery budget (JOB-R18).
    EscrowRecovery(u32),
    /// Price of a job's charged outputs, waiting to be split among contributions.
    OutputHold(u32),
    /// Reserve of a slice line `(job, attempt, slice, lender)`.
    SliceLine {
        job: u32,
        attempt: u32,
        slice: u32,
        lender: u32,
    },
    /// Rewards of a line held during the contest window.
    PendingReward {
        job: u32,
        attempt: u32,
        slice: u32,
        lender: u32,
    },
    /// Platform or pool commissions.
    Commission,
}

impl Account {
    /// Only issuance may go negative.
    pub fn may_go_negative(self) -> bool {
        matches!(self, Account::Issuance)
    }
}
