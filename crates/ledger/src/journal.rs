//! Append-only, hash-chained journal (LEDGER-001 to LEDGER-007). Writes are private to this
//! crate: other crates go through [`crate::LedgerService`].

use std::collections::BTreeMap;
use std::fmt;

use crate::hashing::{entry_hash, FNV_OFFSET};
use crate::{Account, Amount};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub key: String,
    pub from: Account,
    pub to: Account,
    pub amount: Amount,
    pub reason: &'static str,
    pub prev_hash: u64,
    pub hash: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// Key already used: the entry was already applied (LEDGER-001).
    DuplicateKey(String),
    /// The entry would make an account negative (LEDGER-005, JOB-R07).
    InsufficientFunds {
        account: Account,
        balance: Amount,
        requested: Amount,
    },
    /// Zero amount or self-transfer.
    Invalid(&'static str),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerError {}

/// Ledger invariant violation found by [`Ledger::check_invariants`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerViolation {
    SumNotZero(i128),
    NegativeBalance(Account, i128),
    BalanceMismatch(Account, i128, i128),
    BrokenChain(u64),
    DuplicateKeyInJournal(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    entries: Vec<Entry>,
    balances: BTreeMap<Account, i128>,
    keys: BTreeMap<String, u64>,
    /// Test only: entries left before the journal fails once.
    #[cfg(feature = "fault-injection")]
    fail_in: Option<u64>,
}

impl Ledger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub fn balance(&self, account: Account) -> i128 {
        self.balances.get(&account).copied().unwrap_or(0)
    }

    /// Balance of an account that cannot go negative.
    pub fn available(&self, account: Account) -> Amount {
        let b = self.balance(account);
        debug_assert!(b >= 0 || account.may_go_negative());
        u64::try_from(b.max(0)).unwrap_or(u64::MAX)
    }

    pub fn has_key(&self, key: &str) -> bool {
        self.keys.contains_key(key)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn accounts(&self) -> impl Iterator<Item = (&Account, &i128)> {
        self.balances.iter()
    }

    /// Credits in circulation (issued minus burned).
    pub fn circulating(&self) -> i128 {
        -self.balance(Account::Issuance) - self.balance(Account::Burn)
    }

    /// Moves `amount` from `from` to `to`. A zero amount is accepted and writes nothing (free
    /// pools). Private to the crate: see [`crate::LedgerService`].
    pub(crate) fn transfer(
        &mut self,
        key: impl Into<String>,
        from: Account,
        to: Account,
        amount: Amount,
        reason: &'static str,
    ) -> Result<(), LedgerError> {
        if amount == 0 {
            return Ok(());
        }
        if from == to {
            return Err(LedgerError::Invalid("from == to"));
        }
        let key = key.into();
        if self.keys.contains_key(&key) {
            return Err(LedgerError::DuplicateKey(key));
        }
        let bal = self.balance(from);
        if !from.may_go_negative() && bal < i128::from(amount) {
            return Err(LedgerError::InsufficientFunds {
                account: from,
                balance: u64::try_from(bal.max(0)).unwrap_or(0),
                requested: amount,
            });
        }
        #[cfg(feature = "fault-injection")]
        match self.fail_in {
            Some(0) => return Err(LedgerError::Invalid("injected fault")),
            Some(n) => self.fail_in = Some(n - 1),
            None => {}
        }
        let seq =
            u64::try_from(self.entries.len()).map_err(|_| LedgerError::Invalid("journal full"))?;
        let prev_hash = self.entries.last().map_or(FNV_OFFSET, |e| e.hash);
        let hash = entry_hash(prev_hash, seq, &key, from, to, amount);
        self.add(from, -i128::from(amount));
        self.add(to, i128::from(amount));
        self.keys.insert(key.clone(), seq);
        self.entries.push(Entry {
            seq,
            key,
            from,
            to,
            amount,
            reason,
            prev_hash,
            hash,
        });
        Ok(())
    }

    /// Test only: the journal accepts `after` more entries, then refuses every entry until the
    /// fault is cleared with `None`.
    #[cfg(feature = "fault-injection")]
    pub(crate) fn inject_fault(&mut self, after: Option<u64>) {
        self.fail_in = after;
    }

    /// Journal length, to roll back a multi-entry operation that fails half way.
    pub(crate) fn mark(&self) -> usize {
        self.entries.len()
    }

    /// Undoes every entry written after `mark` (still uncommitted: the service rolls back before
    /// returning an error, so these entries were never visible to a caller).
    pub(crate) fn rollback(&mut self, mark: usize) {
        while self.entries.len() > mark {
            let Some(e) = self.entries.pop() else { break };
            self.add(e.from, i128::from(e.amount));
            self.add(e.to, -i128::from(e.amount));
            self.keys.remove(&e.key);
        }
    }

    /// Balances never store zero, so a rolled-back operation leaves the map exactly as before.
    fn add(&mut self, account: Account, delta: i128) {
        let b = self.balances.entry(account).or_insert(0);
        *b += delta;
        if *b == 0 {
            self.balances.remove(&account);
        }
    }

    /// Checks LEDGER-001, 002, 004, 005 and 006 by recomputing everything from the journal.
    pub fn check_invariants(&self) -> Vec<LedgerViolation> {
        let mut out = Vec::new();
        let mut recomputed: BTreeMap<Account, i128> = BTreeMap::new();
        let mut seen = BTreeMap::new();
        let mut prev = FNV_OFFSET;
        for e in &self.entries {
            if e.prev_hash != prev
                || e.hash != entry_hash(prev, e.seq, &e.key, e.from, e.to, e.amount)
            {
                out.push(LedgerViolation::BrokenChain(e.seq));
            }
            prev = e.hash;
            if seen.insert(e.key.clone(), ()).is_some() {
                out.push(LedgerViolation::DuplicateKeyInJournal(e.key.clone()));
            }
            *recomputed.entry(e.from).or_insert(0) -= i128::from(e.amount);
            *recomputed.entry(e.to).or_insert(0) += i128::from(e.amount);
        }
        let sum: i128 = self.balances.values().sum();
        if sum != 0 {
            out.push(LedgerViolation::SumNotZero(sum));
        }
        for (a, b) in &self.balances {
            if *b < 0 && !a.may_go_negative() {
                out.push(LedgerViolation::NegativeBalance(*a, *b));
            }
            let r = recomputed.get(a).copied().unwrap_or(0);
            if r != *b {
                out.push(LedgerViolation::BalanceMismatch(*a, *b, r));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_moves_and_preserves_sum() {
        let mut l = Ledger::new();
        l.transfer("i1", Account::Issuance, Account::User(1), 100, "issue")
            .unwrap();
        l.transfer(
            "t1",
            Account::User(1),
            Account::EscrowWork(7),
            60,
            "reserve",
        )
        .unwrap();
        assert_eq!(l.balance(Account::User(1)), 40);
        assert_eq!(l.balance(Account::EscrowWork(7)), 60);
        assert_eq!(l.circulating(), 100);
        assert!(l.check_invariants().is_empty());
    }

    #[test]
    fn duplicate_key_is_rejected_and_changes_nothing() {
        let mut l = Ledger::new();
        l.transfer("k", Account::Issuance, Account::User(1), 10, "issue")
            .unwrap();
        let before = l.clone();
        assert_eq!(
            l.transfer("k", Account::Issuance, Account::User(1), 10, "issue"),
            Err(LedgerError::DuplicateKey("k".into()))
        );
        assert_eq!(l, before);
    }

    #[test]
    fn no_negative_balance_except_issuance() {
        let mut l = Ledger::new();
        let err = l
            .transfer("k", Account::User(1), Account::User(2), 1, "x")
            .unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
        assert!(l.entries().is_empty());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let mut l = Ledger::new();
        l.transfer("a", Account::Issuance, Account::User(1), 10, "issue")
            .unwrap();
        l.transfer("b", Account::User(1), Account::User(2), 5, "pay")
            .unwrap();
        l.entries[0].amount = 11;
        assert!(l
            .check_invariants()
            .iter()
            .any(|v| matches!(v, LedgerViolation::BrokenChain(_))));
    }

    #[test]
    fn zero_amount_writes_nothing() {
        let mut l = Ledger::new();
        l.transfer("z", Account::User(1), Account::User(2), 0, "free pool")
            .unwrap();
        assert!(l.entries().is_empty());
        assert!(!l.has_key("z"));
    }
}
