//! Registre comptable en partie double (spécification v2.3, section 7).
//!
//! Chaque écriture déplace un montant d'un compte vers un autre : rien n'est
//! créé ni détruit, sauf par les comptes `Issuance` (seul compte autorisé à
//! devenir négatif, LEDGER-003) et `Burn`. Les écritures sont en insertion
//! seule (LEDGER-002), portent une clé d'idempotence unique (LEDGER-001) et
//! sont chaînées par empreinte (LEDGER-006).
//!
//! Le modèle n'utilise aucune base de données : l'atomicité d'une transition
//! (JOB-R01) est obtenue en appliquant toute la transition sur une copie de
//! l'état et en ne la conservant qu'en cas de succès.

use std::collections::BTreeMap;
use std::fmt;

/// Montant en plus petite unité de crédit. Jamais de flottants (LEDGER, à décider → tranché ici).
pub type Amount = u64;

/// Comptes du registre. Les identifiants sont des entiers bruts pour que la
/// crate ne dépende pas du domaine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Account {
    /// Seul compte qui crée des crédits. Son solde est l'opposé du total émis.
    Issuance,
    /// Crédits retirés de la circulation.
    Burn,
    /// Solde disponible d'un utilisateur.
    User(u32),
    /// Trésorerie d'un pool (amorçage, relais du budget de récupération).
    PoolReserve(u32),
    /// Escrow d'un job : part « travail normal ».
    EscrowWork(u32),
    /// Escrow d'un job : part « budget de récupération » (JOB-R18).
    EscrowRecovery(u32),
    /// Prix des sorties validées d'un job, en attente de répartition entre contributions.
    OutputHold(u32),
    /// Réserve d'une ligne de tranche `(job, tentative, tranche, prêteur)`.
    SliceLine {
        job: u32,
        attempt: u32,
        slice: u32,
        lender: u32,
    },
    /// Récompenses retenues d'une ligne pendant la fenêtre de contestation.
    PendingReward {
        job: u32,
        attempt: u32,
        slice: u32,
        lender: u32,
    },
    /// Commissions de la plateforme ou du pool.
    Commission,
}

impl Account {
    /// Un seul compte peut être négatif : l'émission.
    pub fn may_go_negative(self) -> bool {
        matches!(self, Account::Issuance)
    }
}

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
    /// Clé déjà utilisée : l'écriture a déjà eu lieu (LEDGER-001).
    DuplicateKey(String),
    /// L'écriture rendrait un compte négatif (LEDGER-005 / JOB-R07).
    InsufficientFunds {
        account: Account,
        balance: Amount,
        requested: Amount,
    },
    /// Montant nul ou écriture d'un compte vers lui-même.
    Invalid(&'static str),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerError {}

/// Violation d'un invariant du registre, détectée par [`Ledger::check_invariants`].
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
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Empreinte d'une écriture. FNV-1a suffit pour le modèle (détection
/// d'altération accidentelle) ; le coordinateur réel utilisera une fonction
/// cryptographique (SHA-256 ou BLAKE3).
fn entry_hash(prev: u64, seq: u64, key: &str, from: Account, to: Account, amount: Amount) -> u64 {
    let mut h = fnv(FNV_OFFSET, &prev.to_le_bytes());
    h = fnv(h, &seq.to_le_bytes());
    h = fnv(h, key.as_bytes());
    h = fnv(h, format!("{from:?}>{to:?}").as_bytes());
    fnv(h, &amount.to_le_bytes())
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn balance(&self, account: Account) -> i128 {
        self.balances.get(&account).copied().unwrap_or(0)
    }

    /// Solde d'un compte qui ne peut pas être négatif.
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

    /// Total des crédits en circulation (= crédits émis − crédits détruits).
    pub fn circulating(&self) -> i128 {
        -self.balance(Account::Issuance) - self.balance(Account::Burn)
    }

    /// Déplace `amount` de `from` vers `to`. Un montant nul est accepté et
    /// n'écrit rien (pools en partage libre), pour garder les appelants simples.
    pub fn transfer(
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
        let seq = self.entries.len() as u64;
        let prev_hash = self.entries.last().map_or(FNV_OFFSET, |e| e.hash);
        let hash = entry_hash(prev_hash, seq, &key, from, to, amount);
        *self.balances.entry(from).or_insert(0) -= i128::from(amount);
        *self.balances.entry(to).or_insert(0) += i128::from(amount);
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

    /// Vérifie LEDGER-001, 002, 004, 005 et 006 en recalculant tout depuis le journal.
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
