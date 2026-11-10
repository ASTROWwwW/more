//! Model Registry trust domain: pools, membership rights, model catalog and tariffs (SEC-002,
//! SEC-003). Pool data is private to this module: other code reads it and asks for changes through
//! the methods below, which validate every input.

use std::collections::{BTreeMap, BTreeSet};

use gpu_ledger::Amount;

use crate::command::Outcome;
use crate::config::{MAX_LAYERS, MAX_OUTPUTS, MAX_PRICE};
use crate::error::DomainError;
use crate::ids::*;

type R<T = ()> = Result<T, DomainError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    Credits,
    /// Free sharing: no credits, a quota of active jobs per borrower.
    FreeShare {
        quota_per_borrower: u32,
    },
}

/// Who may join a pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolAccess {
    /// Rights are granted by the pool's admins only.
    Private,
    /// Any authenticated account may join to borrow and lend. Witnessing is always granted by an
    /// admin.
    Open,
}

/// What an account may do in a pool. Nothing is implied by an account merely existing (SEC-003).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rights {
    pub borrow: bool,
    pub lend: bool,
    pub witness: bool,
}

impl Rights {
    pub const NONE: Rights = Rights {
        borrow: false,
        lend: false,
        witness: false,
    };
}

/// Catalog entry: the model's size and the pool's tariff for it. The client never sets a price
/// (SEC-002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelSpec {
    pub layers: u32,
    /// Price of one output per work type. Zero in a free-sharing pool.
    pub price: PerType<Amount>,
    /// Most outputs a job may ask for, per type.
    pub max_outputs: PerType<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    id: PoolId,
    mode: PoolMode,
    access: PoolAccess,
    admins: BTreeSet<AccountId>,
    members: BTreeMap<AccountId, Rights>,
    models: BTreeMap<ModelId, ModelSpec>,
}

impl Pool {
    pub fn id(&self) -> PoolId {
        self.id
    }

    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    pub fn access(&self) -> PoolAccess {
        self.access
    }

    pub fn admins(&self) -> &BTreeSet<AccountId> {
        &self.admins
    }

    pub fn members(&self) -> &BTreeMap<AccountId, Rights> {
        &self.members
    }

    pub fn model(&self, id: ModelId) -> Option<&ModelSpec> {
        self.models.get(&id)
    }

    pub fn is_credits(&self) -> bool {
        matches!(self.mode, PoolMode::Credits)
    }

    pub fn rights(&self, account: AccountId) -> Rights {
        self.members.get(&account).copied().unwrap_or(Rights::NONE)
    }

    pub fn is_admin(&self, account: AccountId) -> bool {
        self.admins.contains(&account)
    }
}

/// Every pool of this coordinator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pools: BTreeMap<PoolId, Pool>,
    /// Log position of the last time an account lost its lend right (`false`) or its witness
    /// right (`true`) in a pool (CE-03).
    lost: BTreeMap<(PoolId, AccountId, bool), u64>,
}

impl Registry {
    pub fn pools(&self) -> &BTreeMap<PoolId, Pool> {
        &self.pools
    }

    pub fn pool(&self, id: PoolId) -> R<&Pool> {
        self.pools.get(&id).ok_or(DomainError::UnknownPool)
    }

    /// `account` lost its lend right (or its witness right) in `pool` after log position `seq`.
    pub fn right_lost_since(
        &self,
        pool: PoolId,
        account: AccountId,
        witness: bool,
        seq: u64,
    ) -> bool {
        self.lost
            .get(&(pool, account, witness))
            .is_some_and(|at| *at > seq)
    }

    fn pool_mut(&mut self, id: PoolId) -> R<&mut Pool> {
        self.pools.get_mut(&id).ok_or(DomainError::UnknownPool)
    }

    pub(crate) fn create(
        &mut self,
        pool: PoolId,
        mode: PoolMode,
        access: PoolAccess,
        admin: AccountId,
    ) -> R<Outcome> {
        if let Some(p) = self.pools.get(&pool) {
            return if p.mode == mode && p.access == access && p.is_admin(admin) {
                Ok(Outcome::AlreadyApplied)
            } else {
                Err(DomainError::Precondition("pool id reused"))
            };
        }
        self.pools.insert(
            pool,
            Pool {
                id: pool,
                mode,
                access,
                admins: [admin].into_iter().collect(),
                members: BTreeMap::new(),
                models: BTreeMap::new(),
            },
        );
        Ok(Outcome::Applied)
    }

    pub(crate) fn set_rights(
        &mut self,
        pool: PoolId,
        account: AccountId,
        rights: Rights,
        seq: u64,
    ) -> R<Outcome> {
        let p = self.pool_mut(pool)?;
        let old = p.rights(account);
        if old == rights {
            return Ok(Outcome::AlreadyApplied);
        }
        // A withdrawal is kept with its position: granting the right again later does not make
        // what was signed in between admissible.
        for (witness, had, has) in [
            (false, old.lend, rights.lend),
            (true, old.witness, rights.witness),
        ] {
            if had && !has {
                self.lost.insert((pool, account, witness), seq);
            }
        }
        let p = self.pool_mut(pool)?;
        if rights == Rights::NONE {
            p.members.remove(&account);
        } else {
            p.members.insert(account, rights);
        }
        Ok(Outcome::Applied)
    }

    pub(crate) fn join(&mut self, pool: PoolId, account: AccountId) -> R<Outcome> {
        let p = self.pool_mut(pool)?;
        if p.access != PoolAccess::Open {
            return Err(DomainError::Precondition(
                "private pool: rights come from its admins",
            ));
        }
        let r = p.members.entry(account).or_insert(Rights::NONE);
        if r.borrow && r.lend {
            return Ok(Outcome::AlreadyApplied);
        }
        r.borrow = true;
        r.lend = true;
        Ok(Outcome::Applied)
    }

    /// Catalog and tariff, bounded so job costs cannot overflow (SAFE-001).
    pub(crate) fn register_model(
        &mut self,
        pool: PoolId,
        model: ModelId,
        spec: ModelSpec,
    ) -> R<Outcome> {
        let p = self.pool_mut(pool)?;
        if spec.layers == 0 || spec.layers > MAX_LAYERS {
            return Err(DomainError::InvalidInput("model layers out of range"));
        }
        if spec.price.iter().any(|x| *x > MAX_PRICE) {
            return Err(DomainError::InvalidInput("price above MAX_PRICE"));
        }
        if spec.max_outputs.iter().any(|x| *x > MAX_OUTPUTS) {
            return Err(DomainError::InvalidInput("max outputs above MAX_OUTPUTS"));
        }
        if !p.is_credits() && spec.price != [0; 3] {
            return Err(DomainError::InvalidInput(
                "a free-sharing pool has no tariff",
            ));
        }
        if p.models.get(&model) == Some(&spec) {
            return Ok(Outcome::AlreadyApplied);
        }
        p.models.insert(model, spec);
        Ok(Outcome::Applied)
    }
}
