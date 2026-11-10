//! The simulated world: pools, members, catalog, accounts, jobs.

use super::*;

pub const CREDIT_POOL: PoolId = PoolId(1);
pub const FREE_POOL: PoolId = PoolId(2);
pub const BORROWERS: [AccountId; 2] = [AccountId(1), AccountId(2)];
pub const LENDERS: [AccountId; 4] = [AccountId(10), AccountId(11), AccountId(12), AccountId(13)];
pub const JOBS: [JobId; 3] = [JobId(1), JobId(2), JobId(3)];
/// Delivery witness (relay), independent of lenders and borrowers (JOB-R26).
pub const WITNESS: AccountId = AccountId(90);
/// Admin of both pools: members, catalog, arbitration, pool relay.
pub const POOL_ADMIN: AccountId = AccountId(80);
/// An authenticated account with no right anywhere.
pub const STRANGER: AccountId = AccountId(66);

/// Catalog of the simulated pools: (pool, model, spec).
pub fn catalog() -> [(PoolId, ModelId, ModelSpec); 3] {
    [
        // Job 1's model: 6 layers, divisible prices.
        (
            CREDIT_POOL,
            ModelId(1),
            ModelSpec {
                layers: 6,
                price: [6, 12, 3],
                max_outputs: [4, 12, 3],
            },
        ),
        // Job 2's model: prices with rounding (7 / 2).
        (
            CREDIT_POOL,
            ModelId(2),
            ModelSpec {
                layers: 4,
                price: [4, 7, 2],
                max_outputs: [2, 8, 2],
            },
        ),
        // Job 3's model, in the free pool.
        (
            FREE_POOL,
            ModelId(3),
            ModelSpec {
                layers: 2,
                price: [0; 3],
                max_outputs: [1, 6, 1],
            },
        ),
    ]
}

/// Layout the simulated scheduler uses for each job.
pub fn layout_of(job: JobId) -> Vec<u32> {
    match job.0 {
        1 => vec![3, 2, 1],
        2 => vec![2, 2],
        _ => vec![1, 1],
    }
}

/// Deterministic signing key of a simulated account.
pub fn user_key(a: AccountId) -> UserKey {
    let mut seed = [0x5au8; 32];
    seed[..4].copy_from_slice(&a.0.to_le_bytes());
    UserKey::from_seed(seed)
}

/// Mandate signed by `borrower` for `job` under the pool's current tariff for `model` (checked by
/// the ledger, JOB-R37).
pub fn mandate(
    job: JobId,
    pool: PoolId,
    borrower: AccountId,
    model: ModelId,
    outputs: PerType<u32>,
    max_budget: Amount,
) -> [u8; 64] {
    let spec = catalog()
        .into_iter()
        .find(|(p, m, _)| *p == pool && *m == model)
        .map_or(
            ModelSpec {
                layers: 0,
                price: [0; 3],
                max_outputs: [0; 3],
            },
            |(_, _, s)| s,
        );
    let terms = JobTerms {
        model: model.0,
        layers: spec.layers,
        price: spec.price,
        max_outputs: outputs,
        max_budget,
    };
    user_key(borrower).sign(&mandate_message(job.0, pool.0, borrower.0, &terms))
}

/// JOB-R38: every lender of the attempt accepts its lease, loads its layers and reports its state
/// restored to `restored`, in that order. Statements are signed by the sending lender.
pub fn bring_up(
    job: JobId,
    attempt: u32,
    lenders: &[AccountId],
    restored: PerType<u32>,
) -> Vec<Command> {
    let mut v = Vec::new();
    for l in lenders {
        v.push(Command::AcceptLease {
            job,
            attempt,
            lender: *l,
            signature: UNSIGNED,
        });
        v.push(Command::LeaseLoaded {
            job,
            attempt,
            lender: *l,
            config: UNSET_CONFIG,
        });
    }
    for l in lenders {
        v.push(Command::AttemptReady {
            job,
            attempt,
            lender: *l,
            restored,
            signature: UNSIGNED,
        });
    }
    v
}

/// Setup commands: pools, members, catalog, issuance, job submissions.
pub fn setup_commands() -> Vec<Command> {
    let mut v = vec![
        Command::CreatePool {
            pool: CREDIT_POOL,
            mode: PoolMode::Credits,
            access: PoolAccess::Private,
            admin: POOL_ADMIN,
        },
        Command::CreatePool {
            pool: FREE_POOL,
            mode: PoolMode::FreeShare {
                quota_per_borrower: 1,
            },
            access: PoolAccess::Private,
            admin: POOL_ADMIN,
        },
    ];
    for pool in [CREDIT_POOL, FREE_POOL] {
        let mut grant = |account, borrow, lend, witness| {
            v.push(Command::SetRights {
                pool,
                account,
                rights: Rights {
                    borrow,
                    lend,
                    witness,
                },
            })
        };
        for b in BORROWERS {
            grant(b, true, false, false);
        }
        for l in LENDERS {
            // LENDERS[0] may also witness, so placing it as the witness of its own attempt reaches
            // the independence check (JOB-R26).
            grant(l, false, true, l == LENDERS[0]);
        }
        grant(WITNESS, false, false, true);
    }
    for (pool, model, spec) in catalog() {
        v.push(Command::RegisterModel { pool, model, spec });
    }
    v.extend([
        Command::Issue {
            id: 1,
            to: IssueTarget::User(BORROWERS[0]),
            amount: 2_000,
        },
        Command::Issue {
            id: 2,
            to: IssueTarget::User(BORROWERS[1]),
            amount: 2_000,
        },
        Command::Issue {
            id: 3,
            to: IssueTarget::Pool(CREDIT_POOL),
            amount: 300,
        },
    ]);
    for (job, borrower, pool, model, outputs, budget) in [
        (
            JOBS[0],
            BORROWERS[0],
            CREDIT_POOL,
            ModelId(1),
            [4, 12, 3],
            1_000,
        ),
        (
            JOBS[1],
            BORROWERS[1],
            CREDIT_POOL,
            ModelId(2),
            [2, 8, 2],
            1_000,
        ),
        (JOBS[2], BORROWERS[0], FREE_POOL, ModelId(3), [1, 6, 1], 0),
    ] {
        v.push(Command::Submit {
            job,
            borrower,
            pool,
            model,
            outputs,
            max_budget: budget,
            mandate: mandate(job, pool, borrower, model, outputs, budget),
        });
    }
    v
}

/// Simulation config: spec values, except the anti-collusion cap, lowered to 4 credits per sliding
/// 24 h so simulated prices reach it and disputes get exercised.
pub fn sim_config() -> Config {
    Config {
        uncommitted_cap: 4,
        ..Config::default()
    }
}
