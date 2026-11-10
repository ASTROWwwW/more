//! Shared world for the ledger's API tests: one owner, two honest lenders, an honest witness, a
//! bystander and an account held by the attacker.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use gpu_ledger::*;
use more_identity::{
    lease_message, mandate_message, ready_message, receipt_message, relay_message, restore_message,
    Domain, IdentityAuthority, KeyDirectory, Readiness, Restoration, ServiceCredential,
    ServiceRole, UserKey,
};

pub const ALICE: u32 = 1;
pub const BOB: u32 = 2;
pub const L1: u32 = 10;
pub const L2: u32 = 11;
pub const WIT: u32 = 30;
/// A registered account whose key the attacker holds.
pub const MALLORY: u32 = 66;
pub const POOL: u32 = 7;
/// Admin of the pool's treasury.
pub const ADMIN: u32 = 80;
pub const JOB: u32 = 1;
/// Output type used by the tests, priced 8.
pub const WT: u8 = 1;
/// Commitment an honest lender signs for its restored state in these tests.
pub const STATE: u64 = 0xabc;
/// Commitments an honest lender signs for its recovery segments 0, 1 and 2.
pub const SEGS: [u64; 3] = [0xa0, 0xa1, 0xa2];
/// Recovery segments an honest recipient attests by default: all of them.
pub const SEGMENTS: u32 = 3;
/// Seed of the identity authority of the tests' deployment.
pub const AUTHORITY: [u8; 32] = [3; 32];

/// The deployment every honest account signs for.
pub fn dom() -> Domain {
    IdentityAuthority::new(AUTHORITY).domain()
}
pub const HOUR: u64 = 3600;

pub type Res = Result<LedgerOutcome, LedgerApiError>;

pub fn key(account: u32) -> UserKey {
    let mut seed = [9u8; 32];
    seed[..4].copy_from_slice(&account.to_le_bytes());
    UserKey::from_seed(seed)
}

pub fn terms(max_budget: Amount) -> JobTerms {
    JobTerms {
        model: 1,
        layers: 4,
        price: [0, 8, 0],
        max_outputs: [0, 10, 0],
        max_budget,
    }
}

pub struct World {
    pub auth: IdentityAuthority,
    pub ledger: LedgerService,
    pub treasury: ServiceCredential,
    pub orch: ServiceCredential,
    pub auditor: ServiceCredential,
    pub clock: ServiceCredential,
}

pub fn world() -> World {
    let mut auth = IdentityAuthority::new(AUTHORITY);
    let keys = KeyDirectory::new();
    for a in [ALICE, BOB, L1, L2, WIT, MALLORY, ADMIN] {
        keys.register(a, key(a).public()).unwrap();
    }
    let mut ledger = LedgerService::new(auth.verifier(), keys, LedgerLimits::default());
    let treasury = auth.issue(ServiceRole::Treasury);
    let orch = auth.issue(ServiceRole::Orchestrator);
    let auditor = auth.issue(ServiceRole::Auditor);
    let clock = auth.issue(ServiceRole::Clock);
    let platform = auth.issue(ServiceRole::PlatformAdmin);
    let pool = LedgerOp::RegisterPool {
        pool: POOL,
        admin: ADMIN,
    };
    ledger.execute(&platform, pool).unwrap();
    for (k, to) in [
        ("i1", IssueTo::User(ALICE)),
        ("i2", IssueTo::User(BOB)),
        ("i3", IssueTo::Pool(POOL)),
    ] {
        let op = LedgerOp::Issue {
            key: k.into(),
            to,
            amount: 1_000,
        };
        ledger.execute(&treasury, op).unwrap();
    }
    World {
        auth,
        ledger,
        treasury,
        orch,
        auditor,
        clock,
    }
}

/// What the recipient of `stage` attests about its lender's restoration: segments `0..segments`
/// with the commitments an honest lender signed.
pub fn restoration(a: &Assignment, stage: u32, segments: u32, state: u64) -> Restoration {
    let named: Vec<u32> = (0..segments).collect();
    restoration_of(a, stage, &named, state)
}

/// Same, for exactly the segments named.
pub fn restoration_of(a: &Assignment, stage: u32, segments: &[u32], state: u64) -> Restoration {
    let s = stage as usize;
    let start: u32 = a.layout[..s].iter().sum();
    let commitment = |k: &u32| SEGS.get(*k as usize).copied().unwrap_or(0);
    Restoration {
        job: a.job,
        attempt: a.attempt,
        producer: a.lenders[s],
        layers: (start, start + a.layout[s]),
        restored: [0; 3],
        state,
        segments: segments.iter().map(|k| (*k, commitment(k))).collect(),
    }
}

/// What the lender of `stage` signs when it reports ready.
pub fn readiness(a: &Assignment, stage: u32) -> Readiness {
    Readiness {
        job: a.job,
        attempt: a.attempt,
        lender: a.lenders[stage as usize],
        restored: [0; 3],
        state: STATE,
        segments: SEGS.to_vec(),
    }
}

pub fn assignment(attempt: u32, lenders: &[u32], layout: &[u32], earmark: Amount) -> Assignment {
    Assignment {
        job: JOB,
        attempt,
        lenders: lenders.to_vec(),
        layout: layout.to_vec(),
        witness: WIT,
        recovery_earmark: earmark,
    }
}

pub fn line(attempt: u32, lender: u32) -> LineRef {
    LineRef {
        job: JOB,
        attempt,
        slice: 1,
        lender,
    }
}

pub fn out(pos: u32) -> OutputRef {
    OutputRef { wt: WT, pos }
}

impl World {
    /// As the orchestrator.
    pub fn run(&mut self, op: LedgerOp) -> Res {
        self.ledger.execute(&self.orch, op)
    }

    pub fn bal(&self, a: Account) -> i128 {
        self.ledger.audit_view(&self.auditor).unwrap().balance(a)
    }

    pub fn balances(&self) -> Vec<(Account, i128)> {
        let l = self.ledger.audit_view(&self.auditor).unwrap();
        l.accounts().map(|(a, b)| (*a, *b)).collect()
    }

    pub fn escrow(&self) -> &Escrow {
        &self.ledger.audit_escrows(&self.auditor).unwrap()[&JOB]
    }

    pub fn open(&mut self, job: u32, max: Amount) -> Res {
        let t = terms(max);
        let signature = key(ALICE).sign(&mandate_message(&dom(), job, POOL, ALICE, &t));
        self.run(LedgerOp::OpenEscrow {
            job,
            owner: ALICE,
            pool: POOL,
            terms: t,
            signature,
        })
    }

    pub fn reserve(&mut self, bucket: EscrowBucket, amount: Amount) -> Res {
        let n = self
            .ledger
            .audit_view(&self.auditor)
            .unwrap()
            .entries()
            .len();
        self.run(LedgerOp::Reserve {
            job: JOB,
            bucket,
            key: format!("reserve/{n}"),
            amount,
        })
    }

    /// The pool's admin agrees to relay `amount` more.
    pub fn fund(&mut self, amount: Amount) -> Res {
        self.fund_signed(amount, ADMIN)
    }

    /// `signer` signs the relay's new running total.
    pub fn fund_signed(&mut self, amount: Amount, signer: u32) -> Res {
        let total = self.escrow().pool_funded + amount;
        self.run(LedgerOp::FundRecovery {
            job: JOB,
            amount,
            signature: key(signer).sign(&relay_message(&dom(), JOB, POOL, total)),
        })
    }

    /// Registers an attempt and has every lender sign it.
    pub fn place(&mut self, a: &Assignment) {
        self.run(LedgerOp::RegisterAttempt {
            assignment: a.clone(),
        })
        .unwrap();
        for (stage, l) in a.lenders.iter().enumerate() {
            self.accept(a, stage as u32, *l).unwrap();
        }
    }

    /// `signer` signs the assignment for `stage`.
    pub fn accept(&mut self, a: &Assignment, stage: u32, signer: u32) -> Res {
        self.run(LedgerOp::AcceptLease {
            job: a.job,
            attempt: a.attempt,
            stage,
            signature: key(signer).sign(&lease_message(&dom(), a)),
        })
    }

    pub fn ready(&mut self, a: &Assignment, stage: u32, signer: u32) -> Res {
        self.ready_with(stage, &readiness(a, stage), signer)
    }

    /// `signer` signs exactly `r` for `stage`.
    pub fn ready_with(&mut self, stage: u32, r: &Readiness, signer: u32) -> Res {
        self.run(LedgerOp::LeaseReady {
            job: r.job,
            attempt: r.attempt,
            stage,
            restored: r.restored,
            state: r.state,
            segments: r.segments.clone(),
            signature: key(signer).sign(&ready_message(&dom(), r)),
        })
    }

    pub fn revoke(&mut self, attempt: u32) -> Res {
        self.run(LedgerOp::RevokeAttempt { job: JOB, attempt })
    }

    /// `signer` attests that it received the restored state of the lender of `stage`.
    pub fn corroborate(&mut self, a: &Assignment, stage: u32, signer: u32) -> Res {
        self.corroborate_with(&restoration(a, stage, SEGMENTS, STATE), signer)
    }

    /// `signer` signs exactly `r`; the ledger is told which segments and rebuilds the rest.
    pub fn corroborate_with(&mut self, r: &Restoration, signer: u32) -> Res {
        self.run(LedgerOp::RecordRestore {
            job: r.job,
            attempt: r.attempt,
            producer: r.producer,
            segments: r.segments.iter().map(|(k, _)| *k).collect(),
            signature: key(signer).sign(&restore_message(&dom(), r)),
        })
    }

    /// The clock service moves the ledger's time forward by `dt`.
    pub fn advance(&mut self, dt: u64) {
        let now = self.ledger.now() + dt;
        self.ledger
            .execute(&self.clock, LedgerOp::Advance { now })
            .unwrap();
    }

    /// `signer` signs a receipt for `producer`'s outputs `0..upto`.
    pub fn receipt(&mut self, attempt: u32, producer: u32, upto: u32, signer: u32) -> Res {
        let m = receipt_message(&dom(), JOB, attempt, producer, WT, upto, 0);
        self.run(LedgerOp::RecordReceipt {
            job: JOB,
            attempt,
            producer,
            wt: WT,
            upto,
            digest: 0,
            signature: key(signer).sign(&m),
        })
    }

    pub fn charge(&mut self, attempt: u32, pos: u32) -> Res {
        let gen = self
            .escrow()
            .outputs
            .get(&out(pos))
            .map_or(0, |o| o.next_gen);
        self.run(LedgerOp::ChargeOutput {
            job: JOB,
            attempt,
            output: out(pos),
            gen,
        })
    }

    /// Job 1 open (budget 500), 100 work and 20 recovery reserved, attempt 1 on `L1` (3 layers)
    /// and `L2` (1 layer), both leases signed.
    pub fn running() -> (World, Assignment) {
        let mut w = world();
        w.open(JOB, 500).unwrap();
        w.reserve(EscrowBucket::Work, 100).unwrap();
        w.reserve(EscrowBucket::Recovery, 20).unwrap();
        let a = assignment(1, &[L1, L2], &[3, 1], 0);
        w.place(&a);
        (w, a)
    }
}
