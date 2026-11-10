//! Commands applied by the coordinator. Each maps to one or more transitions of the spec.

use crate::ids::*;
use crate::model::{ClaimItem, PauseReason};
use crate::registry::{ModelSpec, PoolAccess, PoolMode, Rights};
use gpu_ledger::Amount;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTarget {
    User(AccountId),
    Pool(PoolId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Advances the coordinator clock.
    Tick { dt: Time },
    /// Issuance (LEDGER-003), idempotency key `issue/{id}`.
    Issue {
        id: u32,
        to: IssueTarget,
        amount: Amount,
    },
    /// Platform admin. `admin` manages members and the catalog.
    CreatePool {
        pool: PoolId,
        mode: PoolMode,
        access: PoolAccess,
        admin: AccountId,
    },
    /// Pool admin: sets an account's rights in the pool (`Rights::NONE` removes them).
    SetRights {
        pool: PoolId,
        account: AccountId,
        rights: Rights,
    },
    /// An account joins an open pool to borrow and lend.
    JoinPool { pool: PoolId, account: AccountId },
    /// Pool admin: adds or updates a model and its tariff. Jobs keep the price they were
    /// submitted with.
    RegisterModel {
        pool: PoolId,
        model: ModelId,
        spec: ModelSpec,
    },
    /// JOB-T01. The price comes from the pool's tariff; the borrower only states what it wants and
    /// the most it agrees to lock, signed for the ledger (`mandate`).
    Submit {
        job: JobId,
        borrower: AccountId,
        pool: PoolId,
        model: ModelId,
        outputs: PerType<u32>,
        max_budget: Amount,
        mandate: [u8; 64],
    },
    /// JOB-T02.
    Reserve { job: JobId },
    /// JOB-T03.
    RejectQueued { job: JobId },
    /// JOB-T04 (from `reserved`) or JOB-T09 (from `recovering`).
    Place {
        job: JobId,
        lenders: Vec<AccountId>,
        /// Layers per stage, chosen by the scheduler; must cover the model exactly.
        layout: Vec<u32>,
        recovery_estimate: Amount,
        /// Delivery witness assigned to the attempt (JOB-R26).
        witness: AccountId,
        expected_version: Option<u64>,
    },
    /// JOB-R38: the lender of a stage accepts its lease by signing the attempt's assignment
    /// (`lease_message`); the ledger checks the signature.
    AcceptLease {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        signature: [u8; 64],
    },
    /// JOB-R38: the lender's layers are loaded; `config` must be the stage's configuration
    /// digest (`Coordinator::config_digest`).
    LeaseLoaded {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        config: u64,
    },
    /// JOB-R18: the recipient of `lender`'s output (next stage, or the witness) attests that it
    /// received `lender`'s restored state. `signature` is the recipient's over `restore_message`,
    /// checked by the ledger.
    /// `segments`: recovery segments `0..segments` were received. The signature binds the job,
    /// the attempt, the lender, its layer range, the restored positions, the segments and the
    /// commitment the lender signed, so it cannot serve another recovery.
    CorroborateRestore {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        segments: u32,
        signature: [u8; 64],
    },
    /// Renews the sender's own lease (JOB-R31, JOB-R39).
    Heartbeat {
        job: JobId,
        attempt: u32,
        lender: AccountId,
    },
    /// Renews the witness's own lease (JOB-R39).
    WitnessHeartbeat {
        job: JobId,
        attempt: u32,
        witness: AccountId,
    },
    /// Witness attestation: positions `< upto` reached the client's transport (JOB-R26, JOB-R27).
    /// `witness` is the signer.
    Deliver {
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
        /// Chained digest of frames `0..upto`, signed by the output node (JOB-R34).
        digest: u64,
    },
    /// Short witness commitment, stamped by the coordinator; makes a full attestation admissible
    /// during draining (JOB-R32).
    WitnessCommit {
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
    },
    /// Client statement "I hold exactly `0..confirmed`", with the digest of that prefix (JOB-R28,
    /// JOB-R33, JOB-R34).
    ConfirmDelivery {
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        digest: u64,
    },
    /// Signed client keepalive. Covers no position, proves no receipt (JOB-R33).
    ClientHeartbeat { job: JobId },
    /// JOB-R33: contests past their deadline without a covering ack.
    ResolveContests { job: JobId },
    /// Witness frees its buffer after retention (JOB-R28).
    PurgeBuffer { job: JobId, attempt: u32 },
    /// Stronger proof for a reserved item, before the evaluation deadline (JOB-R35).
    SupplementEvidence {
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: crate::model::Evidence,
    },
    /// The witness lost its replay buffer for this attempt (JOB-R28).
    WitnessLost { job: JobId, attempt: u32 },
    /// JOB-R29: delivery window expired without contest.
    ExpireDeliveryWindow { job: JobId },
    /// JOB-T06.
    PlacementFailed { job: JobId },
    /// JOB-T05, JOB-R38: the lender's state is restored to `restored`; `state` commits to that
    /// restored state. Both are signed for the ledger (`ready_message`). The attempt starts when
    /// every lease is ready.
    AttemptReady {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        restored: PerType<u32>,
        state: u64,
        signature: [u8; 64],
    },
    /// Units produced by the cluster (JOB-R11, JOB-R13, JOB-R25).
    Produce {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Client ack accepted by the coordinator (JOB-R23).
    Ack {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Receipt commitment by the recipient of `lender`'s output (JOB-R15): next stage, or the
    /// witness for the output node. `digest` binds it to the receipts it covers; `signature` is
    /// the recipient's over `receipt_message`, checked by the ledger (LEDGER-016).
    CommitReceipts {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
        signature: [u8; 64],
    },
    /// A receipt co-signed by the recipient of `lender`'s output, presented by `lender` itself:
    /// the proof behind an uncommitted claim (JOB-R12, LEDGER-016).
    PresentReceipt {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
        signature: [u8; 64],
    },
    /// Lender claim on an open or draining slice.
    Claim {
        slice: SliceId,
        lender: AccountId,
        items: Vec<ClaimItem>,
    },
    /// JOB-S03 (and JOB-T07 if the slice belongs to the live attempt).
    CloseSlice { slice: SliceId },
    /// JOB-S04.
    Evaluate { slice: SliceId },
    /// JOB-S06, one line at a time.
    Arbitrate {
        slice: SliceId,
        lender: AccountId,
        pay: bool,
    },
    /// JOB-T08.
    NodeLost {
        job: JobId,
        expected_version: Option<u64>,
    },
    /// JOB-T11.
    Pause {
        job: JobId,
        reason: PauseReason,
        expected_version: Option<u64>,
    },
    /// JOB-T12.
    Resume { job: JobId, topup: Amount },
    /// JOB-T10.
    RecoveryTimeout { job: JobId },
    /// The pool locks credits for recovery (JOB-R18). `signature` is the pool admin's over
    /// `relay_message` for the new running total, checked by the ledger.
    FundRecovery {
        job: JobId,
        amount: Amount,
        signature: [u8; 64],
    },
    /// JOB-T13.
    Finish {
        job: JobId,
        expected_version: Option<u64>,
    },
    /// JOB-T14.
    CompleteSettling { job: JobId },
    /// JOB-T15.
    Cancel {
        job: JobId,
        expected_version: Option<u64>,
    },
    /// JOB-T16.
    Fail { job: JobId },
    /// JOB-T17.
    ExpirePause { job: JobId },
    /// JOB-S12.
    Settle { job: JobId },
    /// JOB-R22: release a held reward.
    ReleaseReward { slice: SliceId, lender: AccountId },
    /// JOB-R22: contest within the window.
    ContestReward { slice: SliceId, lender: AccountId },
    /// JOB-R20: applies every automatic transition that is due.
    Reconcile,
}

/// Result of an accepted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// Already applied (idempotency): nothing changed.
    AlreadyApplied,
}
