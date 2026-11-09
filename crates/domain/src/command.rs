//! Commands applied by the coordinator. Each maps to one or more transitions of the spec.

use crate::ids::*;
use crate::model::{ClaimItem, PauseReason, PoolMode};
use gpu_ledger::Amount;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTarget {
    User(AccountId),
    Pool(PoolId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Advances the coordinator clock.
    Tick {
        dt: Time,
    },
    /// Issuance (LEDGER-003), idempotency key `issue/{id}`.
    Issue {
        id: u32,
        to: IssueTarget,
        amount: Amount,
    },
    CreatePool {
        pool: PoolId,
        mode: PoolMode,
    },
    /// JOB-T01.
    Submit {
        job: JobId,
        borrower: AccountId,
        pool: PoolId,
        layout: Vec<u32>,
        price: PerType<Amount>,
        max_outputs: PerType<u32>,
    },
    /// JOB-T02.
    Reserve {
        job: JobId,
    },
    /// JOB-T03.
    RejectQueued {
        job: JobId,
    },
    /// JOB-T04 (from `reserved`) or JOB-T09 (from `recovering`).
    Place {
        job: JobId,
        lenders: Vec<AccountId>,
        recovery_estimate: Amount,
        /// Delivery witness assigned to the attempt (JOB-R26).
        witness: AccountId,
        expected_version: Option<u64>,
    },
    /// Renews the lease of the current attempt (JOB-R31).
    Heartbeat {
        job: JobId,
        attempt: u32,
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
    ClientHeartbeat {
        job: JobId,
    },
    /// JOB-R33: contests past their deadline without a covering ack.
    ResolveContests {
        job: JobId,
    },
    /// Witness frees its buffer after retention (JOB-R28).
    PurgeBuffer {
        job: JobId,
        attempt: u32,
    },
    /// Stronger proof for a reserved item, before the evaluation deadline (JOB-R35).
    SupplementEvidence {
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: crate::model::Evidence,
    },
    /// The witness lost its replay buffer for this attempt (JOB-R28).
    WitnessLost {
        job: JobId,
        attempt: u32,
    },
    /// JOB-R29: delivery window expired without contest.
    ExpireDeliveryWindow {
        job: JobId,
    },
    /// JOB-T06.
    PlacementFailed {
        job: JobId,
    },
    /// JOB-T05: all nodes accepted; `restored` = restored positions per type.
    AttemptReady {
        job: JobId,
        attempt: u32,
        restored: PerType<u32>,
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
    /// Receipt commitment from a recipient (JOB-R15).
    CommitReceipts {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        upto: u32,
    },
    /// Lender claim on an open or draining slice.
    Claim {
        slice: SliceId,
        lender: AccountId,
        items: Vec<ClaimItem>,
    },
    /// JOB-S03 (and JOB-T07 if the slice belongs to the live attempt).
    CloseSlice {
        slice: SliceId,
    },
    /// JOB-S04.
    Evaluate {
        slice: SliceId,
    },
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
    Resume {
        job: JobId,
        topup: Amount,
    },
    /// JOB-T10.
    RecoveryTimeout {
        job: JobId,
    },
    /// The pool locks credits for recovery (JOB-R18).
    FundRecovery {
        job: JobId,
        amount: Amount,
    },
    /// JOB-T13.
    Finish {
        job: JobId,
        expected_version: Option<u64>,
    },
    /// JOB-T14.
    CompleteSettling {
        job: JobId,
    },
    /// JOB-T15.
    Cancel {
        job: JobId,
        expected_version: Option<u64>,
    },
    /// JOB-T16.
    Fail {
        job: JobId,
    },
    /// JOB-T17.
    ExpirePause {
        job: JobId,
    },
    /// JOB-S12.
    Settle {
        job: JobId,
    },
    /// JOB-R22: release a held reward.
    ReleaseReward {
        slice: SliceId,
        lender: AccountId,
    },
    /// JOB-R22: contest within the window.
    ContestReward {
        slice: SliceId,
        lender: AccountId,
    },
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
