//! Audit log (JOB-R10).

use super::*;

/// Audit event, also read by the invariant checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    Exec {
        job: JobId,
        from: Option<ExecStatus>,
        to: ExecStatus,
        rule: &'static str,
    },
    Settle {
        job: JobId,
        from: SettleStatus,
        to: SettleStatus,
        rule: &'static str,
    },
    SliceState {
        slice: SliceId,
        from: Option<SliceStatus>,
        to: SliceStatus,
        rule: &'static str,
    },
    /// A stage's lease moved forward (JOB-R38).
    Lease {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        state: LeaseState,
    },
    /// The recipient of `lender`'s output attested its restored state (JOB-R18).
    RestoreCorroborated {
        job: JobId,
        attempt: u32,
        lender: AccountId,
    },
    /// Nodes whose own lease had expired when the attempt was revoked (JOB-R39).
    LeasesExpired {
        job: JobId,
        attempt: u32,
        nodes: Vec<AccountId>,
    },
    AttemptStarted {
        job: JobId,
        attempt: u32,
        intent: Intent,
        restored: PerType<u32>,
        validated: PerType<u32>,
        delivered: PerType<u32>,
    },
    Produced {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    Validated {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    OutputCharged {
        output: OutputId,
        attempt: u32,
        amount: Amount,
        gen: u32,
        /// Provisional charge on witness attestation (JOB-R27).
        provisional: bool,
    },
    /// Provisional output made definitive (JOB-R27 to JOB-R29).
    OutputConfirmed {
        output: OutputId,
        basis: ChargeBasis,
    },
    /// Provisional output voided by a rewind; price back to escrow (JOB-R29).
    OutputVoided {
        output: OutputId,
        gen: u32,
        amount: Amount,
    },
    /// Output replayed from the witness buffer, not charged again (JOB-R28).
    Replayed {
        output: OutputId,
    },
    /// Contest opened: replay requested, deadline set (JOB-R33).
    ContestOpened {
        output: OutputId,
        deadline: Time,
    },
    /// Full attestation received while draining, covered by a commitment made before revocation
    /// (JOB-R32).
    LateDelivery {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        to: u32,
    },
    BufferPurged {
        job: JobId,
        attempt: u32,
    },
    EvidenceSupplemented {
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: Evidence,
    },
    Delivered {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    Rewound {
        job: JobId,
        wt: WorkType,
        from: u32,
        to: u32,
    },
    /// Contribution to a provisional output, waiting for the output (JOB-R30).
    ItemAwaitingDelivery {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    ItemReserved {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    ItemPaid {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
        evidence: Evidence,
        by_arbitration: bool,
        /// Payment time, used by the sliding cap (JOB-R19).
        at: Time,
    },
    ItemRefunded {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
        reason: RefundReason,
    },
    ItemDisputed {
        slice: SliceId,
        lender: AccountId,
        kind: ItemKind,
        amount: Amount,
    },
    RewardReleased {
        slice: SliceId,
        lender: AccountId,
        amount: Amount,
        commission: Amount,
    },
    RewardContested {
        slice: SliceId,
        lender: AccountId,
        amount: Amount,
    },
}
