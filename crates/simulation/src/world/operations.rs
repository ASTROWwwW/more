//! Abstract operations and their `proptest` generator.

use proptest::prelude::*;

use super::*;

/// Abstract operation. The `u8` fields are selectors taken modulo what exists.
#[derive(Clone, Debug)]
pub enum Op {
    /// A realistic command sent by a random principal instead of its honest sender: borrower,
    /// lender, witness, pool admin, stranger or any service (TEST-P29).
    Impersonate {
        job: u8,
        sel: u8,
        sender: u8,
    },
    Tick(u8),
    Reserve(u8),
    Place {
        job: u8,
        rot: u8,
        est: u8,
    },
    PlacementFailed(u8),
    Ready {
        job: u8,
        correct: bool,
    },
    Produce {
        job: u8,
        wt: u8,
        n: u8,
    },
    Ack {
        job: u8,
        wt: u8,
        n: u8,
    },
    Commit {
        job: u8,
        stage: u8,
        wt: u8,
        partial: bool,
    },
    Claim {
        job: u8,
        slice: u8,
        stage: u8,
        wt: u8,
        pos: u8,
        ev: u8,
        honest: bool,
    },
    ClaimRecovery {
        job: u8,
        slice: u8,
        stage: u8,
        amount: u8,
        ev: u8,
    },
    StaleProduce {
        job: u8,
    },
    Close {
        job: u8,
        slice: u8,
    },
    Evaluate {
        job: u8,
        slice: u8,
    },
    Arbitrate {
        job: u8,
        slice: u8,
        lender: u8,
        pay: bool,
    },
    NodeLost(u8),
    Pause(u8),
    Resume {
        job: u8,
        topup: u8,
    },
    RecoveryTimeout(u8),
    Fund {
        job: u8,
        amount: u8,
    },
    Finish(u8),
    CompleteSettling(u8),
    Cancel(u8),
    Fail(u8),
    Settle(u8),
    Release {
        job: u8,
        slice: u8,
        lender: u8,
    },
    Contest {
        job: u8,
        slice: u8,
        lender: u8,
    },
    Reconcile,
    Duplicate(u16),
    Concurrent {
        job: u8,
        pair: u8,
    },
    /// Moves the job one sensible step along its normal path, so traces reach deep states.
    Drive {
        job: u8,
        sel: u8,
    },
    /// The right lender, on the right range, claims outputs of ANOTHER attempt.
    CrossAttemptClaim {
        job: u8,
        slice: u8,
        stage: u8,
        pos: u8,
    },
    /// Every node of the live attempt renews its own lease (JOB-R31, JOB-R39).
    Heartbeat(u8),
    /// One node renews its own lease; the others stay silent (JOB-R39).
    NodeHeartbeat {
        job: u8,
        node: u8,
    },
    /// The recipient of a stage attests its restoration, or the producer forges it (JOB-R18).
    Corroborate {
        job: u8,
        stage: u8,
        forged: bool,
    },
    /// Every node but one keeps renewing until that one's lease runs out (JOB-R39).
    SilentNode {
        job: u8,
        node: u8,
    },
    /// One lender takes one lease step, honestly or not: accept, load, load the wrong
    /// configuration, ready, accept or ready under someone else's signature (JOB-R38).
    LeaseStep {
        job: u8,
        stage: u8,
        step: u8,
    },
    /// Delivery attestation; `forged` means signed by a lender (JOB-R26).
    Deliver {
        job: u8,
        wt: u8,
        n: u8,
        forged: bool,
    },
    /// Client statement on resume or after the end: honest, "nothing after validated", or more than
    /// delivered (a lie).
    Confirm {
        job: u8,
        wt: u8,
        sel: u8,
    },
    /// The witness loses its replay buffer (current or previous attempt).
    WitnessLost {
        job: u8,
        prev: bool,
    },
    /// Simultaneous faults: silent client AND expired lease, or node AND witness lost in the same
    /// second.
    DoubleFault {
        job: u8,
        kind: u8,
    },
    /// The witness attests everything produced, lenders commit and claim, and the slice is closed
    /// and evaluated before the client answers.
    DeliverAndSettle {
        job: u8,
        sel: u8,
    },
    /// Burst of uncommitted receipts (cap, disputes, arbitration).
    UncommittedBurst {
        job: u8,
        sel: u8,
    },
    /// An arbiter rules on an existing disputed line (JOB-S06).
    ArbitrateDisputed {
        job: u8,
        sel: u8,
    },
    /// Attested tail, buffer and node lost, resume started without waiting for the client, then the
    /// client reports nothing received (JOB-F32).
    ContestUnderLiveResume {
        job: u8,
    },
    /// Full attestation arriving while draining (JOB-R32), with or without a commitment before
    /// revocation.
    LateDeliver {
        job: u8,
        commit_first: bool,
    },
    /// Client keepalive, covers no position (JOB-R33).
    ClientHeartbeat(u8),
    /// The client reports the attested tail of a revoked attempt as not received (buffer intact):
    /// contest and replay (JOB-R33).
    ContestReplay {
        job: u8,
        sel: u8,
    },
    /// The witness tries to purge its buffer (JOB-R28).
    PurgeBuffer {
        job: u8,
        prev: bool,
    },
    /// Supplementary proof before the deadline (JOB-R35); `honest` means only if a prior commitment
    /// really exists.
    Supplement {
        job: u8,
        sel: u8,
        honest: bool,
    },
    /// Contest one minute before the 24 h window ends, then the witness tries to purge right after
    /// (JOB-R28, JOB-F39).
    ContestAtWindowEnd {
        job: u8,
    },
    /// Uncommitted receipts just before midnight, reward contested, new receipts just after
    /// (JOB-R19, JOB-F40).
    BoundaryBurst {
        job: u8,
        sel: u8,
    },
}

pub fn op_strategy() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        3 => b().prop_map(Op::Tick),
        3 => b().prop_map(Op::Reserve),
        4 => (b(), b(), b()).prop_map(|(job, rot, est)| Op::Place { job, rot, est }),
        1 => b().prop_map(Op::PlacementFailed),
        4 => (b(), prop::bool::weighted(0.85)).prop_map(|(job, correct)| Op::Ready { job, correct }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        4 => (b(), b(), b(), any::<bool>()).prop_map(|(job, stage, wt, partial)| Op::Commit { job, stage, wt, partial }),
        8 => (b(), b(), b(), b(), b(), b(), prop::bool::weighted(0.7))
            .prop_map(|(job, slice, stage, wt, pos, ev, honest)| Op::Claim { job, slice, stage, wt, pos, ev, honest }),
        2 => (b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, amount, ev)| Op::ClaimRecovery { job, slice, stage, amount, ev }),
        1 => b().prop_map(|job| Op::StaleProduce { job }),
        4 => (b(), b()).prop_map(|(job, slice)| Op::Close { job, slice }),
        4 => (b(), b()).prop_map(|(job, slice)| Op::Evaluate { job, slice }),
        2 => (b(), b(), b(), any::<bool>()).prop_map(|(job, slice, lender, pay)| Op::Arbitrate { job, slice, lender, pay }),
        2 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(Op::Pause),
        2 => (b(), b()).prop_map(|(job, topup)| Op::Resume { job, topup }),
        1 => b().prop_map(Op::RecoveryTimeout),
        1 => (b(), b()).prop_map(|(job, amount)| Op::Fund { job, amount }),
        2 => b().prop_map(Op::Finish),
        2 => b().prop_map(Op::CompleteSettling),
        1 => b().prop_map(Op::Cancel),
        1 => b().prop_map(Op::Fail),
        2 => b().prop_map(Op::Settle),
        2 => (b(), b(), b()).prop_map(|(job, slice, lender)| Op::Release { job, slice, lender }),
        1 => (b(), b(), b()).prop_map(|(job, slice, lender)| Op::Contest { job, slice, lender }),
        3 => Just(Op::Reconcile),
        3 => any::<u16>().prop_map(Op::Duplicate),
        2 => (b(), b()).prop_map(|(job, pair)| Op::Concurrent { job, pair }),
        20 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        2 => (b(), b(), b(), b()).prop_map(|(job, slice, stage, pos)| Op::CrossAttemptClaim { job, slice, stage, pos }),
        3 => b().prop_map(Op::Heartbeat),
        2 => (b(), b()).prop_map(|(job, node)| Op::NodeHeartbeat { job, node }),
        1 => (b(), b()).prop_map(|(job, node)| Op::SilentNode { job, node }),
        3 => (b(), b(), prop::bool::weighted(0.2)).prop_map(|(job, stage, forged)| Op::Corroborate { job, stage, forged }),
        3 => (b(), b(), b()).prop_map(|(job, stage, step)| Op::LeaseStep { job, stage, step }),
        4 => (b(), b(), b(), prop::bool::weighted(0.2)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        2 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::WitnessLost { job, prev }),
        1 => (b(), b()).prop_map(|(job, kind)| Op::DoubleFault { job, kind }),
                2 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        1 => b().prop_map(Op::ClientHeartbeat),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
        1 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
        4 => (b(), b(), b()).prop_map(|(job, sel, sender)| Op::Impersonate { job, sel, sender }),
    ]
}

pub(super) fn pick<T: Copy>(xs: &[T], sel: u8) -> T {
    xs[sel as usize % xs.len()]
}

pub(super) fn wt_of(sel: u8) -> WorkType {
    pick(&WorkType::ALL, sel)
}
