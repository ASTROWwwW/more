//! Messages per transition (spec section 5) and their fixed binary encoding (PROTO-003): the bytes
//! a sender signs. No dynamic format, no optional field, every length explicit.

use gpu_domain::*;

/// Messages a participant can send. Service commands (scheduler, reconciler, clock, treasury) do
/// not travel through this edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    SubmitJob {
        job: JobId,
        pool: PoolId,
        model: ModelId,
        outputs: PerType<u32>,
        max_budget: Amount,
        /// Borrower's signature over `mandate_message`, checked by the ledger.
        mandate: [u8; 64],
    },
    CancelJob {
        job: JobId,
    },
    PauseJob {
        job: JobId,
    },
    ResumeJob {
        job: JobId,
        topup: Amount,
    },
    JoinPool {
        pool: PoolId,
    },
    SetRights {
        pool: PoolId,
        account: AccountId,
        rights: Rights,
    },
    RegisterModel {
        pool: PoolId,
        model: ModelId,
        spec: ModelSpec,
    },
    /// The lender's state is restored; `signature` over `ready_message`, for the ledger.
    AssignAck {
        job: JobId,
        attempt: u32,
        restored: PerType<u32>,
        /// Commitment to the restored state.
        state: u64,
        signature: [u8; 64],
    },
    AssignReject {
        job: JobId,
        attempt: u32,
    },
    Produced {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    TokenAck {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Sent by the recipient of `producer`'s output; the sender is the committer (SEC-004).
    /// `signature` is the sender's over `receipt_message`, for the ledger.
    ReceiptCommit {
        job: JobId,
        attempt: u32,
        producer: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
        signature: [u8; 64],
    },
    UsageReport {
        slice: SliceId,
        items: Vec<ClaimItem>,
    },
    EvidenceSupplement {
        slice: SliceId,
        output: OutputId,
        evidence: Evidence,
    },
    /// Renewal of the sender's own lease (JOB-R31, JOB-R39).
    Heartbeat {
        job: JobId,
        attempt: u32,
    },
    /// Witness to coordinator (JOB-R26). The envelope signer is the attester (PROTO-006).
    DeliveryAttestation {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
        digest: u64,
    },
    WitnessCommitment {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    WitnessLost {
        job: JobId,
        attempt: u32,
    },
    /// Client keepalive, covers no position (JOB-R33).
    ClientHeartbeat {
        job: JobId,
    },
    /// "I hold exactly `0..confirmed`" (JOB-R28, JOB-R34).
    DeliveryConfirm {
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        digest: u64,
    },
    ContestReward {
        slice: SliceId,
        lender: AccountId,
    },
    ReleaseReward {
        slice: SliceId,
    },
    Arbitrate {
        slice: SliceId,
        lender: AccountId,
        pay: bool,
    },
    /// `signature`: the sender's over `relay_message` for the new running total.
    FundRecovery {
        job: JobId,
        amount: Amount,
        signature: [u8; 64],
    },
    /// The sender accepts its lease: `signature` over `lease_message` (JOB-R38).
    AssignAccept {
        job: JobId,
        attempt: u32,
        signature: [u8; 64],
    },
    /// The sender's layers are loaded with configuration `config` (JOB-R38).
    LayersLoaded {
        job: JobId,
        attempt: u32,
        config: u64,
    },
    /// Renewal of the witness's own lease (JOB-R39).
    WitnessHeartbeat {
        job: JobId,
        attempt: u32,
    },
    /// The sender received `producer`'s restored state: `signature` over `restore_message`
    /// (JOB-R18). The sender is the producer's recipient.
    RestoreCorroboration {
        job: JobId,
        attempt: u32,
        producer: AccountId,
        segments: u32,
        signature: [u8; 64],
    },
    /// The sender presents a receipt for its own output, signed by its recipient (JOB-R12).
    ReceiptPresent {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
        digest: u64,
        signature: [u8; 64],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageKind {
    SubmitJob,
    CancelJob,
    PauseJob,
    ResumeJob,
    JoinPool,
    SetRights,
    RegisterModel,
    AssignAck,
    AssignReject,
    Produced,
    TokenAck,
    ReceiptCommit,
    UsageReport,
    EvidenceSupplement,
    Heartbeat,
    DeliveryAttestation,
    WitnessCommitment,
    WitnessLost,
    ClientHeartbeat,
    DeliveryConfirm,
    ContestReward,
    ReleaseReward,
    Arbitrate,
    FundRecovery,
    AssignAccept,
    LayersLoaded,
    WitnessHeartbeat,
    ReceiptPresent,
    RestoreCorroboration,
}

impl Message {
    pub fn kind(&self) -> MessageKind {
        use Message as M;
        use MessageKind as K;
        match self {
            M::SubmitJob { .. } => K::SubmitJob,
            M::CancelJob { .. } => K::CancelJob,
            M::PauseJob { .. } => K::PauseJob,
            M::ResumeJob { .. } => K::ResumeJob,
            M::JoinPool { .. } => K::JoinPool,
            M::SetRights { .. } => K::SetRights,
            M::RegisterModel { .. } => K::RegisterModel,
            M::AssignAck { .. } => K::AssignAck,
            M::AssignReject { .. } => K::AssignReject,
            M::Produced { .. } => K::Produced,
            M::TokenAck { .. } => K::TokenAck,
            M::ReceiptCommit { .. } => K::ReceiptCommit,
            M::UsageReport { .. } => K::UsageReport,
            M::EvidenceSupplement { .. } => K::EvidenceSupplement,
            M::Heartbeat { .. } => K::Heartbeat,
            M::DeliveryAttestation { .. } => K::DeliveryAttestation,
            M::WitnessCommitment { .. } => K::WitnessCommitment,
            M::WitnessLost { .. } => K::WitnessLost,
            M::ClientHeartbeat { .. } => K::ClientHeartbeat,
            M::DeliveryConfirm { .. } => K::DeliveryConfirm,
            M::ContestReward { .. } => K::ContestReward,
            M::ReleaseReward { .. } => K::ReleaseReward,
            M::Arbitrate { .. } => K::Arbitrate,
            M::FundRecovery { .. } => K::FundRecovery,
            M::AssignAccept { .. } => K::AssignAccept,
            M::LayersLoaded { .. } => K::LayersLoaded,
            M::WitnessHeartbeat { .. } => K::WitnessHeartbeat,
            M::ReceiptPresent { .. } => K::ReceiptPresent,
            M::RestoreCorroboration { .. } => K::RestoreCorroboration,
        }
    }

    /// Fixed binary encoding (little-endian, kind first).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut w = Writer(out);
        w.u8(self.kind() as u8);
        use Message as M;
        match self {
            M::SubmitJob {
                job,
                pool,
                model,
                outputs,
                max_budget,
                mandate,
            } => {
                w.u32(job.0);
                w.u32(pool.0);
                w.u32(model.0);
                outputs.iter().for_each(|o| w.u32(*o));
                w.u64(*max_budget);
                w.bytes(mandate);
            }
            M::CancelJob { job } | M::PauseJob { job } | M::ClientHeartbeat { job } => w.u32(job.0),
            M::ResumeJob { job, topup } => {
                w.u32(job.0);
                w.u64(*topup);
            }
            M::JoinPool { pool } => w.u32(pool.0),
            M::SetRights {
                pool,
                account,
                rights,
            } => {
                w.u32(pool.0);
                w.u32(account.0);
                w.u8(u8::from(rights.borrow)
                    | u8::from(rights.lend) << 1
                    | u8::from(rights.witness) << 2);
            }
            M::RegisterModel { pool, model, spec } => {
                w.u32(pool.0);
                w.u32(model.0);
                w.u32(spec.layers);
                spec.price.iter().for_each(|p| w.u64(*p));
                spec.max_outputs.iter().for_each(|o| w.u32(*o));
            }
            M::AssignAck {
                job,
                attempt,
                restored,
                state,
                signature,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                restored.iter().for_each(|r| w.u32(*r));
                w.u64(*state);
                w.bytes(signature);
            }
            M::AssignAccept {
                job,
                attempt,
                signature,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.bytes(signature);
            }
            M::RestoreCorroboration {
                job,
                attempt,
                producer,
                segments,
                signature,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u32(producer.0);
                w.u32(*segments);
                w.bytes(signature);
            }
            M::LayersLoaded {
                job,
                attempt,
                config,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u64(*config);
            }
            M::AssignReject { job, attempt }
            | M::Heartbeat { job, attempt }
            | M::WitnessHeartbeat { job, attempt }
            | M::WitnessLost { job, attempt } => {
                w.u32(job.0);
                w.u32(*attempt);
            }
            M::Produced {
                job,
                attempt,
                wt,
                upto,
            }
            | M::TokenAck {
                job,
                attempt,
                wt,
                upto,
            }
            | M::WitnessCommitment {
                job,
                attempt,
                wt,
                upto,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u8(wt.idx() as u8);
                w.u32(*upto);
            }
            M::ReceiptCommit {
                job,
                attempt,
                producer,
                wt,
                upto,
                digest,
                signature,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u32(producer.0);
                w.u8(wt.idx() as u8);
                w.u32(*upto);
                w.u64(*digest);
                w.bytes(signature);
            }
            M::ReceiptPresent {
                job,
                attempt,
                wt,
                upto,
                digest,
                signature,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u8(wt.idx() as u8);
                w.u32(*upto);
                w.u64(*digest);
                w.bytes(signature);
            }
            M::UsageReport { slice, items } => {
                w.slice(*slice);
                w.u32(u32::try_from(items.len()).unwrap_or(u32::MAX));
                for it in items {
                    match it {
                        ClaimItem::Contribution {
                            output,
                            stage,
                            evidence,
                        } => {
                            w.u8(0);
                            w.output(*output);
                            w.u32(*stage);
                            w.u8(evidence.rank());
                        }
                        ClaimItem::Recovery {
                            segment,
                            amount,
                            evidence,
                        } => {
                            w.u8(1);
                            w.u32(*segment);
                            w.u64(*amount);
                            w.u8(evidence.rank());
                        }
                    }
                }
            }
            M::EvidenceSupplement {
                slice,
                output,
                evidence,
            } => {
                w.slice(*slice);
                w.output(*output);
                w.u8(evidence.rank());
            }
            M::DeliveryAttestation {
                job,
                attempt,
                wt,
                upto,
                digest,
            } => {
                w.u32(job.0);
                w.u32(*attempt);
                w.u8(wt.idx() as u8);
                w.u32(*upto);
                w.u64(*digest);
            }
            M::DeliveryConfirm {
                job,
                wt,
                confirmed,
                digest,
            } => {
                w.u32(job.0);
                w.u8(wt.idx() as u8);
                w.u32(*confirmed);
                w.u64(*digest);
            }
            M::ContestReward { slice, lender } => {
                w.slice(*slice);
                w.u32(lender.0);
            }
            M::ReleaseReward { slice } => w.slice(*slice),
            M::Arbitrate { slice, lender, pay } => {
                w.slice(*slice);
                w.u32(lender.0);
                w.u8(u8::from(*pay));
            }
            M::FundRecovery {
                job,
                amount,
                signature,
            } => {
                w.u32(job.0);
                w.u64(*amount);
                w.bytes(signature);
            }
        }
    }
}

struct Writer<'a>(&'a mut Vec<u8>);

impl Writer<'_> {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn slice(&mut self, s: SliceId) {
        self.u32(s.job.0);
        self.u32(s.attempt);
        self.u32(s.slice);
    }
    fn output(&mut self, o: OutputId) {
        self.u32(o.job.0);
        self.u8(o.wt.idx() as u8);
        self.u32(o.pos);
    }
}
