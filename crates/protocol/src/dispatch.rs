//! From a signed envelope to a domain command: authenticate, admit, translate, execute.

use gpu_domain::*;
use more_identity::{AuthContext, KeyDirectory};

use crate::envelope::{Envelope, PROTOCOL_VERSION};
use crate::errors::ProtoError;
use crate::messages::Message;
use crate::replay_guard::{Admission, Answer, ReplayGuard};

/// Translates a message into a command. Every actor field of the command is the authenticated
/// sender: a message cannot speak for anyone else (SEC-001, PROTO-006).
pub fn to_command(sender: AccountId, body: &Message) -> Command {
    use Message as M;
    match body {
        M::SubmitJob {
            job,
            pool,
            model,
            outputs,
            max_budget,
            mandate,
        } => Command::Submit {
            job: *job,
            borrower: sender,
            pool: *pool,
            model: *model,
            outputs: *outputs,
            max_budget: *max_budget,
            mandate: *mandate,
        },
        M::CancelJob { job } => Command::Cancel {
            job: *job,
            expected_version: None,
        },
        M::PauseJob { job } => Command::Pause {
            job: *job,
            reason: PauseReason::Requested,
            expected_version: None,
        },
        M::ResumeJob { job, topup } => Command::Resume {
            job: *job,
            topup: *topup,
        },
        M::JoinPool { pool } => Command::JoinPool {
            pool: *pool,
            account: sender,
        },
        M::SetRights {
            pool,
            account,
            rights,
        } => Command::SetRights {
            pool: *pool,
            account: *account,
            rights: *rights,
        },
        M::RegisterModel { pool, model, spec } => Command::RegisterModel {
            pool: *pool,
            model: *model,
            spec: *spec,
        },
        M::AssignAck {
            job,
            attempt,
            restored,
            signature,
        } => Command::AttemptReady {
            job: *job,
            attempt: *attempt,
            lender: sender,
            restored: *restored,
            signature: *signature,
        },
        M::AssignAccept {
            job,
            attempt,
            signature,
        } => Command::AcceptLease {
            job: *job,
            attempt: *attempt,
            lender: sender,
            signature: *signature,
        },
        M::LayersLoaded {
            job,
            attempt,
            config,
        } => Command::LeaseLoaded {
            job: *job,
            attempt: *attempt,
            lender: sender,
            config: *config,
        },
        M::WitnessHeartbeat { job, attempt } => Command::WitnessHeartbeat {
            job: *job,
            attempt: *attempt,
            witness: sender,
        },
        M::ReceiptPresent {
            job,
            attempt,
            wt,
            upto,
            digest,
            signature,
        } => Command::PresentReceipt {
            job: *job,
            attempt: *attempt,
            lender: sender,
            wt: *wt,
            upto: *upto,
            digest: *digest,
            signature: *signature,
        },
        M::AssignReject { job, .. } => Command::PlacementFailed { job: *job },
        M::Produced {
            job,
            attempt,
            wt,
            upto,
        } => Command::Produce {
            job: *job,
            attempt: *attempt,
            wt: *wt,
            upto: *upto,
        },
        M::TokenAck {
            job,
            attempt,
            wt,
            upto,
        } => Command::Ack {
            job: *job,
            attempt: *attempt,
            wt: *wt,
            upto: *upto,
        },
        M::ReceiptCommit {
            job,
            attempt,
            producer,
            wt,
            upto,
            digest,
            signature,
        } => Command::CommitReceipts {
            job: *job,
            attempt: *attempt,
            lender: *producer,
            wt: *wt,
            upto: *upto,
            digest: *digest,
            signature: *signature,
        },
        M::UsageReport { slice, items } => Command::Claim {
            slice: *slice,
            lender: sender,
            items: items.clone(),
        },
        M::EvidenceSupplement {
            slice,
            output,
            evidence,
        } => Command::SupplementEvidence {
            slice: *slice,
            lender: sender,
            output: *output,
            evidence: *evidence,
        },
        M::Heartbeat { job, attempt } => Command::Heartbeat {
            job: *job,
            attempt: *attempt,
            lender: sender,
        },
        M::DeliveryAttestation {
            job,
            attempt,
            wt,
            upto,
            digest,
        } => Command::Deliver {
            job: *job,
            attempt: *attempt,
            witness: sender,
            wt: *wt,
            upto: *upto,
            digest: *digest,
        },
        M::WitnessCommitment {
            job,
            attempt,
            wt,
            upto,
        } => Command::WitnessCommit {
            job: *job,
            attempt: *attempt,
            witness: sender,
            wt: *wt,
            upto: *upto,
        },
        M::WitnessLost { job, attempt } => Command::WitnessLost {
            job: *job,
            attempt: *attempt,
        },
        M::ClientHeartbeat { job } => Command::ClientHeartbeat { job: *job },
        M::DeliveryConfirm {
            job,
            wt,
            confirmed,
            digest,
        } => Command::ConfirmDelivery {
            job: *job,
            wt: *wt,
            confirmed: *confirmed,
            digest: *digest,
        },
        M::ContestReward { slice, lender } => Command::ContestReward {
            slice: *slice,
            lender: *lender,
        },
        M::ReleaseReward { slice } => Command::ReleaseReward {
            slice: *slice,
            lender: sender,
        },
        M::Arbitrate { slice, lender, pay } => Command::Arbitrate {
            slice: *slice,
            lender: *lender,
            pay: *pay,
        },
        M::FundRecovery {
            job,
            amount,
            signature,
        } => Command::FundRecovery {
            job: *job,
            amount: *amount,
            signature: *signature,
        },
    }
}

/// Full chain for one received envelope (size already checked with
/// [`crate::limits::check_frame`]): version, signature, replay guard, authorization and atomic
/// application by the coordinator.
pub fn handle(
    guard: &mut ReplayGuard,
    keys: &KeyDirectory,
    coord: &mut Coordinator,
    env: &Envelope,
) -> Answer {
    if env.version != PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedVersion);
    }
    let verified = keys
        .verify(env.sender.0, &env.signing_bytes(), &env.signature)
        .map_err(ProtoError::Unauthenticated)?;
    if let Admission::Retransmission(answer) = guard.admit(env)? {
        return answer;
    }
    let ctx = AuthContext::account(verified);
    let answer = coord
        .execute(&ctx, &to_command(env.sender, &env.body))
        .map_err(|e| ProtoError::Rejected(e.code()));
    guard.record(env, &answer);
    answer
}
