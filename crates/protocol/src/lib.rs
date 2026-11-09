//! Contrat de messages (spécification v2.5, section 5) — premier jet.
//!
//! Le protocole découle des transitions : chaque message est traduit en une
//! commande du domaine. Le format binaire réel (Protobuf ou maison) n'est pas
//! encore fixé ; cette crate fige ce qui en est indépendant :
//! - l'enveloppe et ses champs obligatoires (PROTO-001) ;
//! - la vérification de taille avant décodage (PROTO-002) ;
//! - les codes d'erreur stables (PROTO-004) ;
//! - l'anti-rejeu par numéro de séquence et la tentative courante (JOB-R05).

use std::collections::BTreeMap;

use gpu_domain::*;

pub const PROTOCOL_VERSION: u16 = 1;

/// Enveloppe commune à tout message (PROTO-001).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub sender: AccountId,
    pub seq: u64,
    /// Signature de l'émetteur. Le modèle ne vérifie pas la cryptographie :
    /// une signature nulle est simplement refusée.
    pub signature: u64,
    pub body: Message,
}

/// Messages par transition (tableau de la section 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    SubmitJob {
        job: JobId,
        pool: PoolId,
        layout: Vec<u32>,
        price: PerType<Amount>,
        max_outputs: PerType<u32>,
    },
    CancelJob {
        job: JobId,
    },
    ResumeJob {
        job: JobId,
        topup: Amount,
    },
    AssignAck {
        job: JobId,
        attempt: u32,
        restored: PerType<u32>,
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
    ReceiptCommit {
        job: JobId,
        attempt: u32,
        producer: AccountId,
        wt: WorkType,
        upto: u32,
    },
    UsageReport {
        slice: SliceId,
        items: Vec<ClaimItem>,
    },
    /// Renouvellement d'autorisation (JOB-R31).
    Heartbeat {
        job: JobId,
        attempt: u32,
    },
    /// Témoin → coordinateur : positions `< upto` livrées au transport du
    /// client (JOB-R26). Le signataire de l'enveloppe est l'attestant.
    DeliveryAttestation {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
        /// Empreinte chaînée des trames signées par le nœud de sortie (JOB-R34).
        digest: u64,
    },
    /// Témoin → coordinateur : engagement court, horodaté (JOB-R32).
    WitnessCommitment {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Client → coordinateur : signe de vie, ne couvre aucune position (JOB-R33).
    ClientHeartbeat {
        job: JobId,
    },
    /// Client → coordinateur : « je détiens exactement `0..confirmed` » (JOB-R28).
    DeliveryConfirm {
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        /// Empreinte du préfixe détenu, liée au flux (JOB-R34).
        digest: u64,
    },
}

impl Message {
    pub fn kind(&self) -> MessageKind {
        match self {
            Message::SubmitJob { .. } => MessageKind::SubmitJob,
            Message::CancelJob { .. } => MessageKind::CancelJob,
            Message::ResumeJob { .. } => MessageKind::ResumeJob,
            Message::AssignAck { .. } => MessageKind::AssignAck,
            Message::AssignReject { .. } => MessageKind::AssignReject,
            Message::Produced { .. } => MessageKind::Produced,
            Message::TokenAck { .. } => MessageKind::TokenAck,
            Message::ReceiptCommit { .. } => MessageKind::ReceiptCommit,
            Message::UsageReport { .. } => MessageKind::UsageReport,
            Message::Heartbeat { .. } => MessageKind::Heartbeat,
            Message::DeliveryAttestation { .. } => MessageKind::DeliveryAttestation,
            Message::DeliveryConfirm { .. } => MessageKind::DeliveryConfirm,
            Message::WitnessCommitment { .. } => MessageKind::WitnessCommitment,
            Message::ClientHeartbeat { .. } => MessageKind::ClientHeartbeat,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageKind {
    SubmitJob,
    CancelJob,
    ResumeJob,
    AssignAck,
    AssignReject,
    Produced,
    TokenAck,
    ReceiptCommit,
    UsageReport,
    Heartbeat,
    DeliveryAttestation,
    DeliveryConfirm,
    WitnessCommitment,
    ClientHeartbeat,
}

impl MessageKind {
    /// Taille maximale d'une trame, vérifiée avant tout décodage (PROTO-002).
    /// Valeurs provisoires.
    pub fn max_frame_bytes(self) -> usize {
        match self {
            MessageKind::SubmitJob => 4 * 1024,
            MessageKind::UsageReport => 64 * 1024,
            _ => 512,
        }
    }
}

/// Codes d'erreur stables (PROTO-004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtoError {
    UnsupportedVersion,
    FrameTooLarge,
    MissingSignature,
    Replay,
    /// Erreur du domaine, avec son code stable.
    Rejected(&'static str),
}

impl ProtoError {
    pub fn code(&self) -> &'static str {
        match self {
            ProtoError::UnsupportedVersion => "UNSUPPORTED_VERSION",
            ProtoError::FrameTooLarge => "FRAME_TOO_LARGE",
            ProtoError::MissingSignature => "MISSING_SIGNATURE",
            ProtoError::Replay => "REPLAY",
            ProtoError::Rejected(c) => c,
        }
    }
}

/// Code stable associé à chaque refus du domaine (PROTO-004).
pub fn domain_code(e: &DomainError) -> &'static str {
    match e {
        DomainError::UnknownJob(_) => "UNKNOWN_JOB",
        DomainError::UnknownSlice(_) => "UNKNOWN_SLICE",
        DomainError::UnknownPool => "UNKNOWN_POOL",
        DomainError::InvalidTransition { .. } => "INVALID_TRANSITION",
        DomainError::InvalidSliceTransition { .. } => "INVALID_SLICE_TRANSITION",
        DomainError::VersionConflict { .. } => "VERSION_CONFLICT",
        DomainError::StaleAttempt => "STALE_ATTEMPT",
        DomainError::JobSettling => "JOB_SETTLING",
        DomainError::FlowBudgetExceeded => "FLOW_BUDGET_EXCEEDED",
        DomainError::WindowNotCovered => "WINDOW_NOT_COVERED",
        DomainError::RecoveryBudget => "RECOVERY_BUDGET",
        DomainError::InadmissibleProof => "INADMISSIBLE_PROOF",
        DomainError::LeaseExpired => "LEASE_EXPIRED",
        DomainError::Precondition(_) => "PRECONDITION_FAILED",
        DomainError::Ledger(_) => "LEDGER_REJECTED",
        DomainError::Internal(_) => "INTERNAL",
    }
}

/// Vérifie la taille déclarée d'une trame AVANT de la décoder (PROTO-002).
pub fn check_frame(kind: MessageKind, declared_len: usize) -> Result<(), ProtoError> {
    if declared_len > kind.max_frame_bytes() {
        return Err(ProtoError::FrameTooLarge);
    }
    Ok(())
}

/// Garde anti-rejeu : numéro de séquence strictement croissant par émetteur.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    last_seq: BTreeMap<AccountId, u64>,
}

impl ReplayGuard {
    pub fn admit(&mut self, env: &Envelope) -> Result<(), ProtoError> {
        if env.version != PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion);
        }
        if env.signature == 0 {
            return Err(ProtoError::MissingSignature);
        }
        let last = self.last_seq.get(&env.sender).copied();
        if last.is_some_and(|l| env.seq <= l) {
            return Err(ProtoError::Replay);
        }
        self.last_seq.insert(env.sender, env.seq);
        Ok(())
    }
}

/// Traduit un message admis en commande du domaine.
pub fn to_command(env: &Envelope) -> Command {
    let sender = env.sender;
    match &env.body {
        Message::SubmitJob {
            job,
            pool,
            layout,
            price,
            max_outputs,
        } => Command::Submit {
            job: *job,
            borrower: sender,
            pool: *pool,
            layout: layout.clone(),
            price: *price,
            max_outputs: *max_outputs,
        },
        Message::CancelJob { job } => Command::Cancel {
            job: *job,
            expected_version: None,
        },
        Message::ResumeJob { job, topup } => Command::Resume {
            job: *job,
            topup: *topup,
        },
        Message::AssignAck {
            job,
            attempt,
            restored,
        } => Command::AttemptReady {
            job: *job,
            attempt: *attempt,
            restored: *restored,
        },
        Message::AssignReject { job, .. } => Command::PlacementFailed { job: *job },
        Message::Produced {
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
        Message::TokenAck {
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
        Message::ReceiptCommit {
            job,
            attempt,
            producer,
            wt,
            upto,
        } => Command::CommitReceipts {
            job: *job,
            attempt: *attempt,
            lender: *producer,
            wt: *wt,
            upto: *upto,
        },
        Message::Heartbeat { job, attempt } => Command::Heartbeat {
            job: *job,
            attempt: *attempt,
        },
        Message::DeliveryAttestation {
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
        Message::WitnessCommitment {
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
        Message::ClientHeartbeat { job } => Command::ClientHeartbeat { job: *job },
        Message::DeliveryConfirm {
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
        Message::UsageReport { slice, items } => Command::Claim {
            slice: *slice,
            lender: sender,
            items: items.clone(),
        },
    }
}

/// Chaîne complète : admission, traduction, application atomique.
pub fn handle(
    guard: &mut ReplayGuard,
    coord: &mut Coordinator,
    env: &Envelope,
) -> Result<Outcome, ProtoError> {
    guard.admit(env)?;
    coord
        .apply(&to_command(env))
        .map_err(|e| ProtoError::Rejected(domain_code(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(seq: u64, body: Message) -> Envelope {
        Envelope {
            version: PROTOCOL_VERSION,
            sender: AccountId(9),
            seq,
            signature: 1,
            body,
        }
    }

    #[test]
    fn oversized_frame_rejected_before_decoding() {
        assert_eq!(
            check_frame(MessageKind::TokenAck, 513),
            Err(ProtoError::FrameTooLarge)
        );
        assert!(check_frame(MessageKind::TokenAck, 512).is_ok());
    }

    #[test]
    fn replayed_or_unsigned_messages_rejected() {
        let mut g = ReplayGuard::default();
        let m = Message::CancelJob { job: JobId(1) };
        assert!(g.admit(&env(5, m.clone())).is_ok());
        assert_eq!(g.admit(&env(5, m.clone())), Err(ProtoError::Replay));
        assert_eq!(g.admit(&env(4, m.clone())), Err(ProtoError::Replay));
        let mut unsigned = env(6, m.clone());
        unsigned.signature = 0;
        assert_eq!(g.admit(&unsigned), Err(ProtoError::MissingSignature));
        let mut old = env(7, m);
        old.version = 0;
        assert_eq!(g.admit(&old), Err(ProtoError::UnsupportedVersion));
    }

    #[test]
    fn domain_refusal_has_stable_code() {
        let mut c = Coordinator::new(Config::default());
        let mut g = ReplayGuard::default();
        let r = handle(
            &mut g,
            &mut c,
            &env(1, Message::CancelJob { job: JobId(42) }),
        );
        assert_eq!(r.unwrap_err().code(), "UNKNOWN_JOB");
    }

    /// JOB-R26 : une attestation signée par un prêteur (et non par le témoin
    /// assigné) est refusée avec un code stable, sans toucher à l'état.
    #[test]
    fn delivery_attested_by_a_lender_is_inadmissible() {
        let mut c = Coordinator::new(Config::default());
        for cmd in [
            Command::CreatePool {
                pool: PoolId(1),
                mode: PoolMode::Credits,
            },
            Command::Issue {
                id: 1,
                to: IssueTarget::User(AccountId(1)),
                amount: 1_000,
            },
            Command::Submit {
                job: JobId(1),
                borrower: AccountId(1),
                pool: PoolId(1),
                layout: vec![1],
                price: [0, 10, 0],
                max_outputs: [0, 4, 0],
            },
            Command::Reserve { job: JobId(1) },
            Command::Place {
                job: JobId(1),
                lenders: vec![AccountId(10)],
                recovery_estimate: 0,
                witness: AccountId(90),
                expected_version: None,
            },
            Command::AttemptReady {
                job: JobId(1),
                attempt: 1,
                restored: [0; 3],
            },
            Command::Produce {
                job: JobId(1),
                attempt: 1,
                wt: WorkType::Generate,
                upto: 2,
            },
        ] {
            c.apply(&cmd).unwrap();
        }
        let mut g = ReplayGuard::default();
        let body = Message::DeliveryAttestation {
            job: JobId(1),
            attempt: 1,
            wt: WorkType::Generate,
            upto: 2,
            digest: c.frame_digest(JobId(1), WorkType::Generate, 2),
        };
        let before = c.clone();
        let mut forged = env(1, body.clone());
        forged.sender = AccountId(10);
        assert_eq!(
            handle(&mut g, &mut c, &forged).unwrap_err().code(),
            "INADMISSIBLE_PROOF"
        );
        assert_eq!(before, c);
        let mut genuine = env(2, body);
        genuine.sender = AccountId(90);
        assert_eq!(handle(&mut g, &mut c, &genuine), Ok(Outcome::Applied));
        assert!(
            !c.charges[&OutputId {
                job: JobId(1),
                wt: WorkType::Generate,
                pos: 1
            }]
                .definitive
        );
    }
}
