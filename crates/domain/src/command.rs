//! Commandes appliquées par le coordinateur. Chaque commande correspond à une
//! ou plusieurs transitions identifiées dans la spécification.

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
    /// Avance l'horloge du coordinateur.
    Tick {
        dt: Time,
    },
    /// Émission (LEDGER-003), clé d'idempotence `issue/{id}`.
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
    /// JOB-T04 (depuis `reserved`) ou JOB-T09 (depuis `recovering`).
    Place {
        job: JobId,
        lenders: Vec<AccountId>,
        recovery_estimate: Amount,
        /// Témoin de livraison assigné à la tentative (JOB-R26).
        witness: AccountId,
        expected_version: Option<u64>,
    },
    /// Renouvellement de l'autorisation de la tentative courante (JOB-R31).
    Heartbeat {
        job: JobId,
        attempt: u32,
    },
    /// Attestation du témoin : positions `< upto` livrées au transport du
    /// client (JOB-R26, JOB-R27). `witness` = signataire de l'attestation.
    Deliver {
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
        /// Empreinte chaînée des trames `0..upto` signées par le nœud de sortie (JOB-R34).
        digest: u64,
    },
    /// Engagement court du témoin, horodaté par le coordinateur : rend
    /// recevable une attestation complète arrivée pendant le drainage (JOB-R32).
    WitnessCommit {
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
    },
    /// Déclaration signée du client : « je détiens exactement `0..confirmed` »,
    /// avec l'empreinte du préfixe détenu (JOB-R28, JOB-R33, JOB-R34).
    ConfirmDelivery {
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        digest: u64,
    },
    /// Signe de vie signé du client, sans aucune position : ne prouve aucune
    /// réception (JOB-R33).
    ClientHeartbeat {
        job: JobId,
    },
    /// JOB-R33 : échéance des contestations sans accusé couvrant.
    ResolveContests {
        job: JobId,
    },
    /// Le témoin libère son tampon à la fin de la rétention (JOB-R28).
    PurgeBuffer {
        job: JobId,
        attempt: u32,
    },
    /// Preuve complémentaire d'un élément réservé, avant l'échéance d'évaluation (JOB-R35).
    SupplementEvidence {
        slice: SliceId,
        lender: AccountId,
        output: OutputId,
        evidence: crate::model::Evidence,
    },
    /// Le témoin a perdu son tampon de rejeu pour cette tentative (JOB-R28).
    WitnessLost {
        job: JobId,
        attempt: u32,
    },
    /// JOB-R29 : fenêtre de livraison expirée sans contestation.
    ExpireDeliveryWindow {
        job: JobId,
    },
    /// JOB-T06.
    PlacementFailed {
        job: JobId,
    },
    /// JOB-T05 : tous les nœuds ont accepté ; `restored` = positions restaurées par type.
    AttemptReady {
        job: JobId,
        attempt: u32,
        restored: PerType<u32>,
    },
    /// Production d'unités par la grappe (JOB-R11, JOB-R13, JOB-R25).
    Produce {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Accusé du client, accepté par le coordinateur (JOB-R23).
    Ack {
        job: JobId,
        attempt: u32,
        wt: WorkType,
        upto: u32,
    },
    /// Engagement de reçus d'un destinataire (JOB-R15).
    CommitReceipts {
        job: JobId,
        attempt: u32,
        lender: AccountId,
        wt: WorkType,
        upto: u32,
    },
    /// Réclamation d'un prêteur sur une tranche ouverte ou en drainage.
    Claim {
        slice: SliceId,
        lender: AccountId,
        items: Vec<ClaimItem>,
    },
    /// JOB-S03 (et JOB-T07 si la tranche appartient à la tentative en cours).
    CloseSlice {
        slice: SliceId,
    },
    /// JOB-S04.
    Evaluate {
        slice: SliceId,
    },
    /// JOB-S06, ligne par ligne.
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
    /// Le pool bloque des crédits pour la récupération (JOB-R18).
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
    /// JOB-R22 : libération d'une récompense retenue.
    ReleaseReward {
        slice: SliceId,
        lender: AccountId,
    },
    /// JOB-R22 : contestation pendant la fenêtre.
    ContestReward {
        slice: SliceId,
        lender: AccountId,
    },
    /// JOB-R20 : applique toutes les transitions automatiques arrivées à échéance.
    Reconcile,
}

/// Résultat d'une commande acceptée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// Commande déjà appliquée (idempotence) : rien n'a changé.
    AlreadyApplied,
}
