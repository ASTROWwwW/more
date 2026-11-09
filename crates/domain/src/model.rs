//! États et structures (spécification v2.5, sections 2.1 à 2.4).

use std::collections::BTreeMap;

use crate::ids::*;
use gpu_ledger::Amount;

/// `execution_status` (section 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecStatus {
    Queued,
    Reserved,
    Placing,
    Running,
    Recovering,
    Paused,
    Settling,
    Completed,
    Failed,
    Cancelled,
}

impl ExecStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecStatus::Completed | ExecStatus::Failed | ExecStatus::Cancelled
        )
    }

    /// Transitions autorisées : toute autre est interdite (section 2).
    /// Sert à l'implémentation et au vérificateur d'invariants (TEST-P01).
    pub fn allowed(from: ExecStatus, to: ExecStatus) -> bool {
        use ExecStatus::*;
        matches!(
            (from, to),
            (Queued, Reserved)            // JOB-T02
                | (Queued, Cancelled)     // JOB-T03, JOB-T15
                | (Reserved, Placing)     // JOB-T04
                | (Placing, Running)      // JOB-T05
                | (Placing, Reserved)     // JOB-T06 (premier placement)
                | (Placing, Recovering)   // JOB-T06 (reprise)
                | (Running, Recovering)   // JOB-T08
                | (Recovering, Placing)   // JOB-T09
                | (Recovering, Paused)    // JOB-T10
                | (Running, Paused)       // JOB-T11
                | (Paused, Reserved)      // JOB-T12
                | (Running, Settling)     // JOB-T13
                | (Settling, Completed)   // JOB-T14
                | (Reserved, Cancelled)
                | (Placing, Cancelled)
                | (Running, Cancelled)
                | (Recovering, Cancelled)
                | (Paused, Cancelled)     // JOB-T15, JOB-T17
                | (Queued, Failed)
                | (Reserved, Failed)
                | (Placing, Failed)
                | (Running, Failed)
                | (Recovering, Failed)
                | (Paused, Failed) // JOB-T16
        )
    }
}

/// `settlement_status` (section 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SettleStatus {
    None,
    Active,
    Finalizing,
    Closed,
}

/// `execution_intent` : monotone, ne revient jamais à `Initial`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intent {
    Initial,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    Credits,
    /// Partage libre : aucun crédit, un quota de jobs actifs par emprunteur.
    FreeShare {
        quota_per_borrower: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub id: PoolId,
    pub mode: PoolMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseReason {
    LowEscrow,
    Requested,
    Preempted,
    ClientSilent,
}

/// Une tentative : grappe figée, autorisations, compteurs de production.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub no: u32,
    /// Prêteur assigné à chaque plage de couches (index = étage).
    pub lenders: Vec<AccountId>,
    pub issued_at: Time,
    /// Témoin de livraison assigné (JOB-R26) : relais indépendant des prêteurs
    /// et de l'emprunteur, seul habilité à attester une livraison.
    pub witness: AccountId,
    /// Expiration de l'autorisation (JOB-R31), heure du coordinateur.
    pub lease_expires_at: Time,
    /// Le témoin a perdu son tampon : plus d'attestation ni de rejeu (JOB-R28).
    pub witness_lost: bool,
    /// Le témoin a purgé son tampon après la fin de la rétention (JOB-R28).
    pub buffer_purged: bool,
    /// `execution_revoked` : plus aucune nouvelle unité acceptée (JOB-R11).
    pub revoked_at: Option<Time>,
    /// Position de la révocation dans le journal du coordinateur (CE-03).
    pub revoked_seq: Option<u64>,
    /// La grappe a accepté et l'état est restauré (JOB-T05).
    pub ready: bool,
    /// Prochaine position produite, par type.
    pub produced: PerType<u32>,
    /// Engagements de reçus enregistrés par le coordinateur :
    /// (prêteur, type) → (couvert jusqu'à, horodatage coordinateur).
    pub commitments: BTreeMap<(AccountId, WorkType), (u32, Time)>,
    /// Enveloppe du budget de récupération réservée à cette tentative.
    pub recovery_earmark: Amount,
    /// Montant de récupération déjà réservé dans des lignes (payé ou non).
    pub recovery_reserved: Amount,
    /// L'enveloppe inutilisée a été rendue au budget.
    pub earmark_returned: bool,
    pub next_slice: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub borrower: AccountId,
    pub pool: PoolId,
    /// Identifiant du flux client (session) : lie trames et accusés (JOB-R34).
    pub stream: u64,
    /// Identifiant du modèle du catalogue, couvert par l'empreinte des trames.
    pub model: u32,
    pub version: u64,
    pub exec: ExecStatus,
    pub settle: SettleStatus,
    pub intent: Intent,
    pub exec_since: Time,
    /// État d'où vient le placement en cours (JOB-T06).
    pub placing_from: Option<ExecStatus>,
    pub placement_failures: u32,
    /// Nombre de couches par étage (plages de couches consécutives).
    pub layout: Vec<u32>,
    /// Prix autorisé d'une sortie, par type.
    pub price: PerType<Amount>,
    pub max_outputs: PerType<u32>,
    pub est_cost: Amount,
    pub recovery_budget: Amount,
    /// Budget de récupération non encore attribué à une tentative.
    pub recovery_unearmarked: Amount,
    pub attempt: u32,
    pub attempts: BTreeMap<u32, Attempt>,
    /// Positions validées (JOB-R23) : `0..validated[t]`, signées par le client.
    /// Ne reculent jamais. Le budget de flux se mesure depuis elles.
    pub validated: PerType<u32>,
    /// Positions livrées (JOB-R27) : `0..delivered[t]`, toutes facturées
    /// (définitivement ou provisoirement). `validated ≤ delivered`. Peut
    /// reculer uniquement par retour arrière (JOB-R29), jamais sous `validated`.
    pub delivered: PerType<u32>,
    pub last_ack_at: Time,
    pub checkpoint: bool,
    pub pause_reason: Option<PauseReason>,
    /// Crédits versés par le pool en relais du budget de récupération (JOB-R18).
    pub pool_recovery_funded: Amount,
    /// Récupération payée, imputée au budget de l'emprunteur (brut, jamais diminué).
    pub recovery_paid_borrower: Amount,
    /// Récupération payée, imputée au relais du pool (brut, jamais diminué).
    pub recovery_paid_pool: Amount,
    /// Part pool rendue au pool par contestation.
    pub recovery_contested_pool: Amount,
}

impl Job {
    pub fn current(&self) -> Option<&Attempt> {
        self.attempts.get(&self.attempt)
    }

    pub fn total_layers(&self) -> u32 {
        self.layout.iter().sum()
    }

    /// Plage `[start, end)` de l'étage `stage`.
    pub fn layer_range(&self, stage: usize) -> Option<(u32, u32)> {
        if stage >= self.layout.len() {
            return None;
        }
        let start: u32 = self.layout[..stage].iter().sum();
        Some((start, start + self.layout[stage]))
    }

    /// Part d'une contribution dans le prix d'une sortie : proportionnelle au
    /// nombre de couches, arrondie vers le bas. Somme des parts ≤ prix (JOB-R21).
    pub fn share(&self, wt: WorkType, stage: usize) -> Amount {
        let total = Amount::from(self.total_layers());
        if total == 0 {
            return 0;
        }
        self.price[wt.idx()] * Amount::from(self.layout[stage]) / total
    }
}

/// Cycle de vie d'une tranche (section 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SliceStatus {
    Open,
    Draining,
    Closed,
    Disputed,
    Final,
}

impl SliceStatus {
    pub fn allowed(from: SliceStatus, to: SliceStatus) -> bool {
        use SliceStatus::*;
        matches!(
            (from, to),
            (Open, Draining)
                | (Open, Closed)
                | (Draining, Closed)
                | (Closed, Final)
                | (Closed, Disputed)
                | (Disputed, Final)
        )
    }
}

/// Preuve attachée à un élément réclamé (JOB-R12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Couvert par un engagement de reçus enregistré par le coordinateur.
    Committed,
    /// Reçu cosigné par le destinataire, non couvert par un engagement.
    Uncommitted,
    /// Aucune preuve.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimItem {
    Contribution {
        output: OutputId,
        stage: u32,
        evidence: Evidence,
    },
    Recovery {
        segment: u32,
        amount: Amount,
        evidence: Evidence,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemKind {
    Contribution(ContributionId),
    Recovery(RecoveryWorkId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemStatus {
    PendingEvaluation,
    Paid,
    Refunded,
    Disputed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    pub kind: ItemKind,
    pub amount: Amount,
    pub evidence: Evidence,
    pub status: ItemStatus,
    /// Part financée par le relais du pool (récupération uniquement).
    pub pool_part: Amount,
    /// La récompense de cet élément a été libérée ou contestée.
    pub reward_done: bool,
    /// Contribution d'une sortie encore provisoire à l'évaluation : contestée
    /// en attente du sort de la sortie, jamais arbitrée à part (JOB-R30).
    pub awaiting_delivery: bool,
}

/// Ligne `(tranche, prêteur)`. Invariant (JOB-R24) :
/// `claimed = pending + paid + refunded + disputed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pub claimed: Amount,
    pub pending: Amount,
    pub paid: Amount,
    pub refunded: Amount,
    pub disputed: Amount,
    pub items: Vec<LineItem>,
    /// Récompenses retenues (part payée, pas encore libérée ni contestée).
    pub held: Amount,
    pub released: Amount,
    pub contested: Amount,
}

/// Réclamation reçue pendant `open` / `draining`, évaluée à la clôture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedClaim {
    pub lender: AccountId,
    pub item: ClaimItem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slice {
    pub id: SliceId,
    pub status: SliceStatus,
    pub opened_at: Time,
    pub receipt_deadline: Option<Time>,
    pub closed_at: Option<Time>,
    /// Position de la clôture dans le journal du coordinateur (CE-03).
    pub closed_seq: Option<u64>,
    pub final_at: Option<Time>,
    pub staged: Vec<StagedClaim>,
    pub lines: BTreeMap<AccountId, Line>,
    pub rejected_items: u32,
}

/// Fondement d'une facturation de sortie (JOB-R26, JOB-R27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeBasis {
    /// Signature du client : accusé, ou position confirmée à la reprise.
    ClientSigned,
    /// Attestation du témoin de livraison : facturation provisoire.
    Witnessed,
    /// Fenêtre de livraison expirée sans contestation.
    WindowExpired,
}

/// Facturation en vigueur d'une sortie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputCharge {
    /// Tentative qui a produit la sortie (JOB-R17).
    pub attempt: u32,
    /// Génération de facturation (clé d'idempotence, `ContributionId::charge`).
    pub gen: u32,
    pub definitive: bool,
    pub basis: ChargeBasis,
    /// Le tampon de rejeu du témoin contient la sortie (JOB-R28).
    pub replayable: bool,
    /// Contestation ouverte (une seule par sortie, JOB-R33).
    pub contest: Option<Contest>,
}

/// Contestation d'une sortie provisoire déclarée non reçue (JOB-R33).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contest {
    pub opened_at: Time,
    /// Sans accusé cumulatif signé couvrant la sortie avant cette échéance :
    /// remboursement (retour arrière).
    pub deadline: Time,
}

/// Motif d'un remboursement d'élément (journal, propriété d'équité TEST-P23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundReason {
    /// Aucune preuve fournie.
    NoEvidence,
    /// Preuve « engagée » annoncée mais introuvable ou postérieure.
    EvidenceNotFound,
    /// Récupération d'une tentative jamais démarrée.
    AttemptNotStarted,
    /// Décision d'arbitrage explicite.
    Arbitration,
    /// Règle par défaut à l'échéance du litige.
    DefaultRuling,
    /// La sortie a été annulée par retour arrière (JOB-R29, JOB-R33).
    OutputVoided,
}

impl Evidence {
    /// Force d'une preuve : une preuve complémentaire doit être plus forte (JOB-R35).
    pub fn rank(self) -> u8 {
        match self {
            Evidence::None => 0,
            Evidence::Uncommitted => 1,
            Evidence::Committed => 2,
        }
    }
}
