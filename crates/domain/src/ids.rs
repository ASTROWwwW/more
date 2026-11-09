//! Identifiants (spécification v2.3, section 1 « Vocabulaire »).

/// Horloge du coordinateur, en secondes. Seule horloge qui fait foi (JOB-R09).
pub type Time = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolId(pub u32);

/// Type de travail : chacun a son propre budget de flux (JOB-R13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkType {
    Prefill,
    Generate,
    Batch,
}

impl WorkType {
    pub const ALL: [WorkType; 3] = [WorkType::Prefill, WorkType::Generate, WorkType::Batch];

    pub fn idx(self) -> usize {
        match self {
            WorkType::Prefill => 0,
            WorkType::Generate => 1,
            WorkType::Batch => 2,
        }
    }
}

/// Une sortie livrée à l'emprunteur : facturée au plus une fois (JOB-R17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputId {
    pub job: JobId,
    pub wt: WorkType,
    pub pos: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContributionRole {
    /// Exécution d'une tranche de couches.
    Executor,
}

/// Une contribution à une sortie : plusieurs contributions distinctes
/// (une par plage de couches) sont rémunérées pour une même sortie,
/// chacune au plus une fois (JOB-R21).
///
/// `charge` est la génération de facturation de la sortie (v2.4) : une sortie
/// provisoire annulée par un retour arrière (JOB-R29) puis régénérée est une
/// nouvelle facturation, dont les contributions sont distinctes des anciennes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContributionId {
    pub output: OutputId,
    pub charge: u32,
    pub layer_start: u32,
    pub layer_end: u32,
    pub role: ContributionRole,
}

/// Tranche de facturation `(job, tentative, numéro)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SliceId {
    pub job: JobId,
    pub attempt: u32,
    pub slice: u32,
}

/// Travail de récupération `(job, tentative, segment)` (JOB-R18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryWorkId {
    pub job: JobId,
    pub attempt: u32,
    pub segment: u32,
}

/// Compteurs indexés par type de travail.
pub type PerType<T> = [T; 3];
