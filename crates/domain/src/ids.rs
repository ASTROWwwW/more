//! Identifiers (spec section 1, vocabulary).

/// Coordinator clock, in seconds. The only clock that counts (JOB-R09).
pub type Time = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolId(pub u32);

/// Model of a pool's catalog (Model Registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelId(pub u32);

/// Work type; each has its own flow budget (JOB-R13).
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

/// An output delivered to the borrower; charged at most once (JOB-R17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputId {
    pub job: JobId,
    pub wt: WorkType,
    pub pos: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContributionRole {
    /// Runs a range of layers.
    Executor,
}

/// One lender's part of an output: one per layer range, each paid at most once (JOB-R21). `charge`
/// is the output's billing generation: an output voided by a rewind and produced again is a new
/// charge with new contributions (JOB-R29).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContributionId {
    pub output: OutputId,
    pub charge: u32,
    pub layer_start: u32,
    pub layer_end: u32,
    pub role: ContributionRole,
}

/// Billing slice `(job, attempt, number)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SliceId {
    pub job: JobId,
    pub attempt: u32,
    pub slice: u32,
}

/// Recovery work `(job, attempt, segment)` (JOB-R18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryWorkId {
    pub job: JobId,
    pub attempt: u32,
    pub segment: u32,
}

/// Counters indexed by work type.
pub type PerType<T> = [T; 3];
