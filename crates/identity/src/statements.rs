//! Statements signed by user accounts and checked by the Ledger (LEDGER-012, LEDGER-015,
//! LEDGER-016, LEDGER-019). Each has a fixed encoding that starts with its own kind tag and the
//! deployment's [`Domain`], so a signature can never be read as another kind of statement, nor
//! replayed in another deployment that happens to reuse the same job and account numbers.

use crate::AccountNo;

/// Cryptographic identifier of a deployment: the public key of its identity authority, the key
/// every service credential chains to. Part of every signed statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Domain(pub(crate) [u8; 32]);

impl Domain {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// What a borrower agrees to for one job: the model and its size, the price of each output type,
/// the most outputs it wants and the most credits it lets the Ledger lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobTerms {
    pub model: u32,
    /// Layers of the model. Every attempt's layout must cover exactly this many.
    pub layers: u32,
    pub price: [u64; 3],
    pub max_outputs: [u32; 3],
    pub max_budget: u64,
}

/// One attempt as placed by the scheduler: who runs which layers, who witnesses delivery, and how
/// much of the recovery budget the attempt may spend. Every lender signs the same assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub job: u32,
    pub attempt: u32,
    /// Lender of each stage, in pipeline order.
    pub lenders: Vec<AccountNo>,
    /// Layers of each stage.
    pub layout: Vec<u32>,
    pub witness: AccountNo,
    pub recovery_earmark: u64,
}

struct Enc(Vec<u8>);

impl Enc {
    fn new(d: &Domain, tag: &[u8]) -> Self {
        let mut v = Vec::with_capacity(128);
        v.extend_from_slice(tag);
        v.extend_from_slice(&d.0);
        Enc(v)
    }
    fn u32(mut self, x: u32) -> Self {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn u64(mut self, x: u64) -> Self {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn len(self, n: usize) -> Self {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX))
    }
    /// Length-prefixed list, so two lists can never be shifted into each other.
    fn list(self, xs: &[u32]) -> Self {
        xs.iter().fold(self.len(xs.len()), |e, x| e.u32(*x))
    }
    fn list64(self, xs: &[u64]) -> Self {
        xs.iter().fold(self.len(xs.len()), |e, x| e.u64(*x))
    }
}

/// Signed by the borrower: lets the Ledger open an escrow for `job` under exactly these terms.
pub fn mandate_message(
    d: &Domain,
    job: u32,
    pool: u32,
    borrower: AccountNo,
    t: &JobTerms,
) -> Vec<u8> {
    let e = Enc::new(d, b"more/mandate/v3")
        .u32(job)
        .u32(pool)
        .u32(borrower)
        .u32(t.model)
        .u32(t.layers);
    let e = t.price.iter().fold(e, |e, p| e.u64(*p));
    let e = t.max_outputs.iter().fold(e, |e, o| e.u32(*o));
    e.u64(t.max_budget).0
}

/// Signed by an admin of the pool: "the pool's relay of the recovery budget of `job` may reach
/// `total` credits". Signing the running total, not the step, makes a replay worthless.
pub fn relay_message(d: &Domain, job: u32, pool: u32, total: u64) -> Vec<u8> {
    Enc::new(d, b"more/relay/v2")
        .u32(job)
        .u32(pool)
        .u64(total)
        .0
}

/// Signed by each lender of the attempt when it accepts its lease.
pub fn lease_message(d: &Domain, a: &Assignment) -> Vec<u8> {
    Enc::new(d, b"more/lease/v2")
        .u32(a.job)
        .u32(a.attempt)
        .list(&a.lenders)
        .list(&a.layout)
        .u32(a.witness)
        .u64(a.recovery_earmark)
        .0
}

/// What a lender signs once its layers are loaded and its state restored: the positions it
/// restored to, a commitment to the restored state (in production, a digest of what the stage
/// hands to the next) and one commitment per recovery segment it recomputed. A segment the lender
/// did not commit to here can never be paid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub job: u32,
    pub attempt: u32,
    pub lender: AccountNo,
    pub restored: [u32; 3],
    pub state: u64,
    /// Commitment to segment `k` at index `k`.
    pub segments: Vec<u64>,
}

/// Signed by a lender when it reports ready.
pub fn ready_message(d: &Domain, r: &Readiness) -> Vec<u8> {
    let e = Enc::new(d, b"more/ready/v3")
        .u32(r.job)
        .u32(r.attempt)
        .u32(r.lender);
    r.restored
        .iter()
        .fold(e, |e, x| e.u32(*x))
        .u64(r.state)
        .list64(&r.segments)
        .0
}

/// What a recipient attests about a producer's restoration (JOB-R18): which stage of which
/// attempt, which layers, up to which positions, the commitment to the restored state, and each
/// recovery segment it received with that segment's own commitment. Nothing in it can be moved to
/// another recovery, and it covers no segment it does not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restoration {
    pub job: u32,
    pub attempt: u32,
    pub producer: AccountNo,
    /// Layer range `[start, end)` of the producer's stage.
    pub layers: (u32, u32),
    pub restored: [u32; 3],
    /// The commitment the producer signed in its readiness.
    pub state: u64,
    /// `(segment, commitment the producer signed for it)`, in increasing segment order.
    pub segments: Vec<(u32, u64)>,
}

/// Signed by the recipient of the producer's output once it has received the restored state.
pub fn restore_message(d: &Domain, r: &Restoration) -> Vec<u8> {
    let e = Enc::new(d, b"more/restore/v2")
        .u32(r.job)
        .u32(r.attempt)
        .u32(r.producer)
        .u32(r.layers.0)
        .u32(r.layers.1);
    let e = r.restored.iter().fold(e, |e, x| e.u32(*x)).u64(r.state);
    r.segments
        .iter()
        .fold(e.len(r.segments.len()), |e, (k, c)| e.u32(*k).u64(*c))
        .0
}

/// Signed by the recipient of `producer`'s output (next stage, or the witness after the last
/// stage): "I received positions `0..upto` of type `wt`, with chained digest `digest`".
pub fn receipt_message(
    d: &Domain,
    job: u32,
    attempt: u32,
    producer: AccountNo,
    wt: u8,
    upto: u32,
    digest: u64,
) -> Vec<u8> {
    Enc::new(d, b"more/receipt/v2")
        .u32(job)
        .u32(attempt)
        .u32(producer)
        .u32(u32::from(wt))
        .u32(upto)
        .u64(digest)
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(d: &Domain) -> Vec<Vec<u8>> {
        let t = JobTerms {
            model: 1,
            layers: 6,
            price: [1, 2, 3],
            max_outputs: [4, 5, 6],
            max_budget: 7,
        };
        let a = Assignment {
            job: 1,
            attempt: 1,
            lenders: vec![10, 11],
            layout: vec![3, 3],
            witness: 30,
            recovery_earmark: 0,
        };
        let ready = Readiness {
            job: 1,
            attempt: 1,
            lender: 10,
            restored: [0; 3],
            state: 5,
            segments: vec![7, 8],
        };
        let restore = Restoration {
            job: 1,
            attempt: 1,
            producer: 10,
            layers: (0, 3),
            restored: [0; 3],
            state: 5,
            segments: vec![(0, 7), (1, 8)],
        };
        vec![
            relay_message(d, 1, 2, 3),
            mandate_message(d, 1, 2, 3, &t),
            lease_message(d, &a),
            ready_message(d, &ready),
            restore_message(d, &restore),
            receipt_message(d, 1, 1, 10, 1, 4, 9),
        ]
    }

    #[test]
    fn statements_never_collide() {
        let d = Domain([1; 32]);
        let msgs = all(&d);
        for (i, x) in msgs.iter().enumerate() {
            for y in &msgs[i + 1..] {
                assert_ne!(x, y);
            }
        }
        // Moving a lender into the layout changes the bytes.
        let a = Assignment {
            job: 1,
            attempt: 1,
            lenders: vec![10, 11],
            layout: vec![3, 3],
            witness: 30,
            recovery_earmark: 0,
        };
        let b = Assignment {
            lenders: vec![10],
            layout: vec![11, 3, 3],
            ..a.clone()
        };
        assert_ne!(lease_message(&d, &a), lease_message(&d, &b));
    }

    /// LEDGER-019: the same statement in another deployment is another message, for every kind.
    #[test]
    fn every_statement_is_bound_to_its_domain() {
        let (here, there) = (all(&Domain([1; 32])), all(&Domain([2; 32])));
        for (x, y) in here.iter().zip(&there) {
            assert_ne!(x, y);
            assert_eq!(x.len(), y.len());
        }
    }

    /// A corroboration names each segment with its commitment: one more, one fewer, another
    /// index or another commitment is another message.
    #[test]
    fn a_restoration_covers_exactly_the_segments_it_names() {
        let d = Domain([1; 32]);
        let r = |segments: &[(u32, u64)]| {
            restore_message(
                &d,
                &Restoration {
                    job: 1,
                    attempt: 1,
                    producer: 10,
                    layers: (0, 3),
                    restored: [0; 3],
                    state: 5,
                    segments: segments.to_vec(),
                },
            )
        };
        let base = r(&[(0, 7), (1, 8)]);
        for other in [
            r(&[(0, 7)]),
            r(&[(0, 7), (1, 8), (2, 9)]),
            r(&[(0, 7), (2, 8)]),
            r(&[(0, 7), (1, 9)]),
        ] {
            assert_ne!(base, other);
        }
    }
}
