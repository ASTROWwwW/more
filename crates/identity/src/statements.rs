//! Statements signed by user accounts and checked by the Ledger (LEDGER-012, LEDGER-015,
//! LEDGER-016). Each has a fixed encoding with its own domain tag, so a signature over one kind of
//! statement can never be read as another.

use crate::AccountNo;

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
    fn new(tag: &[u8]) -> Self {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(tag);
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
    /// Length-prefixed list, so two lists can never be shifted into each other.
    fn list(self, xs: &[u32]) -> Self {
        let n = u32::try_from(xs.len()).unwrap_or(u32::MAX);
        xs.iter().fold(self.u32(n), |e, x| e.u32(*x))
    }
}

/// Signed by the borrower: lets the Ledger open an escrow for `job` under exactly these terms.
pub fn mandate_message(job: u32, pool: u32, borrower: AccountNo, t: &JobTerms) -> Vec<u8> {
    let e = Enc::new(b"more/mandate/v2")
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
pub fn relay_message(job: u32, pool: u32, total: u64) -> Vec<u8> {
    Enc::new(b"more/relay/v1").u32(job).u32(pool).u64(total).0
}

/// Signed by each lender of the attempt when it accepts its lease.
pub fn lease_message(a: &Assignment) -> Vec<u8> {
    Enc::new(b"more/lease/v1")
        .u32(a.job)
        .u32(a.attempt)
        .list(&a.lenders)
        .list(&a.layout)
        .u32(a.witness)
        .u64(a.recovery_earmark)
        .0
}

/// Signed by a lender once its layers are loaded and its state restored to `restored`.
pub fn ready_message(job: u32, attempt: u32, lender: AccountNo, restored: [u32; 3]) -> Vec<u8> {
    let e = Enc::new(b"more/ready/v1").u32(job).u32(attempt).u32(lender);
    restored.iter().fold(e, |e, r| e.u32(*r)).0
}

/// Signed by the recipient of `producer`'s output once it has received `producer`'s state replayed
/// up to `restored`: the restoration is corroborated by a second account (JOB-R18).
pub fn restore_message(job: u32, attempt: u32, producer: AccountNo, restored: [u32; 3]) -> Vec<u8> {
    let e = Enc::new(b"more/restore/v1")
        .u32(job)
        .u32(attempt)
        .u32(producer);
    restored.iter().fold(e, |e, r| e.u32(*r)).0
}

/// Signed by the recipient of `producer`'s output (next stage, or the witness after the last
/// stage): "I received positions `0..upto` of type `wt`, with chained digest `digest`".
pub fn receipt_message(
    job: u32,
    attempt: u32,
    producer: AccountNo,
    wt: u8,
    upto: u32,
    digest: u64,
) -> Vec<u8> {
    Enc::new(b"more/receipt/v1")
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

    #[test]
    fn statements_never_collide() {
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
        let msgs = [
            relay_message(1, 2, 3),
            mandate_message(1, 2, 3, &t),
            lease_message(&a),
            ready_message(1, 1, 10, [0; 3]),
            restore_message(1, 1, 10, [0; 3]),
            receipt_message(1, 1, 10, 1, 4, 9),
        ];
        for (i, x) in msgs.iter().enumerate() {
            for y in &msgs[i + 1..] {
                assert_ne!(x, y);
            }
        }
        // Moving a lender into the layout changes the bytes.
        let b = Assignment {
            lenders: vec![10],
            layout: vec![11, 3, 3],
            ..a.clone()
        };
        assert_ne!(lease_message(&a), lease_message(&b));
    }
}
