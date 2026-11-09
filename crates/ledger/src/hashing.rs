//! Entry chaining (LEDGER-006). FNV-1a in the model; production must use SHA-256 or BLAKE3.

use crate::{Account, Amount};

pub(crate) const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub(crate) fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Entry hash. FNV-1a is enough for the model; the real coordinator will use SHA-256 or BLAKE3.
pub(crate) fn entry_hash(
    prev: u64,
    seq: u64,
    key: &str,
    from: Account,
    to: Account,
    amount: Amount,
) -> u64 {
    let mut h = fnv(FNV_OFFSET, &prev.to_le_bytes());
    h = fnv(h, &seq.to_le_bytes());
    h = fnv(h, key.as_bytes());
    h = fnv(h, format!("{from:?}>{to:?}").as_bytes());
    fnv(h, &amount.to_le_bytes())
}
