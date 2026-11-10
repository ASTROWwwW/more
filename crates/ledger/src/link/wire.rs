//! Wire encoding of the ledger link: fixed, versioned, little-endian, every list and string
//! length-prefixed. A decoder never trusts a length: it checks it against the bytes left before
//! allocating, and a payload must be consumed exactly.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use more_identity::{AuthError, Domain, ServiceCertificate, ServiceRole};

use crate::journal::LedgerError;
use crate::service::{
    Assignment, EscrowBucket, IssueTo, ItemId, JobTerms, LedgerApiError, LedgerLimits, LedgerOp,
    LedgerOutcome, LineRef, OutputRef,
};
use crate::{Account, Amount};

/// Version of this encoding, sent in the first message of a connection.
pub const LINK_VERSION: u16 = 1;
/// Largest payload either side accepts.
pub const MAX_FRAME: usize = 64 * 1024;
/// Longest idempotency key or reason text.
const MAX_TEXT: usize = 160;

/// The payload does not decode: too short, too long, an unknown tag or a value out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

type Res<T> = Result<T, Malformed>;

#[derive(Default)]
pub(crate) struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i128(&mut self, v: i128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    /// Longer texts are cut: the other side refuses them anyway.
    pub fn text(&mut self, s: &str) {
        let cut = (0..=s.len().min(MAX_TEXT))
            .rev()
            .find(|i| s.is_char_boundary(*i))
            .unwrap_or(0);
        self.len(cut);
        self.bytes(&s.as_bytes()[..cut]);
    }
}

pub(crate) struct R<'a> {
    buf: &'a [u8],
}

impl<'a> R<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        R { buf }
    }
    pub fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Malformed);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }
    pub fn array<const N: usize>(&mut self) -> Res<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Malformed)
    }
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn u128(&mut self) -> Res<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }
    pub fn i128(&mut self) -> Res<i128> {
        Ok(i128::from_le_bytes(self.array()?))
    }
    /// A list length, refused if the bytes left cannot hold that many items of `item` bytes.
    fn len(&mut self, item: usize) -> Res<usize> {
        let n = usize::try_from(self.u32()?).map_err(|_| Malformed)?;
        match n.checked_mul(item) {
            Some(bytes) if bytes <= self.buf.len() => Ok(n),
            _ => Err(Malformed),
        }
    }
    pub fn text(&mut self) -> Res<String> {
        let n = self.len(1)?;
        if n > MAX_TEXT {
            return Err(Malformed);
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Malformed)
    }
    /// Nothing may follow a message.
    pub fn end(&self) -> Res<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

/// Reason texts are `&'static str` in the ledger's errors. Read from the wire, they are kept
/// once each in a table of bounded size; past the bound the reason is replaced, the kind of the
/// error never is.
fn interned(s: &str) -> &'static str {
    static TABLE: OnceLock<Mutex<BTreeSet<&'static str>>> = OnceLock::new();
    let mut table = TABLE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(known) = table.get(s) {
        return known;
    }
    if table.len() >= 1024 {
        return "reason not kept";
    }
    let kept: &'static str = Box::leak(s.to_owned().into_boxed_str());
    table.insert(kept);
    kept
}

pub(crate) fn put_cert(w: &mut W, c: &ServiceCertificate) {
    w.bytes(&c.to_bytes());
}

pub(crate) fn get_cert(r: &mut R) -> Res<ServiceCertificate> {
    ServiceCertificate::from_bytes(r.take(ServiceCertificate::LEN)?).ok_or(Malformed)
}

pub(crate) fn put_account(w: &mut W, a: Account) {
    let line = |w: &mut W, tag, (job, attempt, slice, lender)| {
        w.u8(tag);
        for x in [job, attempt, slice, lender] {
            w.u32(x);
        }
    };
    match a {
        Account::Issuance => w.u8(0),
        Account::Burn => w.u8(1),
        Account::User(x) => {
            w.u8(2);
            w.u32(x);
        }
        Account::PoolReserve(x) => {
            w.u8(3);
            w.u32(x);
        }
        Account::EscrowWork(x) => {
            w.u8(4);
            w.u32(x);
        }
        Account::EscrowRecovery(x) => {
            w.u8(5);
            w.u32(x);
        }
        Account::OutputHold(x) => {
            w.u8(6);
            w.u32(x);
        }
        Account::SliceLine {
            job,
            attempt,
            slice,
            lender,
        } => line(w, 7, (job, attempt, slice, lender)),
        Account::PendingReward {
            job,
            attempt,
            slice,
            lender,
        } => line(w, 8, (job, attempt, slice, lender)),
        Account::Commission => w.u8(9),
    }
}

pub(crate) fn get_account(r: &mut R) -> Res<Account> {
    Ok(match r.u8()? {
        0 => Account::Issuance,
        1 => Account::Burn,
        2 => Account::User(r.u32()?),
        3 => Account::PoolReserve(r.u32()?),
        4 => Account::EscrowWork(r.u32()?),
        5 => Account::EscrowRecovery(r.u32()?),
        6 => Account::OutputHold(r.u32()?),
        7 => {
            let l = get_line(r)?;
            l.line_account()
        }
        8 => {
            let l = get_line(r)?;
            l.reward_account()
        }
        9 => Account::Commission,
        _ => return Err(Malformed),
    })
}

fn put_line(w: &mut W, l: LineRef) {
    for x in [l.job, l.attempt, l.slice, l.lender] {
        w.u32(x);
    }
}

fn get_line(r: &mut R) -> Res<LineRef> {
    Ok(LineRef {
        job: r.u32()?,
        attempt: r.u32()?,
        slice: r.u32()?,
        lender: r.u32()?,
    })
}

fn put_output(w: &mut W, o: OutputRef) {
    w.u8(o.wt);
    w.u32(o.pos);
}

fn get_output(r: &mut R) -> Res<OutputRef> {
    Ok(OutputRef {
        wt: r.u8()?,
        pos: r.u32()?,
    })
}

fn put_item(w: &mut W, i: ItemId) {
    match i {
        ItemId::Contribution { output, gen, stage } => {
            w.u8(0);
            put_output(w, output);
            w.u32(gen);
            w.u32(stage);
        }
        ItemId::Recovery { attempt, segment } => {
            w.u8(1);
            w.u32(attempt);
            w.u32(segment);
        }
    }
}

fn get_item(r: &mut R) -> Res<ItemId> {
    Ok(match r.u8()? {
        0 => ItemId::Contribution {
            output: get_output(r)?,
            gen: r.u32()?,
            stage: r.u32()?,
        },
        1 => ItemId::Recovery {
            attempt: r.u32()?,
            segment: r.u32()?,
        },
        _ => return Err(Malformed),
    })
}

fn put_u32s(w: &mut W, xs: &[u32]) {
    w.len(xs.len());
    xs.iter().for_each(|x| w.u32(*x));
}

fn get_u32s(r: &mut R) -> Res<Vec<u32>> {
    let n = r.len(4)?;
    (0..n).map(|_| r.u32()).collect()
}

fn put_u64s(w: &mut W, xs: &[u64]) {
    w.len(xs.len());
    xs.iter().for_each(|x| w.u64(*x));
}

fn get_u64s(r: &mut R) -> Res<Vec<u64>> {
    let n = r.len(8)?;
    (0..n).map(|_| r.u64()).collect()
}

pub(crate) fn put_op(w: &mut W, op: &LedgerOp) {
    match op {
        LedgerOp::Advance { now } => {
            w.u8(0);
            w.u64(*now);
        }
        LedgerOp::Issue { key, to, amount } => {
            w.u8(1);
            w.text(key);
            match to {
                IssueTo::User(a) => {
                    w.u8(0);
                    w.u32(*a);
                }
                IssueTo::Pool(p) => {
                    w.u8(1);
                    w.u32(*p);
                }
            }
            w.u64(*amount);
        }
        LedgerOp::OpenEscrow {
            job,
            owner,
            pool,
            terms,
            signature,
        } => {
            w.u8(2);
            for x in [*job, *owner, *pool, terms.model, terms.layers] {
                w.u32(x);
            }
            terms.price.iter().for_each(|p| w.u64(*p));
            terms.max_outputs.iter().for_each(|o| w.u32(*o));
            w.u64(terms.max_budget);
            w.bytes(signature);
        }
        LedgerOp::Reserve {
            job,
            bucket,
            key,
            amount,
        } => {
            w.u8(3);
            w.u32(*job);
            w.u8(match bucket {
                EscrowBucket::Work => 0,
                EscrowBucket::Recovery => 1,
            });
            w.text(key);
            w.u64(*amount);
        }
        LedgerOp::RegisterPool { pool, admin } => {
            w.u8(4);
            w.u32(*pool);
            w.u32(*admin);
        }
        LedgerOp::FundRecovery {
            job,
            amount,
            signature,
        } => {
            w.u8(5);
            w.u32(*job);
            w.u64(*amount);
            w.bytes(signature);
        }
        LedgerOp::RegisterAttempt { assignment: a } => {
            w.u8(6);
            w.u32(a.job);
            w.u32(a.attempt);
            put_u32s(w, &a.lenders);
            put_u32s(w, &a.layout);
            w.u32(a.witness);
            w.u64(a.recovery_earmark);
        }
        LedgerOp::AcceptLease {
            job,
            attempt,
            stage,
            signature,
        } => {
            w.u8(7);
            for x in [*job, *attempt, *stage] {
                w.u32(x);
            }
            w.bytes(signature);
        }
        LedgerOp::LeaseReady {
            job,
            attempt,
            stage,
            restored,
            state,
            segments,
            signature,
        } => {
            w.u8(8);
            for x in [*job, *attempt, *stage] {
                w.u32(x);
            }
            restored.iter().for_each(|x| w.u32(*x));
            w.u64(*state);
            put_u64s(w, segments);
            w.bytes(signature);
        }
        LedgerOp::RecordRestore {
            job,
            attempt,
            producer,
            segments,
            signature,
        } => {
            w.u8(9);
            for x in [*job, *attempt, *producer] {
                w.u32(x);
            }
            put_u32s(w, segments);
            w.bytes(signature);
        }
        LedgerOp::RevokeAttempt { job, attempt } => {
            w.u8(10);
            w.u32(*job);
            w.u32(*attempt);
        }
        LedgerOp::RecordReceipt {
            job,
            attempt,
            producer,
            wt,
            upto,
            digest,
            signature,
        } => {
            w.u8(11);
            for x in [*job, *attempt, *producer] {
                w.u32(x);
            }
            w.u8(*wt);
            w.u32(*upto);
            w.u64(*digest);
            w.bytes(signature);
        }
        LedgerOp::ChargeOutput {
            job,
            attempt,
            output,
            gen,
        } => {
            w.u8(12);
            w.u32(*job);
            w.u32(*attempt);
            put_output(w, *output);
            w.u32(*gen);
        }
        LedgerOp::VoidOutput { job, output, gen } => {
            w.u8(13);
            w.u32(*job);
            put_output(w, *output);
            w.u32(*gen);
        }
        LedgerOp::ReserveContribution {
            line,
            output,
            gen,
            stage,
        } => {
            w.u8(14);
            put_line(w, *line);
            put_output(w, *output);
            w.u32(*gen);
            w.u32(*stage);
        }
        LedgerOp::ReserveRecovery {
            line,
            segment,
            amount,
        } => {
            w.u8(15);
            put_line(w, *line);
            w.u32(*segment);
            w.u64(*amount);
        }
        LedgerOp::PayLine { line, item } => {
            w.u8(16);
            put_line(w, *line);
            put_item(w, *item);
        }
        LedgerOp::RefundLine { line, item } => {
            w.u8(17);
            put_line(w, *line);
            put_item(w, *item);
        }
        LedgerOp::ReleaseReward { line } => {
            w.u8(18);
            put_line(w, *line);
        }
        LedgerOp::ContestReward { line } => {
            w.u8(19);
            put_line(w, *line);
        }
        LedgerOp::ReturnEarmark { job, attempt } => {
            w.u8(20);
            w.u32(*job);
            w.u32(*attempt);
        }
        LedgerOp::SettleJob { job } => {
            w.u8(21);
            w.u32(*job);
        }
    }
}

pub(crate) fn get_op(r: &mut R) -> Res<LedgerOp> {
    Ok(match r.u8()? {
        0 => LedgerOp::Advance { now: r.u64()? },
        1 => LedgerOp::Issue {
            key: r.text()?,
            to: match r.u8()? {
                0 => IssueTo::User(r.u32()?),
                1 => IssueTo::Pool(r.u32()?),
                _ => return Err(Malformed),
            },
            amount: r.u64()?,
        },
        2 => LedgerOp::OpenEscrow {
            job: r.u32()?,
            owner: r.u32()?,
            pool: r.u32()?,
            terms: JobTerms {
                model: r.u32()?,
                layers: r.u32()?,
                price: [r.u64()?, r.u64()?, r.u64()?],
                max_outputs: [r.u32()?, r.u32()?, r.u32()?],
                max_budget: r.u64()?,
            },
            signature: r.array()?,
        },
        3 => LedgerOp::Reserve {
            job: r.u32()?,
            bucket: match r.u8()? {
                0 => EscrowBucket::Work,
                1 => EscrowBucket::Recovery,
                _ => return Err(Malformed),
            },
            key: r.text()?,
            amount: r.u64()?,
        },
        4 => LedgerOp::RegisterPool {
            pool: r.u32()?,
            admin: r.u32()?,
        },
        5 => LedgerOp::FundRecovery {
            job: r.u32()?,
            amount: r.u64()?,
            signature: r.array()?,
        },
        6 => LedgerOp::RegisterAttempt {
            assignment: Assignment {
                job: r.u32()?,
                attempt: r.u32()?,
                lenders: get_u32s(r)?,
                layout: get_u32s(r)?,
                witness: r.u32()?,
                recovery_earmark: r.u64()?,
            },
        },
        7 => LedgerOp::AcceptLease {
            job: r.u32()?,
            attempt: r.u32()?,
            stage: r.u32()?,
            signature: r.array()?,
        },
        8 => LedgerOp::LeaseReady {
            job: r.u32()?,
            attempt: r.u32()?,
            stage: r.u32()?,
            restored: [r.u32()?, r.u32()?, r.u32()?],
            state: r.u64()?,
            segments: get_u64s(r)?,
            signature: r.array()?,
        },
        9 => LedgerOp::RecordRestore {
            job: r.u32()?,
            attempt: r.u32()?,
            producer: r.u32()?,
            segments: get_u32s(r)?,
            signature: r.array()?,
        },
        10 => LedgerOp::RevokeAttempt {
            job: r.u32()?,
            attempt: r.u32()?,
        },
        11 => LedgerOp::RecordReceipt {
            job: r.u32()?,
            attempt: r.u32()?,
            producer: r.u32()?,
            wt: r.u8()?,
            upto: r.u32()?,
            digest: r.u64()?,
            signature: r.array()?,
        },
        12 => LedgerOp::ChargeOutput {
            job: r.u32()?,
            attempt: r.u32()?,
            output: get_output(r)?,
            gen: r.u32()?,
        },
        13 => LedgerOp::VoidOutput {
            job: r.u32()?,
            output: get_output(r)?,
            gen: r.u32()?,
        },
        14 => LedgerOp::ReserveContribution {
            line: get_line(r)?,
            output: get_output(r)?,
            gen: r.u32()?,
            stage: r.u32()?,
        },
        15 => LedgerOp::ReserveRecovery {
            line: get_line(r)?,
            segment: r.u32()?,
            amount: r.u64()?,
        },
        16 => LedgerOp::PayLine {
            line: get_line(r)?,
            item: get_item(r)?,
        },
        17 => LedgerOp::RefundLine {
            line: get_line(r)?,
            item: get_item(r)?,
        },
        18 => LedgerOp::ReleaseReward { line: get_line(r)? },
        19 => LedgerOp::ContestReward { line: get_line(r)? },
        20 => LedgerOp::ReturnEarmark {
            job: r.u32()?,
            attempt: r.u32()?,
        },
        21 => LedgerOp::SettleJob { job: r.u32()? },
        _ => return Err(Malformed),
    })
}

pub(crate) fn put_outcome(w: &mut W, o: &LedgerOutcome) {
    let pair = |w: &mut W, tag, a: Amount, b: Amount| {
        w.u8(tag);
        w.u64(a);
        w.u64(b);
    };
    match *o {
        LedgerOutcome::Done => w.u8(0),
        LedgerOutcome::Moved(a) => {
            w.u8(1);
            w.u64(a);
        }
        LedgerOutcome::Paid { amount, pool_part } => pair(w, 2, amount, pool_part),
        LedgerOutcome::Released {
            to_lender,
            commission,
        } => pair(w, 3, to_lender, commission),
        LedgerOutcome::Contested { to_pool, to_owner } => pair(w, 4, to_pool, to_owner),
        LedgerOutcome::Settled { to_pool, to_owner } => pair(w, 5, to_pool, to_owner),
    }
}

pub(crate) fn get_outcome(r: &mut R) -> Res<LedgerOutcome> {
    Ok(match r.u8()? {
        0 => LedgerOutcome::Done,
        1 => LedgerOutcome::Moved(r.u64()?),
        2 => LedgerOutcome::Paid {
            amount: r.u64()?,
            pool_part: r.u64()?,
        },
        3 => LedgerOutcome::Released {
            to_lender: r.u64()?,
            commission: r.u64()?,
        },
        4 => LedgerOutcome::Contested {
            to_pool: r.u64()?,
            to_owner: r.u64()?,
        },
        5 => LedgerOutcome::Settled {
            to_pool: r.u64()?,
            to_owner: r.u64()?,
        },
        _ => return Err(Malformed),
    })
}

fn auth_code(e: &AuthError) -> u8 {
    match e {
        AuthError::UnknownAccount => 0,
        AuthError::BadSignature => 1,
        AuthError::KeyAlreadyRegistered => 2,
        AuthError::InvalidCredential => 3,
        AuthError::RevokedCredential => 4,
    }
}

fn auth_error(code: u8) -> Res<AuthError> {
    Ok(match code {
        0 => AuthError::UnknownAccount,
        1 => AuthError::BadSignature,
        2 => AuthError::KeyAlreadyRegistered,
        3 => AuthError::InvalidCredential,
        4 => AuthError::RevokedCredential,
        _ => return Err(Malformed),
    })
}

pub(crate) fn put_error(w: &mut W, e: &LedgerApiError) {
    let reason = |w: &mut W, tag, why: &str| {
        w.u8(tag);
        w.text(why);
    };
    let job = |w: &mut W, tag, job: u32| {
        w.u8(tag);
        w.u32(job);
    };
    match e {
        LedgerApiError::Unauthenticated(a) => {
            w.u8(0);
            w.u8(auth_code(a));
        }
        LedgerApiError::Forbidden { role, op } => {
            w.u8(1);
            w.u8(*role as u8);
            w.text(op);
        }
        LedgerApiError::UnknownEscrow(j) => job(w, 2, *j),
        LedgerApiError::EscrowExists(j) => job(w, 3, *j),
        LedgerApiError::EscrowSettled(j) => job(w, 4, *j),
        LedgerApiError::BadMandate => w.u8(5),
        LedgerApiError::MandateExceeded {
            job,
            mandate,
            requested_total,
        } => {
            w.u8(6);
            w.u32(*job);
            w.u64(*mandate);
            w.u128(*requested_total);
        }
        LedgerApiError::BadProof(why) => reason(w, 7, why),
        LedgerApiError::OutOfWindow(why) => reason(w, 8, why),
        LedgerApiError::OpenItems(j) => job(w, 9, *j),
        LedgerApiError::LimitExceeded(why) => reason(w, 10, why),
        LedgerApiError::Invalid(why) => reason(w, 11, why),
        LedgerApiError::Ledger(LedgerError::DuplicateKey(key)) => reason(w, 12, key),
        LedgerApiError::Ledger(LedgerError::InsufficientFunds {
            account,
            balance,
            requested,
        }) => {
            w.u8(13);
            put_account(w, *account);
            w.u64(*balance);
            w.u64(*requested);
        }
        LedgerApiError::Ledger(LedgerError::Invalid(why)) => reason(w, 14, why),
        LedgerApiError::Unavailable(why) => reason(w, 15, why),
    }
}

pub(crate) fn get_error(r: &mut R) -> Res<LedgerApiError> {
    Ok(match r.u8()? {
        0 => LedgerApiError::Unauthenticated(auth_error(r.u8()?)?),
        1 => LedgerApiError::Forbidden {
            role: ServiceRole::from_u8(r.u8()?).ok_or(Malformed)?,
            op: interned(&r.text()?),
        },
        2 => LedgerApiError::UnknownEscrow(r.u32()?),
        3 => LedgerApiError::EscrowExists(r.u32()?),
        4 => LedgerApiError::EscrowSettled(r.u32()?),
        5 => LedgerApiError::BadMandate,
        6 => LedgerApiError::MandateExceeded {
            job: r.u32()?,
            mandate: r.u64()?,
            requested_total: r.u128()?,
        },
        7 => LedgerApiError::BadProof(interned(&r.text()?)),
        8 => LedgerApiError::OutOfWindow(interned(&r.text()?)),
        9 => LedgerApiError::OpenItems(r.u32()?),
        10 => LedgerApiError::LimitExceeded(interned(&r.text()?)),
        11 => LedgerApiError::Invalid(interned(&r.text()?)),
        12 => LedgerApiError::Ledger(LedgerError::DuplicateKey(r.text()?)),
        13 => LedgerApiError::Ledger(LedgerError::InsufficientFunds {
            account: get_account(r)?,
            balance: r.u64()?,
            requested: r.u64()?,
        }),
        14 => LedgerApiError::Ledger(LedgerError::Invalid(interned(&r.text()?))),
        15 => LedgerApiError::Unavailable(interned(&r.text()?)),
        _ => return Err(Malformed),
    })
}

/// What a connected service may know about the ledger it talks to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerInfo {
    pub limits: LedgerLimits,
    pub domain: Domain,
    /// Ledger time.
    pub now: u64,
    /// Operations accepted so far.
    pub seq: u64,
}

pub(crate) fn put_info(w: &mut W, i: &LedgerInfo) {
    let l = &i.limits;
    for x in [
        l.max_amount,
        l.max_issue,
        l.supply_cap,
        l.commission_bps,
        l.reward_hold,
        l.contest_limit,
    ] {
        w.u64(x);
    }
    w.len(l.max_segments);
    w.bytes(i.domain.as_bytes());
    w.u64(i.now);
    w.u64(i.seq);
}

pub(crate) fn get_info(r: &mut R) -> Res<LedgerInfo> {
    Ok(LedgerInfo {
        limits: LedgerLimits {
            max_amount: r.u64()?,
            max_issue: r.u64()?,
            supply_cap: r.u64()?,
            commission_bps: r.u64()?,
            reward_hold: r.u64()?,
            contest_limit: r.u64()?,
            max_segments: usize::try_from(r.u32()?).map_err(|_| Malformed)?,
        },
        domain: Domain::from_bytes(r.array()?),
        now: r.u64()?,
        seq: r.u64()?,
    })
}

/// Counters an auditor compares between two views of the same ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerSummary {
    /// Entries in the journal.
    pub entries: u64,
    /// Hash of the last entry (0 for an empty journal).
    pub head: u64,
    pub seq: u64,
    pub now: u64,
    /// Requests refused so far.
    pub denied: u64,
}

/// A request, once the connection is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Execute(LedgerOp),
    /// Opens a transaction: what follows is applied entirely at `Commit` or not at all. Inside
    /// a transaction it opens a nested one, which `Abort` undoes alone.
    Begin,
    Commit,
    Abort,
    Info,
    /// Balance of one of a job's accounts (orchestrator).
    Balance(Account),
    /// Every balance (auditor).
    AuditBalances,
    AuditSummary,
    /// Registers the key of a new account (identity service).
    RegisterKey {
        account: u32,
        key: [u8; 32],
    },
    /// Delivers a revocation signed by the authority (any authenticated service).
    Revoke {
        service: u32,
        signature: [u8; 64],
    },
}

/// Why the link itself refused a request, apart from the ledger's own rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another connection holds a transaction: try again.
    Busy,
    NoTransaction,
    /// More transactions nested than allowed.
    TransactionTooDeep,
    /// The transaction held more operations than allowed and was rolled back.
    TransactionTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Outcome(LedgerOutcome),
    Denied(LedgerApiError),
    Done,
    Info(LedgerInfo),
    Balance(Amount),
    Balances(Vec<(Account, i128)>),
    Summary(LedgerSummary),
    Refused(Refusal),
}

/// Why the ledger ends a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Malformed,
    UnsupportedVersion,
    WrongDeployment,
    /// Certificate not signed by the authority, revoked, or its key not proved.
    Unauthenticated,
    /// A message that does not belong at this point of the connection.
    OutOfOrder,
}

const FAULTS: [Fault; 5] = [
    Fault::Malformed,
    Fault::UnsupportedVersion,
    Fault::WrongDeployment,
    Fault::Unauthenticated,
    Fault::OutOfOrder,
];

/// Every message of the link, both directions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Client: who it is and for which deployment, with a fresh nonce.
    Hello {
        version: u16,
        domain: Domain,
        cert: ServiceCertificate,
        nonce: [u8; 32],
    },
    /// Ledger: who it is, its own nonce, and its signature over both nonces.
    Challenge {
        cert: ServiceCertificate,
        nonce: [u8; 32],
        signature: [u8; 64],
    },
    /// Client: its signature over both nonces, with the key its certificate names.
    Proof {
        signature: [u8; 64],
    },
    Ready,
    Request {
        seq: u64,
        body: Request,
    },
    Response {
        seq: u64,
        body: Response,
    },
    Fault(Fault),
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::default();
        match self {
            Message::Hello {
                version,
                domain,
                cert,
                nonce,
            } => {
                w.u8(0x01);
                w.u16(*version);
                w.bytes(domain.as_bytes());
                put_cert(&mut w, cert);
                w.bytes(nonce);
            }
            Message::Challenge {
                cert,
                nonce,
                signature,
            } => {
                w.u8(0x02);
                put_cert(&mut w, cert);
                w.bytes(nonce);
                w.bytes(signature);
            }
            Message::Proof { signature } => {
                w.u8(0x03);
                w.bytes(signature);
            }
            Message::Ready => w.u8(0x04),
            Message::Request { seq, body } => {
                w.u8(0x10);
                w.u64(*seq);
                put_request(&mut w, body);
            }
            Message::Response { seq, body } => {
                w.u8(0x11);
                w.u64(*seq);
                put_response(&mut w, body);
            }
            Message::Fault(f) => {
                w.u8(0x7f);
                w.u8(FAULTS.iter().position(|x| x == f).map_or(0, |i| i as u8));
            }
        }
        w.0
    }

    pub fn decode(payload: &[u8]) -> Res<Message> {
        if payload.len() > MAX_FRAME {
            return Err(Malformed);
        }
        let mut r = R::new(payload);
        let m = match r.u8()? {
            0x01 => Message::Hello {
                version: r.u16()?,
                domain: Domain::from_bytes(r.array()?),
                cert: get_cert(&mut r)?,
                nonce: r.array()?,
            },
            0x02 => Message::Challenge {
                cert: get_cert(&mut r)?,
                nonce: r.array()?,
                signature: r.array()?,
            },
            0x03 => Message::Proof {
                signature: r.array()?,
            },
            0x04 => Message::Ready,
            0x10 => Message::Request {
                seq: r.u64()?,
                body: get_request(&mut r)?,
            },
            0x11 => Message::Response {
                seq: r.u64()?,
                body: get_response(&mut r)?,
            },
            0x7f => Message::Fault(*FAULTS.get(usize::from(r.u8()?)).ok_or(Malformed)?),
            _ => return Err(Malformed),
        };
        r.end()?;
        Ok(m)
    }
}

fn put_request(w: &mut W, q: &Request) {
    match q {
        Request::Execute(op) => {
            w.u8(0);
            put_op(w, op);
        }
        Request::Begin => w.u8(1),
        Request::Commit => w.u8(2),
        Request::Abort => w.u8(3),
        Request::Info => w.u8(4),
        Request::Balance(a) => {
            w.u8(5);
            put_account(w, *a);
        }
        Request::AuditBalances => w.u8(6),
        Request::AuditSummary => w.u8(7),
        Request::RegisterKey { account, key } => {
            w.u8(8);
            w.u32(*account);
            w.bytes(key);
        }
        Request::Revoke { service, signature } => {
            w.u8(9);
            w.u32(*service);
            w.bytes(signature);
        }
    }
}

fn get_request(r: &mut R) -> Res<Request> {
    Ok(match r.u8()? {
        0 => Request::Execute(get_op(r)?),
        1 => Request::Begin,
        2 => Request::Commit,
        3 => Request::Abort,
        4 => Request::Info,
        5 => Request::Balance(get_account(r)?),
        6 => Request::AuditBalances,
        7 => Request::AuditSummary,
        8 => Request::RegisterKey {
            account: r.u32()?,
            key: r.array()?,
        },
        9 => Request::Revoke {
            service: r.u32()?,
            signature: r.array()?,
        },
        _ => return Err(Malformed),
    })
}

const REFUSALS: [Refusal; 4] = [
    Refusal::Busy,
    Refusal::NoTransaction,
    Refusal::TransactionTooDeep,
    Refusal::TransactionTooLarge,
];

fn put_response(w: &mut W, p: &Response) {
    match p {
        Response::Outcome(o) => {
            w.u8(0);
            put_outcome(w, o);
        }
        Response::Denied(e) => {
            w.u8(1);
            put_error(w, e);
        }
        Response::Done => w.u8(2),
        Response::Info(i) => {
            w.u8(3);
            put_info(w, i);
        }
        Response::Balance(a) => {
            w.u8(4);
            w.u64(*a);
        }
        Response::Balances(all) => {
            w.u8(5);
            w.len(all.len());
            for (a, b) in all {
                put_account(w, *a);
                w.i128(*b);
            }
        }
        Response::Summary(s) => {
            w.u8(6);
            for x in [s.entries, s.head, s.seq, s.now, s.denied] {
                w.u64(x);
            }
        }
        Response::Refused(x) => {
            w.u8(7);
            w.u8(REFUSALS.iter().position(|y| y == x).map_or(0, |i| i as u8));
        }
    }
}

fn get_response(r: &mut R) -> Res<Response> {
    Ok(match r.u8()? {
        0 => Response::Outcome(get_outcome(r)?),
        1 => Response::Denied(get_error(r)?),
        2 => Response::Done,
        3 => Response::Info(get_info(r)?),
        4 => Response::Balance(r.u64()?),
        5 => {
            // An account takes at least one byte and a balance sixteen.
            let n = r.len(17)?;
            let mut all = Vec::with_capacity(n);
            for _ in 0..n {
                all.push((get_account(r)?, r.i128()?));
            }
            Response::Balances(all)
        }
        6 => Response::Summary(LedgerSummary {
            entries: r.u64()?,
            head: r.u64()?,
            seq: r.u64()?,
            now: r.u64()?,
            denied: r.u64()?,
        }),
        7 => Response::Refused(*REFUSALS.get(usize::from(r.u8()?)).ok_or(Malformed)?),
        _ => return Err(Malformed),
    })
}

/// What each side signs in the handshake: the deployment, both nonces and both identities, under
/// a tag of its own for each direction, so one side's signature can never stand for the other's.
pub fn transcript(
    server: bool,
    domain: &Domain,
    client: &ServiceCertificate,
    ledger: &ServiceCertificate,
    client_nonce: &[u8; 32],
    ledger_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut w = W::default();
    w.bytes(if server {
        b"more/link/ledger/v1"
    } else {
        b"more/link/client/v1"
    });
    w.bytes(domain.as_bytes());
    put_cert(&mut w, client);
    put_cert(&mut w, ledger);
    w.bytes(client_nonce);
    w.bytes(ledger_nonce);
    w.0
}
