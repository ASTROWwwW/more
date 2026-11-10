//! The ledger behind its link (LEDGER-021 to LEDGER-023): what travels, who may connect, what a
//! connection may do, and that the ledger behind the link is the same ledger.
//!
//! Every test talks to the host through payloads only, as a socket would carry them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::hostile::*;
use common::*;
use gpu_ledger::link::*;
use gpu_ledger::*;
use more_identity::{AuthError, IdentityAuthority, ServiceCredential, ServiceRole};
use proptest::prelude::*;

fn host_of(w: &World) -> Arc<Mutex<LedgerHost>> {
    w.mirror.as_ref().unwrap().host.clone().unwrap()
}

/// A world behind the link and the environment its new connections share.
fn wired() -> (World, TestEnv) {
    (mirrored_world(), TestEnv::default())
}

fn raw(w: &World, env: &TestEnv) -> Loopback {
    Loopback::new(host_of(w), Box::new(env.clone()))
}

fn connect(
    w: &World,
    env: &TestEnv,
    me: &ServiceCredential,
) -> Result<LedgerClient<Loopback>, LinkError> {
    LedgerClient::connect(raw(w, env), me, &w.auth.verifier(), [7; 32])
}

fn state(w: &World) -> LedgerService {
    host_of(w).lock().unwrap().service().clone()
}

fn say(link: &mut Loopback, m: &Message) -> Message {
    link.send(&m.encode()).unwrap();
    Message::decode(&link.recv().unwrap()).unwrap()
}

fn sample_ops() -> Vec<LedgerOp> {
    let l = line(2, L1);
    let item = ItemId::Recovery {
        attempt: 2,
        segment: 1,
    };
    vec![
        LedgerOp::Advance { now: 77 },
        LedgerOp::Issue {
            key: "issue/é".into(),
            to: IssueTo::Pool(POOL),
            amount: 9,
        },
        LedgerOp::Issue {
            key: String::new(),
            to: IssueTo::User(ALICE),
            amount: u64::MAX,
        },
        LedgerOp::OpenEscrow {
            job: JOB,
            owner: ALICE,
            pool: POOL,
            terms: terms(500),
            signature: [3; 64],
        },
        LedgerOp::Reserve {
            job: JOB,
            bucket: EscrowBucket::Recovery,
            key: "r/1".into(),
            amount: 5,
        },
        LedgerOp::Reserve {
            job: JOB,
            bucket: EscrowBucket::Work,
            key: "r/2".into(),
            amount: 6,
        },
        LedgerOp::RegisterPool {
            pool: POOL,
            admin: ADMIN,
        },
        LedgerOp::FundRecovery {
            job: JOB,
            amount: 4,
            signature: [4; 64],
        },
        LedgerOp::RegisterAttempt {
            assignment: assignment(2, &[L1, L2], &[3, 1], 8),
        },
        LedgerOp::AcceptLease {
            job: JOB,
            attempt: 2,
            stage: 1,
            signature: [5; 64],
        },
        LedgerOp::LeaseReady {
            job: JOB,
            attempt: 2,
            stage: 0,
            restored: [1, 2, 3],
            state: STATE,
            segments: SEGS.to_vec(),
            signature: [6; 64],
        },
        LedgerOp::RecordRestore {
            job: JOB,
            attempt: 2,
            producer: L1,
            segments: vec![0, 2],
            signature: [7; 64],
        },
        LedgerOp::RevokeAttempt {
            job: JOB,
            attempt: 2,
        },
        LedgerOp::RecordReceipt {
            job: JOB,
            attempt: 1,
            producer: L1,
            wt: WT,
            upto: 3,
            digest: 11,
            signature: [8; 64],
        },
        LedgerOp::ChargeOutput {
            job: JOB,
            attempt: 1,
            output: out(4),
            gen: 1,
        },
        LedgerOp::VoidOutput {
            job: JOB,
            output: out(4),
            gen: 1,
        },
        LedgerOp::ReserveContribution {
            line: l,
            output: out(2),
            gen: 0,
            stage: 1,
        },
        LedgerOp::ReserveRecovery {
            line: l,
            segment: 1,
            amount: 3,
        },
        LedgerOp::PayLine { line: l, item },
        LedgerOp::RefundLine {
            line: l,
            item: ItemId::Contribution {
                output: out(2),
                gen: 0,
                stage: 1,
            },
        },
        LedgerOp::ReleaseReward { line: l },
        LedgerOp::ContestReward { line: l },
        LedgerOp::ReturnEarmark {
            job: JOB,
            attempt: 2,
        },
        LedgerOp::SettleJob { job: JOB },
    ]
}

fn sample_errors() -> Vec<LedgerApiError> {
    let role = ServiceRole::Orchestrator;
    vec![
        LedgerApiError::Unauthenticated(AuthError::RevokedCredential),
        LedgerApiError::Unauthenticated(AuthError::UnknownAccount),
        LedgerApiError::Forbidden { role, op: "Issue" },
        LedgerApiError::UnknownEscrow(1),
        LedgerApiError::EscrowExists(2),
        LedgerApiError::EscrowSettled(3),
        LedgerApiError::BadMandate,
        LedgerApiError::MandateExceeded {
            job: 4,
            mandate: 5,
            requested_total: u128::MAX,
        },
        LedgerApiError::BadProof("lease not signed by the stage's lender"),
        LedgerApiError::OutOfWindow("contest limit reached"),
        LedgerApiError::OpenItems(6),
        LedgerApiError::LimitExceeded("too many recovery segments"),
        LedgerApiError::Invalid("unknown attempt"),
        LedgerApiError::Ledger(LedgerError::DuplicateKey("issue/1".into())),
        LedgerApiError::Ledger(LedgerError::InsufficientFunds {
            account: line(1, L1).reward_account(),
            balance: 1,
            requested: 2,
        }),
        LedgerApiError::Ledger(LedgerError::Invalid("zero amount")),
        LedgerApiError::Unavailable("the ledger is busy"),
    ]
}

fn sample_messages(w: &World) -> Vec<Message> {
    let cert = w.orch.certificate();
    let accounts = [
        Account::Issuance,
        Account::Burn,
        Account::User(1),
        Account::PoolReserve(2),
        Account::EscrowWork(3),
        Account::EscrowRecovery(4),
        Account::OutputHold(5),
        line(1, L1).line_account(),
        line(1, L1).reward_account(),
        Account::Commission,
    ];
    let outcomes = [
        LedgerOutcome::Done,
        LedgerOutcome::Moved(8),
        LedgerOutcome::Paid {
            amount: 6,
            pool_part: 2,
        },
        LedgerOutcome::Released {
            to_lender: 5,
            commission: 1,
        },
        LedgerOutcome::Contested {
            to_pool: 1,
            to_owner: 5,
        },
        LedgerOutcome::Settled {
            to_pool: 3,
            to_owner: 4,
        },
    ];
    let info = LedgerInfo {
        limits: LedgerLimits::default(),
        domain: dom(),
        now: 5,
        seq: 6,
    };
    let summary = LedgerSummary {
        entries: 1,
        head: 2,
        seq: 3,
        now: 4,
        denied: 5,
    };
    let mut bodies = vec![
        Request::Begin,
        Request::Commit,
        Request::Abort,
        Request::Info,
        Request::AuditBalances,
        Request::AuditSummary,
        Request::RegisterKey {
            account: 9,
            key: [1; 32],
        },
        Request::Revoke {
            service: 3,
            signature: [2; 64],
        },
    ];
    bodies.extend(sample_ops().into_iter().map(Request::Execute));
    bodies.extend(accounts.into_iter().map(Request::Balance));
    let mut answers = vec![
        Response::Done,
        Response::Info(info),
        Response::Balance(7),
        Response::Balances(accounts.iter().map(|a| (*a, -3)).collect()),
        Response::Balances(Vec::new()),
        Response::Summary(summary),
    ];
    answers.extend(outcomes.into_iter().map(Response::Outcome));
    answers.extend(sample_errors().into_iter().map(Response::Denied));
    for r in [
        Refusal::Busy,
        Refusal::NoTransaction,
        Refusal::TransactionTooDeep,
        Refusal::TransactionTooLarge,
    ] {
        answers.push(Response::Refused(r));
    }
    let mut all = vec![
        Message::Hello {
            version: LINK_VERSION,
            domain: dom(),
            cert,
            nonce: [1; 32],
        },
        Message::Challenge {
            cert,
            nonce: [2; 32],
            signature: [3; 64],
        },
        Message::Proof { signature: [4; 64] },
        Message::Ready,
    ];
    for f in [
        Fault::Malformed,
        Fault::UnsupportedVersion,
        Fault::WrongDeployment,
        Fault::Unauthenticated,
        Fault::OutOfOrder,
    ] {
        all.push(Message::Fault(f));
    }
    all.extend(
        bodies
            .into_iter()
            .map(|body| Message::Request { seq: 3, body }),
    );
    all.extend(
        answers
            .into_iter()
            .map(|body| Message::Response { seq: 3, body }),
    );
    all
}

/// LEDGER-021: every message decodes to itself, and nothing shorter or longer decodes at all.
#[test]
fn every_message_round_trips_and_nothing_else_decodes() {
    let w = bare_world();
    let kinds: std::collections::BTreeSet<&str> = sample_ops().iter().map(|o| o.kind()).collect();
    assert_eq!(kinds.len(), 22, "one sample per kind of operation");
    for m in sample_messages(&w) {
        let bytes = m.encode();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(Message::decode(&bytes), Ok(m.clone()), "{m:?}");
        for cut in 0..bytes.len() {
            assert_eq!(
                Message::decode(&bytes[..cut]),
                Err(Malformed),
                "{m:?} cut at {cut}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            Message::decode(&longer),
            Err(Malformed),
            "{m:?} with a trailing byte"
        );
    }
}

/// A length read from the wire is checked against the bytes that follow before anything is
/// allocated, and a payload above the frame limit is not looked at.
#[test]
fn the_decoder_never_trusts_a_length() {
    let ready = LedgerOp::LeaseReady {
        job: JOB,
        attempt: 1,
        stage: 0,
        restored: [0; 3],
        state: 1,
        segments: vec![1, 2],
        signature: [0; 64],
    };
    let m = Message::Request {
        seq: 1,
        body: Request::Execute(ready),
    };
    let mut bytes = m.encode();
    // The list length sits after tag, seq, body tag, op tag, 3 ids, 3 positions and the state.
    let at = 1 + 8 + 1 + 1 + 12 + 12 + 8;
    assert_eq!(bytes[at..at + 4], 2u32.to_le_bytes());
    for claimed in [3u32, 1_000, u32::MAX] {
        bytes[at..at + 4].copy_from_slice(&claimed.to_le_bytes());
        assert_eq!(Message::decode(&bytes), Err(Malformed), "{claimed}");
    }
    let huge = vec![0x04; MAX_FRAME + 1];
    assert_eq!(Message::decode(&huge), Err(Malformed));
    // An idempotency key longer than the limit is cut by the sender and refused by the reader.
    let long = LedgerOp::Issue {
        key: "k".repeat(500),
        to: IssueTo::User(ALICE),
        amount: 1,
    };
    let sent = Message::Request {
        seq: 1,
        body: Request::Execute(long),
    };
    let Ok(Message::Request {
        body: Request::Execute(LedgerOp::Issue { key, .. }),
        ..
    }) = Message::decode(&sent.encode())
    else {
        panic!("a cut key still decodes");
    };
    assert_eq!(key.len(), 160);
}

/// LEDGER-022: each service connects with its own key and gets its own role, and the client
/// checks that the other end is this deployment's ledger.
#[test]
fn a_service_connects_as_itself_only() {
    let (w, env) = wired();
    for me in [
        &w.orch,
        &w.treasury,
        &w.clock,
        &w.platform,
        &w.auditor,
        &w.identity,
    ] {
        let mut c = connect(&w, &env, me).unwrap();
        assert_eq!(c.ledger(), w.ledger_id.certificate());
        assert_eq!(c.info().unwrap().domain, dom());
    }
    // Another deployment's service, with a certificate its own authority signed.
    let mut elsewhere = IdentityAuthority::new([4; 32]);
    let stranger = elsewhere.issue(ServiceRole::Treasury);
    let other = LedgerClient::connect(raw(&w, &env), &stranger, &elsewhere.verifier(), [1; 32]);
    assert_eq!(other.err(), Some(LinkError::Fault(Fault::WrongDeployment)));
    // The same certificate presented for this deployment: not signed by this authority.
    let mut link = raw(&w, &env);
    let hello = |cert, version| Message::Hello {
        version,
        domain: dom(),
        cert,
        nonce: [1; 32],
    };
    let answer = say(&mut link, &hello(stranger.certificate(), LINK_VERSION));
    assert_eq!(answer, Message::Fault(Fault::Unauthenticated));
    assert!(link.send(&Message::Ready.encode()).is_err(), "closed");
    let mut link = raw(&w, &env);
    let answer = say(&mut link, &hello(w.orch.certificate(), LINK_VERSION + 1));
    assert_eq!(answer, Message::Fault(Fault::UnsupportedVersion));
}

/// LEDGER-022, the reason for it: a certificate is public. Whoever copied the treasury's
/// certificate, the orchestrator's process included, cannot connect as the treasury without
/// the treasury's key.
#[test]
fn a_copied_certificate_does_not_open_a_connection() {
    let (w, env) = wired();
    let stolen = w.treasury.certificate();
    let before = state(&w);
    let attempt = |sign: &dyn Fn(&[u8]) -> [u8; 64]| {
        let mut link = raw(&w, &env);
        let nonce = [9; 32];
        let hello = Message::Hello {
            version: LINK_VERSION,
            domain: dom(),
            cert: stolen,
            nonce,
        };
        let Message::Challenge {
            cert,
            nonce: theirs,
            ..
        } = say(&mut link, &hello)
        else {
            panic!("the certificate itself is valid");
        };
        let signed = transcript(false, &dom(), &stolen, &cert, &nonce, &theirs);
        let proof = Message::Proof {
            signature: sign(&signed),
        };
        let answer = say(&mut link, &proof);
        (answer, link)
    };
    // Signed with the key the attacker does hold, or not signed at all.
    for sign in [
        &(|m: &[u8]| w.orch.sign(m)) as &dyn Fn(&[u8]) -> [u8; 64],
        &|_: &[u8]| [0u8; 64],
    ] {
        let (answer, mut link) = attempt(sign);
        assert_eq!(answer, Message::Fault(Fault::Unauthenticated));
        let issue = Message::Request {
            seq: 1,
            body: Request::Execute(LedgerOp::Issue {
                key: "stolen".into(),
                to: IssueTo::User(MALLORY),
                amount: 1_000,
            }),
        };
        assert!(
            link.send(&issue.encode()).is_err(),
            "the connection is closed"
        );
    }
    // The real treasury, same exchange: accepted.
    let (answer, _link) = attempt(&|m: &[u8]| w.treasury.sign(m));
    assert_eq!(answer, Message::Ready);
    assert!(state(&w) == before, "nothing was written");
}

/// A proof is good for one connection: the ledger's nonce changes, so a recorded exchange
/// replayed later is refused.
#[test]
fn a_recorded_handshake_cannot_be_replayed() {
    let (w, env) = wired();
    let me = w.treasury.certificate();
    let nonce = [9; 32];
    let hello = Message::Hello {
        version: LINK_VERSION,
        domain: dom(),
        cert: me,
        nonce,
    };
    let mut first = raw(&w, &env);
    let Message::Challenge {
        cert,
        nonce: theirs,
        ..
    } = say(&mut first, &hello)
    else {
        panic!("challenge expected");
    };
    let proof = Message::Proof {
        signature: w
            .treasury
            .sign(&transcript(false, &dom(), &me, &cert, &nonce, &theirs)),
    };
    assert_eq!(say(&mut first, &proof), Message::Ready);
    // The attacker saw both messages and sends them again on a connection of its own.
    let mut second = raw(&w, &env);
    let Message::Challenge { nonce: again, .. } = say(&mut second, &hello) else {
        panic!("challenge expected");
    };
    assert_ne!(again, theirs, "a fresh nonce for each connection");
    assert_eq!(
        say(&mut second, &proof),
        Message::Fault(Fault::Unauthenticated)
    );
    // Nor does the ledger's own signature serve as a client's proof.
    let mut third = raw(&w, &env);
    let Message::Challenge { signature, .. } = say(&mut third, &hello) else {
        panic!("challenge expected");
    };
    let reflected = Message::Proof { signature };
    assert_eq!(
        say(&mut third, &reflected),
        Message::Fault(Fault::Unauthenticated)
    );
}

/// Messages have an order. Anything out of it ends the connection.
#[test]
fn the_handshake_has_one_order() {
    let (w, env) = wired();
    let info = Message::Request {
        seq: 1,
        body: Request::Info,
    };
    let hello = Message::Hello {
        version: LINK_VERSION,
        domain: dom(),
        cert: w.orch.certificate(),
        nonce: [1; 32],
    };
    let proof = Message::Proof { signature: [0; 64] };
    for early in [&info, &proof, &Message::Ready] {
        let mut link = raw(&w, &env);
        assert_eq!(say(&mut link, early), Message::Fault(Fault::OutOfOrder));
        assert!(link.send(&hello.encode()).is_err());
    }
    // A request between the challenge and the proof.
    let mut link = raw(&w, &env);
    assert!(matches!(say(&mut link, &hello), Message::Challenge { .. }));
    assert_eq!(say(&mut link, &info), Message::Fault(Fault::OutOfOrder));
    // Sequence numbers go up one by one.
    for wrong in [0u64, 2, 7] {
        let mut c = connect(&w, &env, &w.orch).unwrap();
        c.info().unwrap();
        let mut link = raw(&w, &env);
        let me = &w.orch;
        let nonce = [3; 32];
        let Message::Challenge {
            cert,
            nonce: theirs,
            ..
        } = say(
            &mut link,
            &Message::Hello {
                version: LINK_VERSION,
                domain: dom(),
                cert: me.certificate(),
                nonce,
            },
        )
        else {
            panic!("challenge expected");
        };
        let signed = transcript(false, &dom(), &me.certificate(), &cert, &nonce, &theirs);
        let ready = say(
            &mut link,
            &Message::Proof {
                signature: me.sign(&signed),
            },
        );
        assert_eq!(ready, Message::Ready);
        let skipped = Message::Request {
            seq: wrong,
            body: Request::Info,
        };
        assert_eq!(say(&mut link, &skipped), Message::Fault(Fault::OutOfOrder));
    }
    // A second hello on an authenticated connection.
    let mut link = raw(&w, &env);
    let _ = say(&mut link, &hello);
    assert_eq!(say(&mut link, &hello), Message::Fault(Fault::OutOfOrder));
}

/// What stands in for a ledger must be this deployment's ledger: certified by the authority,
/// with the role `Ledger`, and holding that key.
struct Impostor {
    as_who: ServiceCredential,
    signs: ServiceCredential,
    out: Option<Vec<u8>>,
}

impl Transport for Impostor {
    fn send(&mut self, payload: &[u8]) -> Result<(), LinkError> {
        if let Ok(Message::Hello {
            domain,
            cert,
            nonce,
            ..
        }) = Message::decode(payload)
        {
            let mine = self.as_who.certificate();
            let theirs = [8; 32];
            let signed = transcript(true, &domain, &cert, &mine, &nonce, &theirs);
            let challenge = Message::Challenge {
                cert: mine,
                nonce: theirs,
                signature: self.signs.sign(&signed),
            };
            self.out = Some(challenge.encode());
        } else {
            self.out = Some(Message::Ready.encode());
        }
        Ok(())
    }
    fn recv(&mut self) -> Result<Vec<u8>, LinkError> {
        self.out.take().ok_or(LinkError::Io("nothing".into()))
    }
}

#[test]
fn a_client_refuses_anything_but_its_deployments_ledger() {
    let w = bare_world();
    let mut elsewhere = IdentityAuthority::new([4; 32]);
    let foreign_ledger = elsewhere.issue(ServiceRole::Ledger);
    let dial = |as_who: &ServiceCredential, signs: &ServiceCredential| {
        let fake = Impostor {
            as_who: as_who.clone(),
            signs: signs.clone(),
            out: None,
        };
        LedgerClient::connect(fake, &w.orch, &w.auth.verifier(), [1; 32]).map(|_| ())
    };
    // A real service of this deployment that is not the ledger.
    assert_eq!(dial(&w.treasury, &w.treasury), Err(LinkError::NotTheLedger));
    // A ledger certified by another authority.
    assert_eq!(
        dial(&foreign_ledger, &foreign_ledger),
        Err(LinkError::NotTheLedger)
    );
    // The real ledger's certificate, shown by someone who does not hold its key.
    assert_eq!(dial(&w.ledger_id, &w.orch), Err(LinkError::NotTheLedger));
    assert_eq!(dial(&w.ledger_id, &w.ledger_id), Ok(()));
}

/// LEDGER-022: a revocation takes effect on the next request of an open connection, and it
/// travels as a statement only the authority can have signed.
#[test]
fn a_revoked_service_is_cut_off_on_its_next_request() {
    let (w, env) = wired();
    let mut orch = connect(&w, &env, &w.orch).unwrap();
    let mut clock = connect(&w, &env, &w.clock).unwrap();
    orch.info().unwrap();
    let id = w.orch.id().0;
    // Anyone connected may deliver a revocation; nobody but the authority can make one.
    let mut other = IdentityAuthority::new([4; 32]);
    let _ = other.issue(ServiceRole::Clock);
    let forged = other.revocation(w.orch.id());
    assert_eq!(
        clock.revoke(id, forged).unwrap(),
        Err(LedgerApiError::Unauthenticated(AuthError::BadSignature))
    );
    orch.info().unwrap();
    // Revoked in the middle of a transaction: the transaction is rolled back with it.
    orch.begin().unwrap().unwrap();
    let before = state(&w);
    w.auth.revoke(w.orch.id());
    let reserve = LedgerOp::Reserve {
        job: JOB,
        bucket: EscrowBucket::Work,
        key: "late".into(),
        amount: 1,
    };
    assert_eq!(
        orch.execute(reserve),
        Err(LinkError::Fault(Fault::Unauthenticated))
    );
    assert!(orch.info().is_err(), "closed");
    assert_eq!(
        connect(&w, &env, &w.orch).err(),
        Some(LinkError::Fault(Fault::Unauthenticated))
    );
    // The clock is not affected, and the ledger is free again.
    clock
        .execute(LedgerOp::Advance { now: 5 })
        .unwrap()
        .unwrap();
    assert_eq!(state(&w).now(), 5);
    assert_eq!(before.now(), 0);
}

/// The signed revocation, delivered over the link to a ledger that has no other way to learn
/// of it.
#[test]
fn a_signed_revocation_reaches_a_ledger_that_only_knows_the_authoritys_key() {
    let w = bare_world();
    // This host's verifier was built from the public key alone: it shares nothing with the
    // authority.
    let verifier = more_identity::CredentialVerifier::for_domain(dom()).unwrap();
    let service = LedgerService::new(verifier.clone(), w.keys.clone(), LedgerLimits::default());
    let host = LedgerHost::new(
        service,
        w.keys.clone(),
        verifier,
        w.ledger_id.clone(),
        HostLimits::default(),
    )
    .unwrap();
    let host = Arc::new(Mutex::new(host));
    let env = TestEnv::default();
    let dial = |me: &ServiceCredential| {
        let link = Loopback::new(host.clone(), Box::new(env.clone()));
        LedgerClient::connect(link, me, &w.auth.verifier(), [2; 32])
    };
    let mut treasury = dial(&w.treasury).unwrap();
    let mut clock = dial(&w.clock).unwrap();
    w.auth.revoke(w.treasury.id());
    treasury.info().expect("the host has not heard of it yet");
    let statement = w.auth.revocation(w.treasury.id());
    assert_eq!(clock.revoke(w.treasury.id().0, statement).unwrap(), Ok(()));
    assert_eq!(
        treasury.info().err(),
        Some(LinkError::Fault(Fault::Unauthenticated))
    );
    assert_eq!(
        dial(&w.treasury).err(),
        Some(LinkError::Fault(Fault::Unauthenticated))
    );
}

/// LEDGER-022: a connection can only do what its service may do. Nothing in a request says who
/// is asking, so there is nothing to forge.
#[test]
fn a_connection_has_its_own_rights_and_no_other() {
    let (mut w, env) = wired();
    w.open(JOB, 500).unwrap();
    w.reserve(EscrowBucket::Work, 100).unwrap();
    let before = state(&w);
    let forbidden = |r: Result<Response, LinkError>, role, op: &'static str| {
        assert_eq!(
            r,
            Ok(Response::Denied(LedgerApiError::Forbidden { role, op })),
            "{role:?} {op}"
        );
    };
    let issue = LedgerOp::Issue {
        key: "x".into(),
        to: IssueTo::User(MALLORY),
        amount: 10,
    };
    let reserve = LedgerOp::Reserve {
        job: JOB,
        bucket: EscrowBucket::Work,
        key: "y".into(),
        amount: 1,
    };
    let pool = LedgerOp::RegisterPool { pool: 9, admin: 9 };
    let advance = LedgerOp::Advance { now: 1 << 40 };
    let register = Request::RegisterKey {
        account: 99,
        key: key(99).public().to_bytes(),
    };
    use ServiceRole::*;
    // The orchestrator: its own operations and its jobs' balances, nothing else.
    let mut c = connect(&w, &env, &w.orch).unwrap();
    forbidden(
        c.call(Request::Execute(issue.clone())),
        Orchestrator,
        "Issue",
    );
    forbidden(
        c.call(Request::Execute(advance.clone())),
        Orchestrator,
        "Advance",
    );
    forbidden(
        c.call(Request::Execute(pool.clone())),
        Orchestrator,
        "RegisterPool",
    );
    forbidden(c.call(Request::AuditBalances), Orchestrator, "audit_view");
    forbidden(c.call(Request::AuditSummary), Orchestrator, "audit_view");
    forbidden(c.call(register.clone()), Orchestrator, "RegisterKey");
    forbidden(
        c.call(Request::Balance(Account::User(ALICE))),
        Orchestrator,
        "job_balance",
    );
    assert_eq!(c.balance(Account::EscrowWork(JOB)).unwrap(), Ok(100));
    // Every other service: never an orchestrator's operation, never a transaction.
    for (me, role) in [
        (&w.treasury, Treasury),
        (&w.clock, Clock),
        (&w.platform, PlatformAdmin),
        (&w.auditor, Auditor),
        (&w.identity, Identity),
    ] {
        let mut c = connect(&w, &env, me).unwrap();
        forbidden(c.call(Request::Execute(reserve.clone())), role, "Reserve");
        forbidden(c.call(Request::Begin), role, "Begin");
        if role != Treasury {
            forbidden(c.call(Request::Execute(issue.clone())), role, "Issue");
        }
        if role != Clock {
            forbidden(c.call(Request::Execute(advance.clone())), role, "Advance");
        }
        if role != Identity {
            forbidden(c.call(register.clone()), role, "RegisterKey");
        }
        if role != Auditor {
            forbidden(c.call(Request::AuditBalances), role, "audit_view");
        }
        forbidden(
            c.call(Request::Balance(Account::EscrowWork(JOB))),
            role,
            "job_balance",
        );
    }
    // Refusals are counted and logged by the ledger; nothing else moved.
    let after = state(&w);
    let (old, new) = (
        before.audit_view(&w.auditor).unwrap(),
        after.audit_view(&w.auditor).unwrap(),
    );
    assert_eq!(old.entries(), new.entries());
    assert_eq!((before.seq(), before.now()), (after.seq(), after.now()));
    // The identity service registers a key, once; then statements by that account verify.
    let mut ids = connect(&w, &env, &w.identity).unwrap();
    assert_eq!(ids.call(register.clone()), Ok(Response::Done));
    assert_eq!(
        ids.call(register),
        Ok(Response::Denied(LedgerApiError::Unauthenticated(
            AuthError::KeyAlreadyRegistered
        )))
    );
    assert!(w.keys.contains(99));
}

fn reserve(n: u32) -> LedgerOp {
    LedgerOp::Reserve {
        job: JOB,
        bucket: EscrowBucket::Work,
        key: format!("tx/{n}"),
        amount: 10,
    }
}

/// LEDGER-023: what the orchestrator does between `Begin` and `Commit` is applied entirely or
/// not at all, nobody else sees it meanwhile, and it cannot hold the ledger for ever.
#[test]
fn a_transaction_is_all_or_nothing_and_bounded() {
    let (mut w, env) = wired();
    w.open(JOB, 500).unwrap();
    let mut orch = connect(&w, &env, &w.orch).unwrap();
    let mut clock = connect(&w, &env, &w.clock).unwrap();
    let mut auditor = connect(&w, &env, &w.auditor).unwrap();
    let refused = |r: Result<Result<(), LedgerApiError>, LinkError>, why| {
        assert_eq!(r, Err(LinkError::Refused(why)));
    };
    refused(orch.commit(), Refusal::NoTransaction);
    refused(orch.abort(), Refusal::NoTransaction);
    let before = state(&w);
    // Aborted: two reserves and a refused operation leave no trace at all.
    orch.begin().unwrap().unwrap();
    orch.execute(reserve(1)).unwrap().unwrap();
    orch.execute(reserve(2)).unwrap().unwrap();
    assert!(orch.execute(reserve(2)).unwrap().is_err(), "duplicate key");
    assert!(state(&w) != before);
    // A nested transaction is undone alone, or kept until the outer one decides.
    let outer = state(&w);
    orch.begin().unwrap().unwrap();
    orch.execute(reserve(6)).unwrap().unwrap();
    orch.abort().unwrap().unwrap();
    assert!(
        state(&w) == outer,
        "the nested abort undoes its own part only"
    );
    orch.begin().unwrap().unwrap();
    orch.execute(reserve(7)).unwrap().unwrap();
    orch.commit().unwrap().unwrap();
    assert!(state(&w) != outer, "kept, for now");
    // Nesting is bounded.
    let depth = HostLimits::default().max_tx_depth;
    for _ in 1..depth {
        orch.begin().unwrap().unwrap();
    }
    refused(orch.begin(), Refusal::TransactionTooDeep);
    for _ in 1..depth {
        orch.commit().unwrap().unwrap();
    }
    // Meanwhile the others wait: they neither write nor read uncommitted state.
    assert_eq!(
        clock.execute(LedgerOp::Advance { now: 9 }),
        Err(LinkError::Refused(Refusal::Busy))
    );
    assert_eq!(
        auditor.audit_balances(),
        Err(LinkError::Refused(Refusal::Busy))
    );
    assert_eq!(auditor.info(), Err(LinkError::Refused(Refusal::Busy)));
    orch.abort().unwrap().unwrap();
    assert!(state(&w) == before, "abort restores the ledger exactly");
    refused(orch.commit(), Refusal::NoTransaction);
    // Committed: kept, and visible to the others from then on.
    orch.begin().unwrap().unwrap();
    orch.execute(reserve(1)).unwrap().unwrap();
    orch.commit().unwrap().unwrap();
    assert_eq!(orch.balance(Account::EscrowWork(JOB)).unwrap(), Ok(10));
    assert!(auditor.audit_balances().unwrap().is_ok());
    // A connection that goes away takes its uncommitted work with it.
    let kept = state(&w);
    let mut gone = connect(&w, &env, &w.orch).unwrap();
    gone.begin().unwrap().unwrap();
    gone.execute(reserve(3)).unwrap().unwrap();
    drop(gone);
    assert!(state(&w) == kept);
    // So does one that sends garbage in the middle.
    let mut link = raw(&w, &env);
    let me = &w.orch;
    let nonce = [5; 32];
    let hello = Message::Hello {
        version: LINK_VERSION,
        domain: dom(),
        cert: me.certificate(),
        nonce,
    };
    let Message::Challenge {
        cert,
        nonce: theirs,
        ..
    } = say(&mut link, &hello)
    else {
        panic!("challenge expected");
    };
    let signed = transcript(false, &dom(), &me.certificate(), &cert, &nonce, &theirs);
    let proof = Message::Proof {
        signature: me.sign(&signed),
    };
    assert_eq!(say(&mut link, &proof), Message::Ready);
    for (seq, body) in [(1, Request::Begin), (2, Request::Execute(reserve(4)))] {
        let m = Message::Request { seq, body };
        assert!(matches!(say(&mut link, &m), Message::Response { .. }));
    }
    link.send(&[0xee, 1, 2]).unwrap();
    assert_eq!(
        Message::decode(&link.recv().unwrap()),
        Ok(Message::Fault(Fault::Malformed))
    );
    assert!(state(&w) == kept);
    // A transaction held too long is rolled back as soon as someone else needs the ledger.
    orch.begin().unwrap().unwrap();
    orch.execute(reserve(5)).unwrap().unwrap();
    let limit = HostLimits::default().tx_timeout_ms;
    env.now_ms.store(limit - 1, Ordering::Relaxed);
    assert_eq!(
        clock.execute(LedgerOp::Advance { now: 9 }),
        Err(LinkError::Refused(Refusal::Busy))
    );
    env.now_ms.store(limit, Ordering::Relaxed);
    clock
        .execute(LedgerOp::Advance { now: 9 })
        .unwrap()
        .unwrap();
    refused(orch.commit(), Refusal::NoTransaction);
    let after = state(&w);
    assert_eq!(after.now(), 9);
    assert_eq!(orch.balance(Account::EscrowWork(JOB)).unwrap(), Ok(10));
}

/// A transaction has a size limit; past it, it is rolled back, not cut.
#[test]
fn a_transaction_too_large_is_rolled_back() {
    let w = bare_world();
    let limits = HostLimits {
        max_tx_ops: 3,
        ..HostLimits::default()
    };
    let service = LedgerService::new(w.auth.verifier(), w.keys.clone(), LedgerLimits::default());
    let host = LedgerHost::new(
        service,
        w.keys.clone(),
        w.auth.verifier(),
        w.ledger_id.clone(),
        limits,
    )
    .unwrap();
    let host = Arc::new(Mutex::new(host));
    let link = Loopback::new(host.clone(), Box::new(TestEnv::default()));
    let mut orch = LedgerClient::connect(link, &w.orch, &w.auth.verifier(), [1; 32]).unwrap();
    let before = host.lock().unwrap().service().clone();
    orch.begin().unwrap().unwrap();
    for n in 0..3 {
        // Refused or not, an operation counts.
        let _ = orch.execute(reserve(n)).unwrap();
    }
    assert_eq!(
        orch.execute(reserve(3)),
        Err(LinkError::Refused(Refusal::TransactionTooLarge))
    );
    assert!(*host.lock().unwrap().service() == before);
    assert_eq!(
        orch.commit(),
        Err(LinkError::Refused(Refusal::NoTransaction))
    );
}

/// A host does not start on an identity that is not a ledger's, on another deployment's
/// ledger, or on limits that could strand a payment.
#[test]
fn a_host_checks_what_it_is_given() {
    let w = bare_world();
    let service = |limits| LedgerService::new(w.auth.verifier(), w.keys.clone(), limits);
    let start = |svc: LedgerService, verifier, id: &ServiceCredential| {
        LedgerHost::new(
            svc,
            w.keys.clone(),
            verifier,
            id.clone(),
            HostLimits::default(),
        )
        .map(|_| ())
    };
    let ok = LedgerLimits::default();
    assert!(start(service(ok.clone()), w.auth.verifier(), &w.ledger_id).is_ok());
    assert!(start(service(ok.clone()), w.auth.verifier(), &w.orch).is_err());
    let mut elsewhere = IdentityAuthority::new([4; 32]);
    let foreign = elsewhere.issue(ServiceRole::Ledger);
    assert!(start(service(ok.clone()), w.auth.verifier(), &foreign).is_err());
    assert!(start(service(ok.clone()), elsewhere.verifier(), &foreign).is_err());
    let stuck = LedgerLimits {
        contest_limit: ok.reward_hold - 1,
        ..ok
    };
    assert!(start(service(stuck), w.auth.verifier(), &w.ledger_id).is_err());
}

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(256), failure_persistence: None, ..ProptestConfig::default() })]

    /// TEST-P35: the hostile orchestrator of TEST-P30, with every call also sent over the link
    /// to a second ledger. Call after call the two give the same answer and hold the same
    /// state, so everything TEST-P30 shows of the ledger holds of the ledger behind the link.
    #[test]
    fn p35_behind_the_link_the_ledger_is_the_same_ledger(
        seq in prop::collection::vec(calls(), 1..120)
    ) {
        let mut w = mirrored_world();
        w.open(JOB, 500).unwrap();
        for c in &seq {
            let _ = apply(&mut w, c);
            check(&w, c)?;
        }
    }

    /// TEST-P36: transactions over the link against plain copy-and-restore. Groups of hostile
    /// calls are committed or aborted; an aborted group must leave the ledger behind the link
    /// exactly as a restored copy.
    #[test]
    fn p36_transactions_match_copy_and_restore(
        groups in prop::collection::vec((prop::collection::vec(calls(), 1..8), any::<bool>()), 1..24)
    ) {
        let mut w = mirrored_world();
        w.open(JOB, 500).unwrap();
        for (group, commit) in &groups {
            let copy = w.ledger.clone();
                        let m = w.mirror.as_mut().unwrap();
            m.orch.tx(Request::Begin);
            m.in_tx = true;
            // Only the orchestrator's own calls belong in its transaction: the clock waits.
            let own = group.iter().filter(|c| !matches!(c, Call::Tick(_)));
            for c in own {
                let _ = apply(&mut w, c);
            }
            let end = if *commit { Request::Commit } else { Request::Abort };
                        let m = w.mirror.as_mut().unwrap();
            m.orch.tx(end);
            m.in_tx = false;
            if !*commit {
                w.ledger = copy;
            }
            let host = host_of(&w);
            prop_assert!(*host.lock().unwrap().service() == w.ledger, "commit = {}", commit);
            check(&w, &Call::Settle(255))?;
        }
    }

    /// Arbitrary bytes never get a connection anywhere: the host answers with a fault and
    /// closes, and its ledger is untouched.
    #[test]
    fn noise_never_gets_past_the_handshake(payload in prop::collection::vec(any::<u8>(), 0..300)) {
        let (w, env) = wired();
        let before = state(&w);
        let mut link = raw(&w, &env);
        link.send(&payload).unwrap();
        let answer = Message::decode(&link.recv().unwrap());
        prop_assert!(matches!(answer, Ok(Message::Fault(_))), "{:?}", answer);
        prop_assert!(link.send(&payload).is_err());
        prop_assert!(state(&w) == before);
    }

    /// A valid request with some bytes changed, sent on an auditor's connection: whatever it
    /// decodes to, an auditor writes nothing.
    #[test]
    fn a_damaged_request_from_a_reader_writes_nothing(
        which in 0usize..64,
        flips in prop::collection::vec((0usize..400, any::<u8>()), 1..6),
    ) {
        let (mut w, env) = wired();
        w.open(JOB, 500).unwrap();
        let before = state(&w);
        let samples = sample_messages(&w);
        let requests: Vec<&Message> = samples
            .iter()
            .filter(|m| matches!(m, Message::Request { .. }))
            .collect();
        let Message::Request { body, .. } = requests[which % requests.len()].clone() else {
            unreachable!()
        };
        let mut bytes = Message::Request { seq: 1, body }.encode();
        for (at, value) in flips {
            let at = at % bytes.len();
            bytes[at] = value;
        }
        let mut auditor = connect(&w, &env, &w.auditor).unwrap();
        // Reach under the client to send the damaged payload on its authenticated connection.
        let answer = auditor_send(&mut auditor, &bytes);
        prop_assert!(answer.is_ok(), "an answer or a fault, never a panic");
        let after = state(&w);
        let (old, new) = (
            before.audit_view(&w.auditor).unwrap(),
            after.audit_view(&w.auditor).unwrap(),
        );
        prop_assert_eq!(old.entries(), new.entries());
        prop_assert_eq!((before.seq(), before.now()), (after.seq(), after.now()));
        prop_assert!(!w.keys.contains(99));
    }
}

/// Sends a raw payload on an authenticated client connection and decodes the answer.
fn auditor_send(c: &mut LedgerClient<Loopback>, payload: &[u8]) -> Result<Message, Malformed> {
    let t = c.transport_mut();
    t.send(payload).unwrap();
    Message::decode(&t.recv().unwrap())
}
