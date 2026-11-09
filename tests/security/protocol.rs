//! These three names come from the first protocol draft and are cited by the spec (PROTO-004, PROTO-005, PROTO-006, JOB-R26). Their content now goes through signed envelopes.

use super::*;

/// PROTO-004: a domain refusal reaches the sender with its stable code.
#[test]
fn domain_refusal_has_stable_code() {
    let mut e = Edge::running();
    e.refused(
        BORROWERS[0],
        Message::CancelJob { job: JobId(42) },
        "UNKNOWN_JOB",
    );
}

/// PROTO-005: a replayed or unsigned message is refused before the domain.
#[test]
fn replayed_or_unsigned_messages_rejected() {
    let mut e = Edge::running();
    let env = e.envelope(BORROWERS[0], Message::ClientHeartbeat { job: J1 });
    assert_eq!(e.send_env(&env), Ok(Outcome::AlreadyApplied));
    let mut older = env.clone();
    older.seq -= 1;
    older.signature = user_key(BORROWERS[0]).sign(&older.signing_bytes());
    assert_eq!(e.send_env(&older), Err(ProtoError::Replay));
    let mut unsigned = e.envelope(BORROWERS[0], Message::ClientHeartbeat { job: J1 });
    unsigned.signature = [0; 64];
    assert_eq!(
        e.send_env(&unsigned).map_err(|x| x.code()),
        Err("BAD_SIGNATURE")
    );
}

/// JOB-R26, PROTO-006: an attestation signed by a lender instead of the assigned witness is
/// refused with a stable code and no state change; the witness's own is accepted, provisionally.
#[test]
fn delivery_attested_by_a_lender_is_inadmissible() {
    let mut e = Edge::running();
    let digest = e.sim.coord.frame_digest(J1, GEN, 2);
    let body = Message::DeliveryAttestation {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
        digest,
    };
    e.refused(LENDERS[2], body.clone(), "INADMISSIBLE_PROOF");
    assert_eq!(e.send(WITNESS, body), Ok(Outcome::Applied));
    let o = OutputId {
        job: J1,
        wt: GEN,
        pos: 1,
    };
    let charge = e.sim.coord.delivery().charge(o).copied();
    assert!(
        charge.is_some_and(|c| !c.definitive),
        "charged, provisionally"
    );
}

/// A revoked service credential stops working at the coordinator, not only at the ledger.
#[test]
fn revoked_service_credential_is_refused_by_the_coordinator() {
    let mut e = Edge::running();
    let scheduler = e.sim.ids.scheduler.clone();
    let ctx = AuthContext::service(scheduler.clone());
    assert!(e
        .sim
        .exec_as(
            &ctx,
            Command::NodeLost {
                job: J1,
                expected_version: None,
            }
        )
        .is_ok());
    e.sim.ids.revoke(&scheduler);
    let before = e.sim.coord.clone();
    let r = e.sim.exec_as(&ctx, Command::Reserve { job: J2 });
    assert_eq!(r.map_err(|x| x.code()), Err("UNAUTHORIZED"));
    assert_eq!(before, e.sim.coord);
}
