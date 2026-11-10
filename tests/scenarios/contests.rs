//! JOB-F33 to JOB-F41: contests closed by signed acks, stream binding, late attestations, buffer
//! retention, sliding cap, supplementary proofs.

use super::*;

/// Attested tail (positions 1 to 3), node lost.
fn provisional_tail(t: &mut T) {
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
}

#[test]
fn f33_signed_heartbeat_without_replay_receipt_is_refunded() {
    let mut t = T::new();
    provisional_tail(&mut t);
    let escrow = t.bal(Account::EscrowWork(1));
    t.confirm(J1, 1); // "nothing after position 1": contest and replay
    assert!(t.charge(J1, 3).unwrap().contest.is_some());
    // The client sends a signed keepalive, but no ack covering the replay.
    assert_eq!(
        t.ok(Command::ClientHeartbeat { job: J1 }),
        Outcome::AlreadyApplied
    );
    t.ok(Command::Tick { dt: 3600 });
    t.ok(Command::Reconcile);
    assert!(t.charge(J1, 1).is_none(), "unconfirmed replay is refunded");
    assert_eq!(t.job(J1).delivered[GEN.idx()], 1);
    assert_eq!(t.bal(Account::EscrowWork(1)) - escrow, 3 * 12);
    t.finish();
}

#[test]
fn f34_cumulative_ack_covering_the_replay_bills_definitively() {
    let mut t = T::new();
    provisional_tail(&mut t);
    t.confirm(J1, 1);
    // The replay arrives: signed cumulative ack, bound to the stream, covering 1 to 3.
    t.confirm(J1, 4);
    for pos in 1..4 {
        let ch = t.charge(J1, pos).unwrap();
        assert!(ch.definitive && ch.contest.is_none());
        assert_eq!(ch.basis, ChargeBasis::ClientSigned);
    }
    t.ok(Command::Tick { dt: 3600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.net_charges(J1, 3), 1, "nothing refunded at the deadline");
    t.finish();
}

#[test]
fn f35_declaration_or_attestation_from_another_session_is_rejected() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    let j2 = JobId(2);
    t.start(j2, 0);
    let a = t.attempt(J1);
    // Frames from another stream presented for this job.
    let foreign = t.c().frame_digest(j2, GEN, 3);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto: 3,
            digest: foreign,
        }),
        DomainError::InadmissibleProof
    );
    t.deliver(J1, 3);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Statement signed in another session: rejected, nothing changes.
    let foreign = t.c().frame_digest(j2, GEN, 3);
    assert_eq!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 3,
            digest: foreign,
        }),
        DomainError::InadmissibleProof
    );
    assert!(!t.charge(J1, 2).unwrap().definitive);
    t.finish();
}

#[test]
fn f36_frame_different_from_the_signed_digest_is_rejected() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    let a = t.attempt(J1);
    let substituted = t.c().frame_digest(J1, GEN, 3) ^ 1;
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto: 3,
            digest: substituted,
        }),
        DomainError::InadmissibleProof
    );
    assert!(
        t.charge(J1, 1).is_none(),
        "nothing billed on a substituted frame"
    );
    t.finish();
}

#[test]
fn f37_commitment_before_revocation_makes_late_attestation_admissible() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::WitnessCommit {
        job: J1,
        attempt: 1,
        witness: WITNESS,
        wt: GEN,
        upto: 4,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 30 }); // the full attestation arrives while draining
    t.deliver(J1, 4);
    assert!(t
        .c()
        .audit_log()
        .iter()
        .any(|e| matches!(e, AuditEvent::LateDelivery { to: 4, .. })));
    assert!(!t.charge(J1, 3).unwrap().definitive, "billed provisionally");
    t.finish();
}

#[test]
fn f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Commitment forged after revocation: rejected.
    assert_eq!(
        t.err(Command::WitnessCommit {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
        }),
        DomainError::StaleAttempt
    );
    let d = t.c().frame_digest(J1, GEN, 4);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
            digest: d,
        }),
        DomainError::InadmissibleProof
    );
    // Even with an earlier commitment, an attestation after draining is rejected.
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.ok(Command::WitnessCommit {
        job: J1,
        attempt: 1,
        witness: WITNESS,
        wt: GEN,
        upto: 4,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    let d = t.c().frame_digest(J1, GEN, 4);
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: WITNESS,
            wt: GEN,
            upto: 4,
            digest: d,
        }),
        DomainError::StaleAttempt
    );
    t.finish();
}

#[test]
fn f39_contest_just_before_window_end_keeps_the_buffer() {
    let mut t = T::new();
    provisional_tail(&mut t);
    t.ok(Command::Tick { dt: 24 * 3600 - 60 }); // 23:59
    t.confirm(J1, 1);
    t.ok(Command::Tick { dt: 120 }); // the 24 h window is over
    t.ok(Command::Reconcile);
    assert!(
        !t.charge(J1, 3).unwrap().definitive,
        "positions after a contested one wait for it"
    );
    assert!(matches!(
        t.err(Command::PurgeBuffer {
            job: J1,
            attempt: 1
        }),
        DomainError::Precondition(_)
    ));
    t.confirm(J1, 4); // the replay is received and acked
    t.ok(Command::PurgeBuffer {
        job: J1,
        attempt: 1,
    });
    t.finish();
}

#[test]
fn f40_sliding_cap_holds_across_midnight_and_after_refunds() {
    let mut t = T::new();
    t.ok(Command::Tick {
        dt: 24 * 3600 - 300,
    }); // 23:55
    t.start(J1, 0);
    t.gen(J1, 3);
    let un = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 2,
        evidence: Evidence::Uncommitted,
    };
    t.present(J1, 1, L[2], 3);
    // Two uncommitted receipts of 2 credits before midnight: 4 = cap.
    let mut slices = Vec::new();
    for p in 0..2 {
        let s = t.open_slice(J1);
        t.ok(Command::Claim {
            slice: s,
            lender: L[2],
            items: vec![un(p)],
        });
        t.close_eval(s);
        assert_eq!(t.line(s, L[2]).paid, 2);
        slices.push(s);
    }
    // A contest returns 2 credits to the borrower; the quota is not restored.
    t.ok(Command::ContestReward {
        slice: slices[0],
        lender: L[2],
    });
    t.wait(360); // 00:01: new calendar day, same sliding window
    let s = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s,
        lender: L[2],
        items: vec![un(2)],
    });
    t.close_eval(s);
    assert_eq!(
        t.line(s, L[2]).disputed,
        2,
        "6 > 4 within 24 h: disputed despite midnight and the refund"
    );
    // 24 h after the first payments, the quota is available again.
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 24 * 3600 });
    let j2 = JobId(2);
    t.ok(Command::Reserve { job: j2 });
    t.ok(Command::Place {
        job: j2,
        lenders: vec![L[2], L[0]],
        layout: layout_of(j2),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    t.ready(j2, 1, [0; 3]);
    t.gen(j2, 1);
    let s2 = t.open_slice(j2);
    t.present(j2, 1, L[2], 1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[2],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j2,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Uncommitted,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.line(s2, L[2]).paid, 3);
    t.finish();
}

#[test]
fn f41_supplementary_proof_before_deadline_is_paid_after_is_refused() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::None); // claims sent before the proof came back
    t.close_eval(s);
    assert_eq!(t.c().slices()[&s].status, SliceStatus::Closed);
    assert_eq!(
        t.line(s, L[0]).pending,
        2 * 6,
        "nothing refunded before the deadline"
    );
    t.ok(Command::SupplementEvidence {
        slice: s,
        lender: L[0],
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 0,
        },
        evidence: Evidence::Committed,
    });
    t.ok(Command::Tick { dt: 600 });
    // Deadline reached, slice not evaluated yet: a proof sent now is too late.
    let late = Command::SupplementEvidence {
        slice: s,
        lender: L[0],
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 1,
        },
        evidence: Evidence::Committed,
    };
    assert!(matches!(t.err(late), DomainError::Precondition(_)));
    t.ok(Command::Reconcile);
    assert_eq!(t.line(s, L[0]).paid, 6, "supplemented proof is paid");
    assert_eq!(
        t.line(s, L[0]).refunded,
        6,
        "the other one is refunded at the deadline"
    );
    assert!(matches!(
        t.err(Command::SupplementEvidence {
            slice: s,
            lender: L[0],
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 1,
            },
            evidence: Evidence::Committed,
        }),
        DomainError::Precondition(_)
    ));
    t.finish();
}
