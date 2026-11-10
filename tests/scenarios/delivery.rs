//! JOB-F24 to JOB-F32: proven delivery, replay, rewinds, leases (I-03).

use super::*;

#[test]
fn f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    let escrow0 = t.bal(Account::EscrowWork(1));
    t.produce(J1, 5);
    t.deliver(J1, 5); // the witness sees 4 tokens go by; the client never acks
    assert_eq!(t.job(J1).validated[GEN.idx()], 1);
    assert_eq!(t.job(J1).delivered[GEN.idx()], 5);
    assert!(!t.charge(J1, 4).unwrap().definitive);
    assert_eq!(
        escrow0 - t.bal(Account::EscrowWork(1)),
        4 * 12,
        "billed provisionally"
    );
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    // End of draining, then of the 24 h delivery window and of evaluation.
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 24 * 3600 });
    t.ok(Command::Reconcile);
    assert!(t.charge(J1, 4).unwrap().definitive);
    assert_eq!(t.charge(J1, 4).unwrap().basis, ChargeBasis::WindowExpired);
    assert_eq!(
        t.line(s, L[0]).paid,
        5 * 6,
        "the witnessed window is paid to lenders"
    );
    assert_eq!(t.line(s, L[2]).paid, 5 * 2);
    // The client contests too late: free retransmission, no refund.
    let before = t.sim.ledger().entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    assert_eq!(
        t.sim.ledger().entries().len(),
        before,
        "replay moves no credits"
    );
    t.finish();
}

#[test]
fn f25_lender_cannot_attest_its_own_delivery() {
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    // A lender cannot be the witness of its own cluster (JOB-R26), even one that holds the witness
    // right in the pool (L[0] does): only the independence check refuses it.
    assert!(matches!(
        t.err(Command::Place {
            job: J1,
            lenders: L.to_vec(),
            layout: layout_of(J1),
            recovery_estimate: 0,
            witness: L[0],
            expected_version: None,
        }),
        DomainError::Precondition(_)
    ));
    t.start(J1, 0);
    t.produce(J1, 3);
    // The output node "attests" itself: no proof.
    assert_eq!(
        t.err(Command::Deliver {
            job: J1,
            attempt: 1,
            witness: L[2],
            wt: GEN,
            upto: 3,
            digest: t.c().frame_digest(J1, GEN, 3)
        }),
        DomainError::InadmissibleProof
    );
    assert!(t.c().delivery().charges().is_empty());
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).delivered[GEN.idx()],
        0,
        "nothing billed without proof"
    );
    t.finish();
}

#[test]
fn f26_lost_ack_then_resume_replays_without_double_billing() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.produce(J1, 6);
    t.deliver(J1, 6); // positions 2..6 delivered; the client's ack is lost
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // The client reports its last received position: 2 and 3 received, 4 and 5 not.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 4,
        digest: t.c().frame_digest(J1, GEN, 4),
    });
    assert_eq!(t.job(J1).validated[GEN.idx()], 4);
    assert_eq!(t.charge(J1, 3).unwrap().basis, ChargeBasis::ClientSigned);
    // 4 and 5: contested, replayed, still provisional (JOB-R33).
    let c5 = t.charge(J1, 5).unwrap();
    assert!(!c5.definitive && c5.contest.is_some());
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    // The resume starts from delivered positions, not validated ones.
    assert!(matches!(
        t.ready_err(J1, 2, [0, 4, 0]),
        DomainError::Precondition(_)
    ));
    t.ready(J1, 2, [0, 6, 0]);
    t.gen(J1, 1); // cumulative ack up to 7, also covers the replay of 4 and 5
    assert_eq!(t.charge(J1, 5).unwrap().basis, ChargeBasis::ClientSigned);
    assert!(t.charge(J1, 5).unwrap().contest.is_none());
    for pos in 0..7 {
        assert_eq!(t.net_charges(J1, pos), 1, "position {pos} billed once");
    }
    assert_eq!(
        t.c().delivery().outputs()[&OutputId {
            job: J1,
            wt: GEN,
            pos: 5
        }],
        1,
        "replayed, not regenerated"
    );
    assert_eq!(
        t.c().delivery().outputs()[&OutputId {
            job: J1,
            wt: GEN,
            pos: 6
        }],
        2
    );
    t.finish();
}

#[test]
fn f27_lost_replay_buffer_contest_refunds_and_rewinds() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 5);
    t.deliver(J1, 5);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    // Contributions to provisional outputs: reserved and waiting (JOB-R30); the slice stays closed
    // until the deadline (CE-06).
    assert_eq!(t.c().slices()[&s].status, SliceStatus::Closed);
    assert_eq!(t.line(s, L[0]).paid, 6);
    assert_eq!(t.line(s, L[0]).disputed, 4 * 6);
    assert!(
        t.sim
            .try_on_copy(&Command::Arbitrate {
                slice: s,
                lender: L[0],
                pay: true,
            })
            .is_err(),
        "awaiting contributions are never arbitrated on their own"
    );
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    let escrow = t.bal(Account::EscrowWork(1));
    // The client got 1 and 2, not 3 or 4; the buffer is lost.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 3,
        digest: t.c().frame_digest(J1, GEN, 3),
    });
    assert_eq!(
        t.job(J1).delivered[GEN.idx()],
        3,
        "rewound to the first lost position"
    );
    assert_eq!(
        t.bal(Account::EscrowWork(1)) - escrow,
        2 * 12,
        "voided outputs refunded"
    );
    assert!(t.charge(J1, 3).is_none());
    // 1 and 2 signed by the client are paid; 3 and 4 voided are refunded.
    assert_eq!(t.line(s, L[0]).paid, 3 * 6);
    assert_eq!(t.line(s, L[0]).refunded, 2 * 6);
    assert_eq!(t.line(s, L[0]).disputed + t.line(s, L[0]).pending, 0);
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        layout: layout_of(J1),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    t.ready(J1, 2, [0, 3, 0]);
    t.gen(J1, 2); // positions 3 and 4 produced again and charged again
    assert_eq!(t.net_charges(J1, 3), 1);
    assert_eq!(t.charge(J1, 3).unwrap().gen, 1);
    assert_eq!(
        t.c().delivery().outputs()[&OutputId {
            job: J1,
            wt: GEN,
            pos: 3
        }],
        2
    );
    t.finish();
}

#[test]
fn f28_simultaneous_client_silence_and_lease_expiry() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 3);
    // No ack and no heartbeat: both deadlines hit together.
    t.ok(Command::Tick { dt: 60 });
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).exec,
        ExecStatus::Recovering,
        "one transition wins"
    );
    let revocations = t
        .c()
        .audit_log()
        .iter()
        .filter(|e| {
            matches!(
                e,
                AuditEvent::Exec {
                    from: Some(ExecStatus::Running),
                    ..
                }
            )
        })
        .count();
    assert_eq!(revocations, 1);
    // Node and witness lost in the same second, on the resume.
    t.start(J1, 2);
    t.produce(J1, 3);
    t.deliver(J1, 3);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 2,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert!(!t.charge(J1, 2).unwrap().replayable);
    t.finish();
}

#[test]
fn f29_expired_lease_rejects_work_until_reconciliation_revokes() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.wait(300); // healthy cluster: the lease is renewed
    t.gen(J1, 1);
    t.ok(Command::Tick { dt: 45 }); // silent cluster
    let a = t.attempt(J1);
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: a,
            wt: GEN,
            upto: 3,
        }),
        DomainError::LeaseExpired
    );
    assert_eq!(
        t.err(Command::Heartbeat {
            job: J1,
            attempt: a,
            lender: L[0],
        }),
        DomainError::LeaseExpired,
        "an expired lease is never renewed"
    );
    assert_eq!(t.job(J1).exec, ExecStatus::Running);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Recovering);
    t.finish();
}

#[test]
fn f30_client_cannot_overstate_or_unconfirm_or_contest_live_output() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 5);
    t.deliver(J1, 3);
    // Output of the live attempt: retransmit, don't contest.
    assert!(matches!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 1,
            digest: t.c().frame_digest(J1, GEN, 1)
        }),
        DomainError::Precondition(_)
    ));
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    for confirmed in [0, 4] {
        assert!(matches!(
            t.err(Command::ConfirmDelivery {
                job: J1,
                wt: GEN,
                confirmed,
                digest: t.c().frame_digest(J1, GEN, confirmed)
            }),
            DomainError::Precondition(_)
        ));
    }
    t.finish();
}

#[test]
fn f31_contest_after_window_replays_but_never_refunds() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 24 * 3600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.charge(J1, 3).unwrap().basis, ChargeBasis::WindowExpired);
    let entries = t.sim.ledger().entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    // Window over: plain retransmission, no contest, no ledger entry.
    assert!(t.charge(J1, 3).unwrap().contest.is_none());
    assert_eq!(t.sim.ledger().entries().len(), entries);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    // Buffer lost after the window: the output stays due, no replay possible.
    assert!(matches!(
        t.err(Command::ConfirmDelivery {
            job: J1,
            wt: GEN,
            confirmed: 1,
            digest: t.c().frame_digest(J1, GEN, 1)
        }),
        DomainError::Precondition(_)
    ));
    t.finish();
}

#[test]
fn f32_rewind_revokes_live_attempt_built_on_voided_outputs() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.produce(J1, 4);
    t.deliver(J1, 4);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 2); // the resume starts at position 4 without waiting for the client
                    // Flow budget measured from the client's signature: only 1 more unit.
    t.produce(J1, 5);
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 2,
            wt: GEN,
            upto: 6,
        }),
        DomainError::FlowBudgetExceeded
    );
    assert_eq!(t.job(J1).exec, ExecStatus::Running);
    // The client comes back: it got nothing after position 1.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    assert_eq!(t.job(J1).delivered[GEN.idx()], 1);
    assert_eq!(
        t.job(J1).exec,
        ExecStatus::Recovering,
        "attempt 2 was built on voided outputs"
    );
    assert!(t.job(J1).attempts[&2].revoked_at.is_some());
    t.start(J1, 2);
    assert_eq!(t.job(J1).current().unwrap().produced[GEN.idx()], 1);
    t.gen(J1, 1);
    assert_eq!(t.net_charges(J1, 1), 1);
    t.finish();
}

// ------------------------------------------------ JOB-F33 to F41 (contests, proofs, cap)
