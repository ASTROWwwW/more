//! Non-régression : chaque contre-exemple trouvé par proptest est recopié ici
//! sous forme réduite et lisible, avec la règle de la spécification qu'il a
//! fait corriger. Ces tests ne doivent jamais être supprimés.
//!
//! Les graines brutes sont aussi conservées dans
//! `tests/properties/proptest-regressions.txt` et rejouées en premier.

use gpu_domain::*;
use gpu_simulation::*;

fn run(ops: &[Op]) -> Sim {
    let mut sim = Sim::default();
    for op in ops {
        sim.run_op(op);
    }
    sim.drain();
    sim
}

#[track_caller]
fn assert_clean(sim: &Sim) {
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-01 — trouvé par `invariants_hold_under_heavy_faults` (TEST-P13).
///
/// Séquence réduite par proptest : `[Fund { job: 132, amount: 0 }]`.
/// Le pool finançait la récupération d'un job encore `queued` ; le rejet du job
/// (JOB-T03 / JOB-S13, « aucune écriture ») laissait ces crédits sans
/// responsable dans `EscrowRecovery`.
///
/// Correction (spec v2.3, JOB-R18) : le relais du pool exige
/// `settlement_status = active`.
#[test]
fn ce01_pool_cannot_fund_a_job_without_active_escrow() {
    let sim = run(&[Op::Fund {
        job: 132,
        amount: 0,
    }]);
    assert_clean(&sim);

    let mut c = Sim::default().coord;
    let r = c.apply(&Command::FundRecovery {
        job: JobId(1),
        amount: 1,
    });
    assert_eq!(
        r,
        Err(DomainError::Precondition("JOB-R18: settlement not active"))
    );
    c.apply(&Command::Reserve { job: JobId(1) }).unwrap();
    c.apply(&Command::FundRecovery {
        job: JobId(1),
        amount: 1,
    })
    .unwrap();
    c.apply(&Command::Cancel {
        job: JobId(1),
        expected_version: None,
    })
    .unwrap();
    c.apply(&Command::Settle { job: JobId(1) }).unwrap();
    assert_eq!(c.ledger.balance(Account::EscrowRecovery(1)), 0);
    // (Avant CE-02, ce crédit du pool partait chez l'emprunteur.)
    assert_eq!(
        c.ledger.balance(Account::PoolReserve(1)),
        300,
        "unused pool relay returns to the pool"
    );
}

/// CE-02 — trouvé en écrivant CE-01 : aucune propriété ne surveillait la
/// destination des crédits du pool (trou du vérificateur, comblé par TEST-P17).
///
/// JOB-S12 rendait tout le budget de récupération non utilisé à l'emprunteur,
/// y compris la part avancée par le pool. Correction (spec v2.3) : budget de
/// l'emprunteur consommé d'abord, puis relais du pool ; à la clôture et en cas
/// de contestation, chaque payeur récupère sa propre part.
#[test]
fn ce02_pool_relay_never_benefits_the_borrower() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let lenders = vec![AccountId(10), AccountId(11), AccountId(12)];
    let ready = |sim: &mut Sim| {
        let (a, v) = (sim.coord.jobs[&j1].attempt, sim.coord.jobs[&j1].validated);
        sim.exec(Command::AttemptReady {
            job: j1,
            attempt: a,
            restored: v,
        })
        .unwrap();
    };
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: lenders.clone(),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    ready(&mut sim);
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::NodeLost {
        job: j1,
        expected_version: None,
    })
    .unwrap();
    // Budget emprunteur = 17. Le pool avance 10. Reprise estimée à 20 : 17 + 3 du pool.
    sim.exec(Command::FundRecovery {
        job: j1,
        amount: 10,
    })
    .unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: lenders.clone(),
        recovery_estimate: 20,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    ready(&mut sim);
    let s = *sim.coord.slices.keys().rfind(|s| s.attempt == 2).unwrap();
    sim.exec(Command::Claim {
        slice: s,
        lender: lenders[0],
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: 20,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    assert_eq!(
        (
            sim.coord.jobs[&j1].recovery_paid_borrower,
            sim.coord.jobs[&j1].recovery_paid_pool
        ),
        (17, 3)
    );
    // Fraude : la récupération est contestée. Le pool récupère ses 3, l'emprunteur ses 17.
    let pool_before = sim.coord.ledger.balance(Account::PoolReserve(1));
    sim.exec(Command::ContestReward {
        slice: s,
        lender: lenders[0],
    })
    .unwrap();
    assert_eq!(
        sim.coord.ledger.balance(Account::PoolReserve(1)),
        pool_before + 3
    );
    sim.drain();
    assert_clean(&sim);
    // Le pool a récupéré ses 10 (7 jamais utilisés + 3 contestés).
    assert_eq!(sim.coord.ledger.balance(Account::PoolReserve(1)), 300);
}

/// CE-03 — trouvé par `invariants_hold_under_heavy_faults` (TEST-P08) une fois
/// le vérificateur rendu indépendant du domaine (la mutation M09 n'était
/// détectée que par un scénario).
///
/// Séquence réduite (8 opérations) : tranche fermée à t=0 avec une réclamation
/// « engagée » ; saut d'horloge de 3 jours ; engagement enregistré ; annulation
/// (révocation à la même seconde) ; évaluation. L'engagement, postérieur à la
/// clôture, était accepté comme preuve.
///
/// Correction (spec v2.3, JOB-R12 / JOB-R15) : l'antériorité se juge dans
/// l'ordre du journal du coordinateur, avant la plus ancienne de la révocation
/// et de la clôture de la tranche.
#[test]
fn ce03_commitment_after_slice_closure_proves_nothing() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let l = AccountId(10);
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: vec![l, AccountId(11), AccountId(12)],
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::AttemptReady {
        job: j1,
        attempt: 1,
        restored: [0; 3],
    })
    .unwrap();
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    let s = SliceId {
        job: j1,
        attempt: 1,
        slice: 1,
    };
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: j1,
            wt: WorkType::Generate,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: l,
        items: vec![item],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    // Engagement APRÈS la clôture, puis révocation à la même seconde.
    sim.exec(Command::CommitReceipts {
        job: j1,
        attempt: 1,
        lender: l,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Cancel {
        job: j1,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    let line = &sim.coord.slices[&s].lines[&l];
    assert_eq!(
        (line.paid, line.pending),
        (0, 6),
        "a commitment recorded after closure is not proof: never paid"
    );
    // v2.5 (JOB-R35) : le remboursement faute de preuve devient définitif à
    // l'échéance d'évaluation, pas avant.
    sim.exec(Command::Tick { dt: 600 }).unwrap();
    sim.exec(Command::Reconcile).unwrap();
    let line = &sim.coord.slices[&s].lines[&l];
    assert_eq!(
        (line.paid, line.refunded),
        (0, 6),
        "a commitment recorded after closure is not proof"
    );
    sim.drain();
    assert_clean(&sim);
}

/// CE-03, cas symétrique : un engagement enregistré AVANT la clôture reste une preuve.
#[test]
fn ce03_commitment_before_closure_still_counts() {
    let mut sim = Sim::default();
    let j1 = JobId(1);
    let l = AccountId(10);
    sim.exec(Command::Reserve { job: j1 }).unwrap();
    sim.exec(Command::Place {
        job: j1,
        lenders: vec![l, AccountId(11), AccountId(12)],
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::AttemptReady {
        job: j1,
        attempt: 1,
        restored: [0; 3],
    })
    .unwrap();
    sim.exec(Command::Produce {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::Ack {
        job: j1,
        attempt: 1,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    sim.exec(Command::CommitReceipts {
        job: j1,
        attempt: 1,
        lender: l,
        wt: WorkType::Generate,
        upto: 1,
    })
    .unwrap();
    let s = SliceId {
        job: j1,
        attempt: 1,
        slice: 1,
    };
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: j1,
            wt: WorkType::Generate,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: l,
        items: vec![item],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    assert_eq!(sim.coord.slices[&s].lines[&l].paid, 6);
    sim.drain();
    assert_clean(&sim);
}

/// CE-04 (v2.4) — contre-exemple `proptest` (TEST-P06), générateur
/// « delivery », réduit à 16 opérations puis réécrit à la main.
///
/// La tranche est close (contribution réservée, pas encore évaluée) quand le
/// client déclare n'avoir pas reçu une sortie dont le tampon est perdu : la
/// sortie est annulée et sa contribution remboursée (JOB-R29). L'évaluation
/// tentait ensuite de trancher cet élément une seconde fois, échouait avec une
/// erreur interne avalée par la réconciliation, et le job restait bloqué.
#[test]
fn ce04_voided_output_after_closure_does_not_block_evaluation() {
    let mut sim = Sim::default();
    let j = JobId(1);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11), AccountId(12)],
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 2,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::Deliver {
            job: j,
            attempt: 1,
            witness: WITNESS,
            wt: gen,
            upto: 2,
            digest: sim.coord.frame_digest(j, gen, 2),
        },
        Command::CommitReceipts {
            job: j,
            attempt: 1,
            lender: AccountId(10),
            wt: gen,
            upto: 2,
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(10),
        items: (0..2)
            .map(|pos| ClaimItem::Contribution {
                output: OutputId {
                    job: j,
                    wt: gen,
                    pos,
                },
                stage: 0,
                evidence: Evidence::Committed,
            })
            .collect(),
    })
    .unwrap();
    sim.exec(Command::WitnessLost { job: j, attempt: 1 })
        .unwrap();
    sim.exec(Command::NodeLost {
        job: j,
        expected_version: None,
    })
    .unwrap();
    sim.exec(Command::Tick { dt: 121 }).unwrap();
    sim.exec(Command::Reconcile).unwrap(); // clôture : les deux contributions réservées
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Closed);
    // Le client n'a pas reçu la position 1, que le témoin ne peut plus rejouer.
    sim.exec(Command::ConfirmDelivery {
        job: j,
        wt: gen,
        confirmed: 1,
        digest: sim.coord.frame_digest(j, gen, 1),
    })
    .unwrap();
    assert!(!sim.coord.outputs.contains_key(&OutputId {
        job: j,
        wt: gen,
        pos: 1
    }));
    sim.exec(Command::Tick { dt: 601 }).unwrap();
    sim.exec(Command::Reconcile).unwrap(); // évaluation : ne doit plus échouer
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Final);
    let line = &sim.coord.slices[&s].lines[&AccountId(10)];
    assert_eq!((line.paid, line.refunded), (6, 6));
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-05 (v2.4) — contre-exemple `proptest` (TEST-P23, nouvelle propriété
/// d'équité), trouvé par les quatre générateurs dès la première exécution.
///
/// En partage libre, une contribution payée vaut 0 crédit : rien n'est retenu,
/// donc rien n'est jamais libéré, et l'élément restait indéfiniment « ni
/// libéré ni contesté ». Une récompense nulle est complète dès son paiement.
#[test]
fn ce05_zero_reward_in_free_pool_completes_at_payment() {
    let mut sim = Sim::default();
    let j = JobId(3);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11)],
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
        Command::CommitReceipts {
            job: j,
            attempt: 1,
            lender: AccountId(11),
            wt: gen,
            upto: 1,
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(11),
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j,
                wt: gen,
                pos: 0,
            },
            stage: 1,
            evidence: Evidence::Committed,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap();
    let it = &sim.coord.slices[&s].lines[&AccountId(11)].items[0];
    assert_eq!((it.status, it.amount), (ItemStatus::Paid, 0));
    assert!(it.reward_done, "a zero reward has nothing to hold");
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// CE-06 (v2.5) — contre-exemple `proptest` (TEST-P12), générateurs général et
/// réserve partielle, dès la première exécution de la v2.5.
///
/// Une tranche terminait son évaluation avant l'échéance alors qu'une
/// contribution attendait la livraison de sa sortie. Quand la sortie devenait
/// définitive, la contribution, sans preuve, redevenait « en attente de
/// preuve » (JOB-R35) dans une tranche déjà évaluée : tranche finale avec un
/// montant en attente. Correction : avant l'échéance, une tranche ne termine
/// pas son évaluation tant qu'une contribution attend sa sortie.
#[test]
fn ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open() {
    let mut sim = Sim::default();
    let j = JobId(1);
    let gen = WorkType::Generate;
    for cmd in [
        Command::Reserve { job: j },
        Command::Place {
            job: j,
            lenders: vec![AccountId(10), AccountId(11), AccountId(12)],
            recovery_estimate: 0,
            witness: WITNESS,
            expected_version: None,
        },
        Command::AttemptReady {
            job: j,
            attempt: 1,
            restored: [0; 3],
        },
        Command::Produce {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 2,
        },
        Command::Ack {
            job: j,
            attempt: 1,
            wt: gen,
            upto: 1,
        },
    ] {
        sim.exec(cmd.clone())
            .unwrap_or_else(|e| panic!("{cmd:?}: {e:?}"));
    }
    let digest = sim.coord.frame_digest(j, gen, 2);
    sim.exec(Command::Deliver {
        job: j,
        attempt: 1,
        witness: WITNESS,
        wt: gen,
        upto: 2,
        digest,
    })
    .unwrap();
    let s = SliceId {
        job: j,
        attempt: 1,
        slice: 1,
    };
    sim.exec(Command::Claim {
        slice: s,
        lender: AccountId(10),
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: j,
                wt: gen,
                pos: 1,
            },
            stage: 0,
            evidence: Evidence::None,
        }],
    })
    .unwrap();
    sim.exec(Command::CloseSlice { slice: s }).unwrap();
    sim.exec(Command::Evaluate { slice: s }).unwrap(); // sortie provisoire : en attente
    assert_eq!(
        sim.coord.slices[&s].status,
        SliceStatus::Closed,
        "not finished before deadline"
    );
    // Le client signe : la sortie devient définitive avant l'échéance.
    sim.exec(Command::Ack {
        job: j,
        attempt: 1,
        wt: gen,
        upto: 2,
    })
    .unwrap();
    let line = &sim.coord.slices[&s].lines[&AccountId(10)];
    assert_eq!(
        line.pending, 6,
        "back to pending evaluation, slice still open"
    );
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
    sim.exec(Command::Tick { dt: 600 }).unwrap();
    sim.exec(Command::Reconcile).unwrap();
    assert_eq!(sim.coord.slices[&s].status, SliceStatus::Final);
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}
