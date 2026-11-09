//! Scénarios déterministes JOB-F01 à JOB-F32 (section 4) et tests ciblés des
//! corrections v2.3 (JOB-R21, JOB-R22, JOB-R24). JOB-F24 à F32 (v2.4) couvrent
//! le protocole de livraison et de rejeu (I-03) et les autorisations datées ;
//! JOB-F33 à F41 (v2.5) les huit cas adverses demandés à l'audit de la v2.4.
//!
//! Chaque commande passe par le vérificateur d'invariants complet ; chaque
//! scénario se termine par la phase de vidage (vivacité, escrow soldé).

use gpu_domain::*;
use gpu_simulation::*;

const J1: JobId = JobId(1); // 3 étages (3, 2, 1 couches), génération à 12 crédits
const J3: JobId = JobId(3); // pool en partage libre
const L: [AccountId; 3] = [AccountId(10), AccountId(11), AccountId(12)];
const GEN: WorkType = WorkType::Generate;

struct T {
    sim: Sim,
}

impl T {
    fn new() -> Self {
        T {
            sim: Sim::new(sim_config()),
        }
    }

    fn with(cfg: Config) -> Self {
        T { sim: Sim::new(cfg) }
    }

    fn c(&self) -> &Coordinator {
        &self.sim.coord
    }

    fn job(&self, j: JobId) -> &Job {
        &self.c().jobs[&j]
    }

    fn assert_clean(&self) {
        assert!(
            self.sim.violations.is_empty(),
            "violations: {:#?}",
            self.sim.violations
        );
    }

    #[track_caller]
    fn ok(&mut self, cmd: Command) -> Outcome {
        let r = self.sim.exec(cmd.clone());
        self.assert_clean();
        r.unwrap_or_else(|e| panic!("{cmd:?} refused: {e:?}"))
    }

    #[track_caller]
    fn err(&mut self, cmd: Command) -> DomainError {
        let before = self.c().clone();
        let r = self.sim.exec(cmd.clone());
        self.assert_clean();
        let e = r.expect_err(&format!("{cmd:?} should be refused"));
        assert_eq!(&before, self.c(), "a refused command changed the state");
        e
    }

    fn bal(&self, a: Account) -> i128 {
        self.c().ledger.balance(a)
    }

    fn attempt(&self, j: JobId) -> u32 {
        self.job(j).attempt
    }

    /// Réservation, placement, démarrage.
    fn start(&mut self, j: JobId, est: Amount) {
        if self.job(j).exec == ExecStatus::Queued {
            self.ok(Command::Reserve { job: j });
        }
        let n = self.job(j).layout.len();
        self.ok(Command::Place {
            job: j,
            lenders: L[..n].to_vec(),
            recovery_estimate: est,
            witness: WITNESS,
            expected_version: None,
        });
        let (attempt, restored) = (self.attempt(j), self.job(j).delivered);
        self.ok(Command::AttemptReady {
            job: j,
            attempt,
            restored,
        });
    }

    /// Produit et fait valider `n` tokens de génération, un par un.
    fn gen(&mut self, j: JobId, n: u32) {
        for _ in 0..n {
            let a = self.attempt(j);
            let p = self.job(j).current().unwrap().produced[GEN.idx()];
            self.ok(Command::Produce {
                job: j,
                attempt: a,
                wt: GEN,
                upto: p + 1,
            });
            self.ok(Command::Ack {
                job: j,
                attempt: a,
                wt: GEN,
                upto: p + 1,
            });
        }
    }

    fn commit_all(&mut self, j: JobId) {
        let a = self.attempt(j);
        let att = self.job(j).current().unwrap().clone();
        for l in &att.lenders {
            self.ok(Command::CommitReceipts {
                job: j,
                attempt: a,
                lender: *l,
                wt: GEN,
                upto: att.produced[GEN.idx()],
            });
        }
    }

    fn open_slice(&self, j: JobId) -> SliceId {
        *self
            .c()
            .slices
            .keys()
            .rfind(|s| s.job == j && self.c().slices[s].status == SliceStatus::Open)
            .expect("open slice")
    }

    /// Chaque prêteur réclame sa plage pour toutes les sorties de la tentative de la tranche.
    fn claim_all(&mut self, s: SliceId, ev: Evidence) {
        let outs: Vec<OutputId> = self
            .c()
            .outputs
            .iter()
            .filter(|(o, a)| o.job == s.job && **a == s.attempt)
            .map(|(o, _)| *o)
            .collect();
        let lenders = self.job(s.job).attempts[&s.attempt].lenders.clone();
        for (stage, l) in lenders.iter().enumerate() {
            let items = outs
                .iter()
                .map(|o| ClaimItem::Contribution {
                    output: *o,
                    stage: stage as u32,
                    evidence: ev,
                })
                .collect();
            self.ok(Command::Claim {
                slice: s,
                lender: *l,
                items,
            });
        }
    }

    /// Le temps passe, la grappe reste saine : elle renouvelle ses
    /// autorisations (JOB-R31). Pour une grappe muette, utiliser `Tick`.
    fn wait(&mut self, dt: Time) {
        let mut left = dt;
        while left > 0 {
            let step = left.min(15);
            let live: Vec<(JobId, u32)> = self
                .c()
                .jobs
                .values()
                .filter(|j| matches!(j.exec, ExecStatus::Running | ExecStatus::Placing))
                .filter(|j| j.current().is_some_and(|a| a.revoked_at.is_none()))
                .map(|j| (j.id, j.attempt))
                .collect();
            for (job, attempt) in live {
                self.ok(Command::Heartbeat { job, attempt });
            }
            self.ok(Command::Tick { dt: step });
            left -= step;
        }
    }

    /// Le témoin atteste la livraison jusqu'à `upto` (JOB-R26).
    fn deliver(&mut self, j: JobId, upto: u32) {
        let a = self.attempt(j);
        self.ok(Command::Deliver {
            job: j,
            attempt: a,
            witness: WITNESS,
            wt: GEN,
            upto,
            digest: self.c().frame_digest(j, GEN, upto),
        });
    }

    /// Déclaration signée du client, liée au flux (JOB-R28, JOB-R34).
    fn confirm(&mut self, j: JobId, confirmed: u32) -> Outcome {
        let digest = self.c().frame_digest(j, GEN, confirmed);
        self.ok(Command::ConfirmDelivery {
            job: j,
            wt: GEN,
            confirmed,
            digest,
        })
    }

    fn produce(&mut self, j: JobId, upto: u32) {
        let a = self.attempt(j);
        self.ok(Command::Produce {
            job: j,
            attempt: a,
            wt: GEN,
            upto,
        });
    }

    fn charge(&self, j: JobId, pos: u32) -> Option<OutputCharge> {
        self.c()
            .charges
            .get(&OutputId {
                job: j,
                wt: GEN,
                pos,
            })
            .copied()
    }

    /// Nombre de facturations nettes d'une sortie, d'après le journal.
    fn net_charges(&self, j: JobId, pos: u32) -> i64 {
        let o = OutputId {
            job: j,
            wt: GEN,
            pos,
        };
        self.c()
            .audit
            .iter()
            .map(|e| match e {
                AuditEvent::OutputCharged { output, .. } if *output == o => 1,
                AuditEvent::OutputVoided { output, .. } if *output == o => -1,
                _ => 0,
            })
            .sum()
    }

    fn close_eval(&mut self, s: SliceId) {
        self.ok(Command::CloseSlice { slice: s });
        self.ok(Command::Evaluate { slice: s });
    }

    fn line(&self, s: SliceId, l: AccountId) -> Line {
        self.c().slices[&s]
            .lines
            .get(&l)
            .cloned()
            .unwrap_or_default()
    }

    fn finish(mut self) {
        self.sim.drain();
        self.assert_clean();
        for j in self.c().jobs.values() {
            assert_eq!(j.settle, SettleStatus::Closed, "{:?}", j.id);
        }
    }
}

// ---------------------------------------------------------------- JOB-F01 à F23

#[test]
fn f01_partial_transition_leaves_no_trace() {
    // Une transition en deux écritures dont la seconde échoue : rien n'est écrit (JOB-R01).
    let mut t = T::new();
    t.ok(Command::Issue {
        id: 50,
        to: IssueTarget::User(AccountId(3)),
        amount: 177,
    });
    t.ok(Command::Submit {
        job: JobId(4),
        borrower: AccountId(3),
        pool: CREDIT_POOL,
        layout: vec![3, 2, 1],
        price: [6, 12, 3],
        max_outputs: [4, 12, 3],
    });
    // Assez pour la part travail (177), pas pour le budget de récupération (17).
    let e = t.err(Command::Reserve { job: JobId(4) });
    assert!(matches!(e, DomainError::Ledger(_)));
    assert_eq!(t.bal(Account::User(3)), 177);
    assert_eq!(t.bal(Account::EscrowWork(4)), 0);
    t.finish();
}

#[test]
fn f02_redelivered_assignments_are_harmless() {
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    let place = Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    };
    t.ok(place.clone());
    t.err(place); // rejouée depuis l'outbox : refusée, aucune nouvelle tentative
    assert_eq!(t.attempt(J1), 1);
    // Timeout de placement entre-temps : JOB-T06 renvoie en `reserved`.
    t.ok(Command::Tick { dt: 61 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Reserved);
    t.err(Command::AttemptReady {
        job: J1,
        attempt: 1,
        restored: [0; 3],
    });
    t.finish();
}

#[test]
fn f03_work_after_revocation_rejected_prior_receipts_paid() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 3
        }),
        DomainError::StaleAttempt
    );
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 2 * 6);
    t.finish();
}

#[test]
fn f04_duplicate_report_after_settlement_pays_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    let before = t.bal(Account::PendingReward {
        job: 1,
        attempt: 1,
        slice: s.slice,
        lender: 10,
    });
    t.err(Command::Evaluate { slice: s });
    t.err(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Committed,
        }],
    });
    // Le prêteur renvoie son rapport sur la tranche suivante : la contribution est déjà prise.
    let s2 = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 0,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices[&s2].rejected_items, 1);
    assert_eq!(
        t.bal(Account::PendingReward {
            job: 1,
            attempt: 1,
            slice: s.slice,
            lender: 10
        }),
        before
    );
    t.finish();
}

#[test]
fn f05_returning_node_is_ignored_but_keeps_prior_pay() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 2); // tentative 2
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2
        }),
        DomainError::StaleAttempt
    );
    assert_eq!(
        t.err(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1
        }),
        DomainError::StaleAttempt
    );
    t.claim_all(s1, Evidence::Committed);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[2]).paid, 2);
    t.finish();
}

#[test]
fn f06_duplicate_ack_charges_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    t.ok(Command::Ack {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    assert_eq!(
        t.ok(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2
        }),
        Outcome::AlreadyApplied
    );
    assert_eq!(
        t.ok(Command::Ack {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 1
        }),
        Outcome::AlreadyApplied
    );
    assert_eq!(t.bal(Account::OutputHold(1)), 24);
    t.finish();
}

#[test]
fn f07_client_disconnect_stops_after_k_then_pauses() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 6,
    }); // K = 4
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 7
        }),
        DomainError::FlowBudgetExceeded
    );
    t.wait(60);
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Paused);
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    assert_eq!(
        t.job(J1).validated[GEN.idx()],
        2,
        "unacknowledged window never charged"
    );
    // Reprise : la génération repart à la dernière position validée.
    t.ok(Command::Resume { job: J1, topup: 0 });
    t.start(J1, 3);
    assert_eq!(t.job(J1).current().unwrap().produced[GEN.idx()], 2);
    t.finish();
}

#[test]
fn f08_lost_contact_revocation_stops_payment() {
    // Le modèle n'a pas de minuterie d'autorisation : l'expiration est représentée
    // par la révocation (JOB-T08). Ce qui suit la révocation n'est jamais payé.
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    t.commit_all(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.err(Command::Ack {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 2,
    });
    assert!(!t.c().outputs.contains_key(&OutputId {
        job: J1,
        wt: GEN,
        pos: 1
    }));
    t.finish();
}

#[test]
fn f09_cancel_and_finish_race() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    let v = Some(t.job(J1).version);
    t.ok(Command::Finish {
        job: J1,
        expected_version: v,
    });
    assert!(matches!(
        t.err(Command::Cancel {
            job: J1,
            expected_version: v
        }),
        DomainError::VersionConflict { .. }
    ));
    // En relisant la version, l'annulation est refusée en `settling`.
    let v2 = Some(t.job(J1).version);
    assert_eq!(
        t.err(Command::Cancel {
            job: J1,
            expected_version: v2
        }),
        DomainError::JobSettling
    );
    assert_eq!(t.err(Command::Fail { job: J1 }), DomainError::JobSettling);
    t.finish();
}

#[test]
fn f10_low_escrow_blocks_window_then_pause_and_topup() {
    let mut t = T::with(Config {
        initial_reserve_max: 26,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 2); // 24 facturés, 2 restants
    assert_eq!(
        t.err(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 3
        }),
        DomainError::WindowNotCovered
    );
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::LowEscrow,
        expected_version: None,
    });
    // 2 crédits ne couvrent aucune sortie restante (la moins chère coûte 3).
    t.err(Command::Resume { job: J1, topup: 0 });
    t.ok(Command::Resume { job: J1, topup: 60 });
    t.start(J1, 2);
    t.gen(J1, 3);
    t.finish();
}

#[test]
fn f11_identical_reports_counted_once() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    let item = ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: 0,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![item],
    });
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![item],
    });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 6);
    assert_eq!(t.c().slices[&s].rejected_items, 1);
    t.finish();
}

#[test]
fn f12_oversized_frame_rejected_before_decoding() {
    use gpu_protocol::*;
    assert_eq!(
        check_frame(MessageKind::TokenAck, 10_000),
        Err(ProtoError::FrameTooLarge)
    );
    assert_eq!(ProtoError::FrameTooLarge.code(), "FRAME_TOO_LARGE");
}

#[test]
fn f13_scheduler_restart_replays_nothing() {
    // Le scheduler n'a pas d'état propre : rejouer ses décisions est sans effet.
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    let place = Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    };
    t.ok(place.clone());
    let snapshot = t.c().clone();
    t.err(place);
    assert_eq!(&snapshot, t.c());
    t.finish();
}

#[test]
fn f14_preemption_settles_slice_then_resumes() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Preempted,
        expected_version: None,
    });
    assert_eq!(t.c().slices[&s].status, SliceStatus::Draining);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[1]).paid, 2 * 4);
    t.ok(Command::Resume { job: J1, topup: 0 });
    t.start(J1, 3);
    t.gen(J1, 1);
    t.finish();
}

#[test]
fn f15_withheld_acks_bound_loss_to_k() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 5,
    }); // 4 livrés, jamais acquittés
    t.commit_all(J1);
    let s = t.open_slice(J1);
    // Les prêteurs réclament aussi la fenêtre non acquittée : refusée (sortie non validée).
    let items = (0..5)
        .map(|p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage: 0,
            evidence: Evidence::Committed,
        })
        .collect();
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items,
    });
    t.wait(60);
    t.ok(Command::Reconcile); // pause, client silencieux
    assert_eq!(t.job(J1).pause_reason, Some(PauseReason::ClientSilent));
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile); // fin du drainage : clôture
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile); // échéance d'évaluation
    assert_eq!(t.line(s, L[0]).paid, 6, "only the validated output is paid");
    assert_eq!(
        t.c().slices[&s].rejected_items,
        4,
        "loss bounded by K = 4 unacknowledged outputs"
    );
    t.finish();
}

#[test]
fn f16_survivor_paid_after_other_gpu_fails() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 3);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Seul le prêteur de l'étage 0 réclame, en drainage.
    let items = (0..3)
        .map(|p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage: 0,
            evidence: Evidence::Committed,
        })
        .collect();
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items,
    });
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 18);
    t.finish();
}

#[test]
fn f17_receipts_fabricated_after_revocation() {
    // Scénario écrit pour un plafond de 8 crédits (la simulation en utilise 4).
    let mut t = T::with(Config {
        uncommitted_cap: 8,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 4);
    let s = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Engagement envoyé APRÈS la révocation : horodaté trop tard.
    t.ok(Command::Tick { dt: 5 });
    t.ok(Command::CommitReceipts {
        job: J1,
        attempt: 1,
        lender: L[0],
        wt: GEN,
        upto: 4,
    });
    let ev = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 0,
        evidence: Evidence::Committed,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: vec![ev(0), ev(1)],
    });
    // Reçus non engagés : au plus K = 4 par type en drainage.
    let un = |p| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage: 1,
        evidence: Evidence::Uncommitted,
    };
    assert_eq!(
        t.err(Command::Claim {
            slice: s,
            lender: L[1],
            items: (0..5).map(un).collect()
        }),
        DomainError::FlowBudgetExceeded
    );
    t.ok(Command::Claim {
        slice: s,
        lender: L[1],
        items: (0..4).map(un).collect(),
    });
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid, 0, "late commitment proves nothing");
    // JOB-R35 : remboursement faute de preuve seulement à l'échéance d'évaluation.
    assert_eq!(t.line(s, L[0]).pending, 12);
    t.ok(Command::Tick { dt: 600 });
    t.ok(Command::Reconcile);
    assert_eq!(t.line(s, L[0]).refunded, 12);
    // 4 × 4 = 16 > plafond 8 : 2 payés, 2 contestés.
    assert_eq!(t.line(s, L[1]).paid, 8);
    assert_eq!(t.line(s, L[1]).disputed, 8);
    assert_eq!(t.c().slices[&s].status, SliceStatus::Disputed);
    t.finish();
}

#[test]
fn f18_new_attempt_runs_while_old_slice_drains() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 4);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    assert_eq!(t.c().slices[&s1].status, SliceStatus::Draining);
    t.claim_all(s1, Evidence::Committed);
    t.claim_all(s2, Evidence::Committed);
    t.close_eval(s2);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[0]).paid, 12);
    assert_eq!(t.line(s2, L[0]).paid, 12);
    t.finish();
}

#[test]
fn f18b_free_pool_resume_uses_quota_not_credits() {
    let mut t = T::new();
    t.start(J3, 0);
    t.gen(J3, 2);
    t.ok(Command::Pause {
        job: J3,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.err(Command::Resume { job: J3, topup: 10 });
    t.ok(Command::Resume { job: J3, topup: 0 });
    t.start(J3, 0);
    t.gen(J3, 1);
    t.finish();
}

#[test]
fn f19_resume_after_pause_keeps_intent() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 3);
    t.ok(Command::Pause {
        job: J1,
        reason: PauseReason::Requested,
        expected_version: None,
    });
    t.ok(Command::Resume { job: J1, topup: 0 });
    assert_eq!(t.job(J1).intent, Intent::Resume);
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    assert_eq!(
        t.job(J1).intent,
        Intent::Resume,
        "JOB-T04 does not reset the intent"
    );
    t.err(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0; 3],
    });
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 3, 0],
    });
    t.finish();
}

#[test]
fn f20_unvalidated_positions_are_wasted_not_billed() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2); // positions 0-1 validées
    t.ok(Command::Produce {
        job: J1,
        attempt: 1,
        wt: GEN,
        upto: 5,
    }); // 2-4 produites
    t.commit_all(J1);
    let s1 = t.open_slice(J1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 6);
    assert_eq!(
        t.job(J1).current().unwrap().produced[GEN.idx()],
        2,
        "attempt 2 resumes at 2"
    );
    t.gen(J1, 3); // positions 2-4 validées sur la tentative 2
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    // Tentative 1 : réclame 0..5 ; seules 0-1 lui appartiennent.
    let all = |stage| {
        (0..5).map(move |p| ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: p,
            },
            stage,
            evidence: Evidence::Committed,
        })
    };
    t.ok(Command::Claim {
        slice: s1,
        lender: L[0],
        items: all(0).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: all(0).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: vec![ClaimItem::Recovery {
            segment: 0,
            amount: 6,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    t.ok(Command::Tick { dt: 121 });
    t.close_eval(s1);
    assert_eq!(t.line(s1, L[0]).paid, 12, "attempt 1: positions 0-1");
    assert_eq!(
        t.line(s2, L[0]).paid,
        18 + 6,
        "attempt 2: positions 2-4 + recovery"
    );
    for p in 0..5 {
        let o = OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        };
        assert_eq!(t.c().outputs[&o], if p < 2 { 1 } else { 2 });
    }
    t.finish();
}

#[test]
fn f21_dispute_isolated_to_one_lender_line() {
    // Scénario écrit pour un plafond de 8 crédits (la simulation en utilise 4).
    let mut t = T::with(Config {
        uncommitted_cap: 8,
        ..sim_config()
    });
    t.start(J1, 0);
    t.gen(J1, 3);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    let item = |p, stage, evidence| ClaimItem::Contribution {
        output: OutputId {
            job: J1,
            wt: GEN,
            pos: p,
        },
        stage,
        evidence,
    };
    t.ok(Command::Claim {
        slice: s,
        lender: L[0],
        items: (0..3).map(|p| item(p, 0, Evidence::Committed)).collect(),
    });
    t.ok(Command::Claim {
        slice: s,
        lender: L[1],
        items: (0..3).map(|p| item(p, 1, Evidence::Committed)).collect(),
    });
    // Étage 2 (2 crédits / sortie) sur reçus non engagés : 6 ≤ 8, payé. On abaisse le plafond par une 2e tranche plus bas.
    t.ok(Command::Claim {
        slice: s,
        lender: L[2],
        items: (0..3).map(|p| item(p, 2, Evidence::Uncommitted)).collect(),
    });
    t.close_eval(s);
    assert_eq!(t.c().slices[&s].status, SliceStatus::Final);
    // Deuxième tranche : le prêteur 12 dépasse le plafond, seule sa ligne est contestée.
    t.gen(J1, 3);
    t.commit_all(J1);
    let s2 = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: (3..6).map(|p| item(p, 0, Evidence::Committed)).collect(),
    });
    t.ok(Command::Claim {
        slice: s2,
        lender: L[2],
        items: (3..6).map(|p| item(p, 2, Evidence::Uncommitted)).collect(),
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices[&s2].status, SliceStatus::Disputed);
    assert_eq!(t.line(s2, L[0]).paid, 18);
    assert_eq!(t.line(s2, L[0]).disputed, 0);
    assert_eq!(t.line(s2, L[2]).paid, 2);
    assert_eq!(t.line(s2, L[2]).disputed, 4);
    t.ok(Command::Arbitrate {
        slice: s2,
        lender: L[2],
        pay: true,
    });
    assert_eq!(t.c().slices[&s2].status, SliceStatus::Final);
    t.finish();
}

#[test]
fn f22_cancel_while_draining_settles_everything() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::Cancel {
        job: J1,
        expected_version: None,
    });
    assert_eq!(t.job(J1).exec, ExecStatus::Cancelled);
    assert_eq!(t.job(J1).settle, SettleStatus::Finalizing);
    t.err(Command::Settle { job: J1 }); // tranche encore en drainage
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).settle, SettleStatus::Closed);
    assert_eq!(t.bal(Account::EscrowWork(1)), 0);
    assert_eq!(t.bal(Account::OutputHold(1)), 0);
    // Emprunteur : 2 000 − 24 (2 sorties). Les 24 sont retenus pour les prêteurs.
    assert_eq!(t.bal(Account::User(1)), 2_000 - 24);
    t.finish();
}

#[test]
fn f23_recovery_budget_exhausted_then_pool_relay() {
    let mut t = T::new();
    assert_eq!(t.job(J1).recovery_budget, 17);
    t.start(J1, 0);
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    t.start(J1, 17); // tout le budget
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    assert_eq!(
        t.err(Command::Place {
            job: J1,
            lenders: L.to_vec(),
            recovery_estimate: 1,
            witness: WITNESS,
            expected_version: None
        }),
        DomainError::RecoveryBudget
    );
    // Le pool bloque 10 crédits avant la reprise.
    t.ok(Command::FundRecovery {
        job: J1,
        amount: 10,
    });
    t.start(J1, 10);
    t.gen(J1, 1);
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Plus rien : aucune reprise non financée, pause à l'échéance.
    t.err(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 1,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    assert_eq!(t.job(J1).exec, ExecStatus::Paused);
    t.finish();
}

// ------------------------------------------------- Corrections v2.3 (ciblées)

#[test]
fn r21_every_stage_paid_once_and_sum_le_price() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    let paid: Amount = L.iter().map(|l| t.line(s, *l).paid).sum();
    assert_eq!(
        [
            t.line(s, L[0]).paid,
            t.line(s, L[1]).paid,
            t.line(s, L[2]).paid
        ],
        [6, 4, 2]
    );
    assert_eq!(paid, 12, "three contributions, one output, sum = price");
    // Un prêteur ne peut pas réclamer la plage d'un autre.
    let s2 = t.open_slice(J1);
    t.ok(Command::Claim {
        slice: s2,
        lender: L[0],
        items: vec![ClaimItem::Contribution {
            output: OutputId {
                job: J1,
                wt: GEN,
                pos: 0,
            },
            stage: 1,
            evidence: Evidence::Committed,
        }],
    });
    t.close_eval(s2);
    assert_eq!(t.c().slices[&s2].rejected_items, 1);
    t.finish();
}

#[test]
fn r21_rounding_never_exceeds_price() {
    // Job 2 : 2 étages égaux, prix 7 → parts 3 + 3 = 6 ≤ 7 ; le reste revient à l'emprunteur.
    let mut t = T::new();
    let j2 = JobId(2);
    t.ok(Command::Reserve { job: j2 });
    t.ok(Command::Place {
        job: j2,
        lenders: L[..2].to_vec(),
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::AttemptReady {
        job: j2,
        attempt: 1,
        restored: [0; 3],
    });
    t.gen(j2, 1);
    t.commit_all(j2);
    let s = t.open_slice(j2);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    assert_eq!(t.line(s, L[0]).paid + t.line(s, L[1]).paid, 6);
    t.finish();
}

#[test]
fn r24_pending_evaluation_balances_line_between_close_and_evaluate() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.ok(Command::CloseSlice { slice: s });
    let l = t.line(s, L[0]);
    assert_eq!(
        (l.claimed, l.pending, l.paid, l.refunded, l.disputed),
        (12, 12, 0, 0, 0)
    );
    // Réservation atomique : l'argent est déjà sorti de OutputHold vers la ligne.
    assert_eq!(
        t.bal(Account::SliceLine {
            job: 1,
            attempt: 1,
            slice: s.slice,
            lender: 10
        }),
        12
    );
    t.ok(Command::Evaluate { slice: s });
    let l = t.line(s, L[0]);
    assert_eq!((l.pending, l.paid), (0, 12));
    t.finish();
}

#[test]
fn r22_contest_after_job_closed_refunds_from_held_rewards() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 2);
    t.commit_all(J1);
    let s = t.open_slice(J1);
    t.claim_all(s, Evidence::Committed);
    t.close_eval(s);
    t.ok(Command::Finish {
        job: J1,
        expected_version: None,
    });
    t.ok(Command::Tick { dt: 121 });
    t.ok(Command::Reconcile);
    t.ok(Command::Tick { dt: 601 });
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).settle,
        SettleStatus::Closed,
        "job financially closed"
    );
    let circulating = t.c().ledger.circulating();
    let borrower = t.bal(Account::User(1));
    // Fraude découverte : contestation de la ligne du prêteur 11, pendant la fenêtre.
    t.ok(Command::ContestReward {
        slice: s,
        lender: L[1],
    });
    assert_eq!(
        t.bal(Account::User(1)),
        borrower + 8,
        "refund comes from held rewards"
    );
    assert_eq!(t.c().ledger.circulating(), circulating, "no credit created");
    // Après la fenêtre : libération définitive, plus de contestation possible.
    t.ok(Command::Tick { dt: 48 * 3600 });
    t.ok(Command::ReleaseReward {
        slice: s,
        lender: L[0],
    });
    t.err(Command::ContestReward {
        slice: s,
        lender: L[0],
    });
    t.err(Command::ContestReward {
        slice: s,
        lender: L[2],
    }); // fenêtre close
    t.ok(Command::ReleaseReward {
        slice: s,
        lender: L[2],
    });
    assert_eq!(
        t.bal(Account::User(10)),
        12 - 1,
        "lender gets 12 minus 10 % commission"
    );
    t.finish();
}

// ------------------------------------------------- JOB-F24 à F32 (v2.4, I-03)

#[test]
fn f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders() {
    let mut t = T::new();
    t.start(J1, 0);
    t.gen(J1, 1);
    let escrow0 = t.bal(Account::EscrowWork(1));
    t.produce(J1, 5);
    t.deliver(J1, 5); // le témoin voit passer 4 tokens ; le client n'acquitte jamais
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
    // Fin du drainage puis de la fenêtre de livraison (24 h) et de l'évaluation.
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
    // Le client conteste trop tard : rejeu gratuit, aucun remboursement.
    let before = t.c().ledger.entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    assert_eq!(
        t.c().ledger.entries().len(),
        before,
        "replay moves no credits"
    );
    t.finish();
}

#[test]
fn f25_lender_cannot_attest_its_own_delivery() {
    let mut t = T::new();
    t.ok(Command::Reserve { job: J1 });
    // Un prêteur ne peut pas être le témoin de sa propre grappe (JOB-R26).
    assert!(matches!(
        t.err(Command::Place {
            job: J1,
            lenders: L.to_vec(),
            recovery_estimate: 0,
            witness: L[2],
            expected_version: None,
        }),
        DomainError::Precondition(_)
    ));
    t.start(J1, 0);
    t.produce(J1, 3);
    // Le nœud de sortie « atteste » lui-même : aucune preuve.
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
    assert!(t.c().charges.is_empty());
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
    t.deliver(J1, 6); // positions 2..6 livrées ; l'accusé du client est perdu
    t.ok(Command::NodeLost {
        job: J1,
        expected_version: None,
    });
    // Le client annonce sa dernière position reçue : 2 et 3 reçues, 4 et 5 non.
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 4,
        digest: t.c().frame_digest(J1, GEN, 4),
    });
    assert_eq!(t.job(J1).validated[GEN.idx()], 4);
    assert_eq!(t.charge(J1, 3).unwrap().basis, ChargeBasis::ClientSigned);
    // 4 et 5 : contestées, rejouées, toujours provisoires (JOB-R33).
    let c5 = t.charge(J1, 5).unwrap();
    assert!(!c5.definitive && c5.contest.is_some());
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    // La reprise repart des positions livrées, pas des validées.
    assert!(matches!(
        t.err(Command::AttemptReady {
            job: J1,
            attempt: 2,
            restored: [0, 4, 0],
        }),
        DomainError::Precondition(_)
    ));
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 6, 0],
    });
    t.gen(J1, 1); // accusé cumulatif jusqu'à 7 : couvre aussi le rejeu de 4 et 5
    assert_eq!(t.charge(J1, 5).unwrap().basis, ChargeBasis::ClientSigned);
    assert!(t.charge(J1, 5).unwrap().contest.is_none());
    for pos in 0..7 {
        assert_eq!(t.net_charges(J1, pos), 1, "position {pos} billed once");
    }
    assert_eq!(
        t.c().outputs[&OutputId {
            job: J1,
            wt: GEN,
            pos: 5
        }],
        1,
        "replayed, not regenerated"
    );
    assert_eq!(
        t.c().outputs[&OutputId {
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
    // Contributions des sorties provisoires : réservées, en attente (JOB-R30) ;
    // la tranche reste close jusqu'à l'échéance (CE-06).
    assert_eq!(t.c().slices[&s].status, SliceStatus::Closed);
    assert_eq!(t.line(s, L[0]).paid, 6);
    assert_eq!(t.line(s, L[0]).disputed, 4 * 6);
    assert!(
        t.sim
            .coord
            .clone()
            .apply(&Command::Arbitrate {
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
    // Le client a reçu 1 et 2, pas 3 ni 4 ; le tampon est perdu.
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
    // 1 et 2 signées par le client → payées ; 3 et 4 annulées → remboursées.
    assert_eq!(t.line(s, L[0]).paid, 3 * 6);
    assert_eq!(t.line(s, L[0]).refunded, 2 * 6);
    assert_eq!(t.line(s, L[0]).disputed + t.line(s, L[0]).pending, 0);
    t.ok(Command::Place {
        job: J1,
        lenders: L.to_vec(),
        recovery_estimate: 2,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::AttemptReady {
        job: J1,
        attempt: 2,
        restored: [0, 3, 0],
    });
    t.gen(J1, 2); // positions 3 et 4 régénérées et facturées une nouvelle fois
    assert_eq!(t.net_charges(J1, 3), 1);
    assert_eq!(t.charge(J1, 3).unwrap().gen, 1);
    assert_eq!(
        t.c().outputs[&OutputId {
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
    // Ni accusé ni heartbeat : les deux échéances tombent ensemble.
    t.ok(Command::Tick { dt: 60 });
    t.ok(Command::Reconcile);
    assert_eq!(
        t.job(J1).exec,
        ExecStatus::Recovering,
        "one transition wins"
    );
    let revocations = t
        .c()
        .audit
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
    // Perte du nœud et du témoin dans la même seconde, sur la reprise.
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
    t.wait(300); // grappe saine : l'autorisation est renouvelée
    t.gen(J1, 1);
    t.ok(Command::Tick { dt: 45 }); // grappe muette
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
            attempt: a
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
    // Sortie de la tentative vivante : on la retransmet, on ne la conteste pas.
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
    let entries = t.c().ledger.entries().len();
    t.ok(Command::ConfirmDelivery {
        job: J1,
        wt: GEN,
        confirmed: 1,
        digest: t.c().frame_digest(J1, GEN, 1),
    });
    // Fenêtre passée : simple retransmission, aucune contestation ni écriture.
    assert!(t.charge(J1, 3).unwrap().contest.is_none());
    assert_eq!(t.c().ledger.entries().len(), entries);
    t.ok(Command::WitnessLost {
        job: J1,
        attempt: 1,
    });
    // Tampon perdu après la fenêtre : la sortie reste due, plus de rejeu possible.
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
    t.start(J1, 2); // la reprise démarre en position 4 sans attendre le client
                    // Budget de flux mesuré depuis la signature du client : 1 seule unité de plus.
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
    // Le client revient : il n'a rien reçu après la position 1.
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

// ------------------------------------------------ JOB-F33 à F41 (v2.5)

/// Fin de flux attestée (positions 1 à 3), nœud perdu.
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
    t.confirm(J1, 1); // « rien reçu après la position 1 » : contestation et rejeu
    assert!(t.charge(J1, 3).unwrap().contest.is_some());
    // Le client signe un signe de vie, mais aucun accusé couvrant le rejeu.
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
    // Le rejeu arrive : accusé cumulatif signé, lié au flux, couvrant 1 à 3.
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
    // Trames d'un autre flux présentées pour ce job.
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
    // Déclaration signée dans une autre session : refusée, rien ne change.
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
    t.ok(Command::Tick { dt: 30 }); // l'attestation complète arrive pendant le drainage
    t.deliver(J1, 4);
    assert!(t
        .c()
        .audit
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
    // Engagement fabriqué après la révocation : refusé.
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
    // Même avec un engagement antérieur, une attestation après le drainage est refusée.
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
    t.ok(Command::Tick { dt: 24 * 3600 - 60 }); // 23 h 59
    t.confirm(J1, 1);
    t.ok(Command::Tick { dt: 120 }); // la fenêtre de 24 h est passée
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
    t.confirm(J1, 4); // le rejeu est bien reçu et acquitté
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
    }); // 23 h 55
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
    // Deux reçus non engagés de 2 crédits avant minuit : 4 = plafond.
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
    // Une contestation rend 2 crédits à l'emprunteur : le quota n'est pas restauré.
    t.ok(Command::ContestReward {
        slice: slices[0],
        lender: L[2],
    });
    t.wait(360); // 00 h 01 : nouveau jour calendaire, même fenêtre glissante
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
    // 24 h après les premiers paiements, le quota est de nouveau disponible.
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
        recovery_estimate: 0,
        witness: WITNESS,
        expected_version: None,
    });
    t.ok(Command::AttemptReady {
        job: j2,
        attempt: 1,
        restored: [0; 3],
    });
    t.gen(j2, 1);
    let s2 = t.open_slice(j2);
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
    t.claim_all(s, Evidence::None); // réclamations envoyées avant le retour de la preuve
    t.close_eval(s);
    assert_eq!(t.c().slices[&s].status, SliceStatus::Closed);
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
