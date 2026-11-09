//! Tests de propriétés (section 9, TEST-P01 à TEST-P28).
//!
//! `proptest` génère des séquences de commandes, pannes, doublons, versions
//! concurrentes, sauts d'horloge et comportements adverses (client qui
//! n'acquitte pas, prêteur qui atteste sa propre livraison, témoin qui perd son
//! tampon, client qui ment sur ce qu'il a reçu). Après chaque commande, toutes
//! les propriétés d'état et de transition sont vérifiées ; en fin de séquence,
//! la phase de vidage vérifie la vivacité et l'équité.
//!
//! Tout contre-exemple trouvé est enregistré dans
//! `tests/properties/proptest-regressions.txt` (rejoué en premier à chaque
//! exécution) ET recopié à la main, réduit, dans `tests/regressions/`.
//!
//! Chaque test écrit ses mesures de couverture dans `target/coverage/` : le
//! rapport cite ces fichiers, produits par l'exécution de référence elle-même.

use std::sync::Mutex;

use gpu_simulation::*;
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, TestCaseError, TestRunner};

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

fn report(sim: &Sim, ops: &[Op]) -> String {
    format!(
        "{} violation(s):\n{}\nops: {ops:#?}",
        sim.violations.len(),
        sim.violations
            .iter()
            .map(|v| format!("  [{}] {}", v.property, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Exécute une propriété : chaque trace est rejouée commande par commande
/// sous le vérificateur complet, puis vidée.
fn run_property(
    name: &str,
    cases: u32,
    max_len: usize,
    strategy: impl Strategy<Value = Op>,
    cfg: gpu_domain::Config,
) {
    let config = ProptestConfig {
        cases,
        max_shrink_iters: 20_000,
        // Contre-exemples rejoués en premier à chaque exécution (non-régression).
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/properties/proptest-regressions.txt",
        ))),
        ..ProptestConfig::default()
    };
    let stats = Mutex::new(Stats::default());
    let mut runner = TestRunner::new(config);
    let result = runner.run(&prop::collection::vec(strategy, 1..max_len), |ops| {
        let mut sim = Sim::new(cfg.clone());
        for op in &ops {
            sim.run_op(op);
            if !sim.violations.is_empty() {
                return Err(TestCaseError::fail(report(&sim, &ops)));
            }
        }
        sim.drain();
        if !sim.violations.is_empty() {
            return Err(TestCaseError::fail(report(&sim, &ops)));
        }
        stats.lock().unwrap().add(&sim);
        Ok(())
    });
    let stats = stats.into_inner().unwrap();
    stats.write(name);
    if let Err(e) = result {
        panic!("{name}: {e}");
    }
}

/// Toutes les propriétés de sûreté après chaque commande, puis la vivacité.
#[test]
fn invariants_hold_on_random_traces() {
    run_property("random", cases(), 160, op_strategy(), sim_config());
}

/// Traces longues orientées « pannes » : plus de pertes de nœud, de reprises
/// et de réclamations tardives.
#[test]
fn invariants_hold_under_heavy_faults() {
    run_property("faults", cases(), 220, fault_heavy_op(), sim_config());
}

/// Réserve initiale partielle : l'escrow peut s'épuiser (JOB-R25, JOB-F10),
/// les reprises passent par des compléments (JOB-T12).
#[test]
fn invariants_hold_with_partial_reserve() {
    run_property(
        "partial_reserve",
        cases() / 2,
        200,
        fault_heavy_op(),
        gpu_domain::Config {
            initial_reserve_max: 40,
            ..sim_config()
        },
    );
}

/// I-03 (v2.4) : livraison attestée, client qui n'acquitte pas, prêteur qui
/// atteste lui-même, témoin qui perd son tampon, client qui ment à la reprise,
/// pannes simultanées.
#[test]
fn invariants_hold_under_delivery_adversaries() {
    run_property(
        "delivery",
        cases(),
        200,
        delivery_adversary_op(),
        sim_config(),
    );
}

/// Mélange qui force le chemin nominal + pannes : réserver, placer, démarrer,
/// produire, acquitter, réclamer, perdre un nœud, reprendre.
fn fault_heavy_op() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        2 => b().prop_map(Op::Reserve),
        3 => (b(), b(), b()).prop_map(|(job, rot, est)| Op::Place { job, rot, est }),
        3 => b().prop_map(|job| Op::Ready { job, correct: true }),
        6 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        6 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        3 => (b(), b(), b()).prop_map(|(job, stage, wt)| Op::Commit { job, stage, wt, partial: false }),
        6 => (b(), b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, wt, pos, ev)| Op::Claim { job, slice, stage, wt, pos, ev, honest: true }),
        2 => (b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, amount, ev)| Op::ClaimRecovery { job, slice, stage, amount, ev }),
        3 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(|job| Op::StaleProduce { job }),
        2 => b().prop_map(Op::Pause),
        2 => (b(), b()).prop_map(|(job, topup)| Op::Resume { job, topup }),
        1 => (b(), b()).prop_map(|(job, amount)| Op::Fund { job, amount }),
        3 => (b(), b()).prop_map(|(job, slice)| Op::Close { job, slice }),
        3 => (b(), b()).prop_map(|(job, slice)| Op::Evaluate { job, slice }),
        2 => b().prop_map(Op::Tick),
        2 => Just(Op::Reconcile),
        2 => any::<u16>().prop_map(Op::Duplicate),
        1 => (b(), b()).prop_map(|(job, pair)| Op::Concurrent { job, pair }),
        1 => b().prop_map(Op::Finish),
        30 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        3 => (b(), b(), b(), b()).prop_map(|(job, slice, stage, pos)| Op::CrossAttemptClaim { job, slice, stage, pos }),
        3 => (b(), b(), b(), prop::bool::weighted(0.1)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        1 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        1 => (b(), b(), b(), b()).prop_map(|(job, slice, lender, pay)| Op::Arbitrate { job, slice, lender, pay: pay % 2 == 0 }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        4 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        6 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        2 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        3 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::ContestReplay { job, sel }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::BoundaryBurst { job, sel }),
        1 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
    ]
}

/// Mélange centré sur I-03 : peu d'accusés, beaucoup d'attestations, de
/// déclarations du client, de pertes de témoin et de pannes simultanées.
fn delivery_adversary_op() -> impl Strategy<Value = Op> {
    let b = any::<u8>;
    prop_oneof![
        3 => b().prop_map(|job| Op::Ready { job, correct: true }),
        8 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Produce { job, wt, n }),
        2 => (b(), b(), b()).prop_map(|(job, wt, n)| Op::Ack { job, wt, n }),
        8 => (b(), b(), b(), prop::bool::weighted(0.25)).prop_map(|(job, wt, n, forged)| Op::Deliver { job, wt, n, forged }),
        6 => (b(), b(), b()).prop_map(|(job, wt, sel)| Op::Confirm { job, wt, sel }),
        3 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::WitnessLost { job, prev }),
        3 => (b(), b()).prop_map(|(job, kind)| Op::DoubleFault { job, kind }),
        3 => b().prop_map(Op::NodeLost),
        2 => b().prop_map(Op::Pause),
        2 => b().prop_map(Op::Finish),
        3 => b().prop_map(Op::Heartbeat),
        3 => (b(), b(), b()).prop_map(|(job, stage, wt)| Op::Commit { job, stage, wt, partial: false }),
        4 => (b(), b(), b(), b(), b(), b()).prop_map(|(job, slice, stage, wt, pos, ev)| Op::Claim { job, slice, stage, wt, pos, ev, honest: true }),
        2 => b().prop_map(Op::Tick),
        2 => Just(Op::Reconcile),
        2 => any::<u16>().prop_map(Op::Duplicate),
        30 => (b(), b()).prop_map(|(job, sel)| Op::Drive { job, sel }),
        5 => (b(), b()).prop_map(|(job, sel)| Op::DeliverAndSettle { job, sel }),
        2 => (b(), b()).prop_map(|(job, sel)| Op::UncommittedBurst { job, sel }),
        5 => (b(), b()).prop_map(|(job, sel)| Op::ArbitrateDisputed { job, sel }),
        2 => b().prop_map(|job| Op::ContestUnderLiveResume { job }),
        4 => (b(), any::<bool>()).prop_map(|(job, commit_first)| Op::LateDeliver { job, commit_first }),
        3 => b().prop_map(Op::ClientHeartbeat),
        4 => (b(), b()).prop_map(|(job, sel)| Op::ContestReplay { job, sel }),
        1 => b().prop_map(|job| Op::ContestAtWindowEnd { job }),
        1 => (b(), b()).prop_map(|(job, sel)| Op::BoundaryBurst { job, sel }),
        3 => (b(), any::<bool>()).prop_map(|(job, prev)| Op::PurgeBuffer { job, prev }),
        3 => (b(), b(), any::<bool>()).prop_map(|(job, sel, honest)| Op::Supplement { job, sel, honest }),
    ]
}

/// Contrôle de couverture : sans cela, des propriétés « vraies » pourraient
/// l'être seulement parce que les chemins intéressants ne sont jamais atteints.
/// Chaque chemin doit être atteint un nombre minimal de fois.
#[test]
fn generator_reaches_interesting_paths() {
    use proptest::strategy::ValueTree;

    let mut total = Stats::default();
    for (gen_name, n) in [("faults", 300usize), ("delivery", 300)] {
        let mut runner = TestRunner::deterministic();
        let mut st = Stats::default();
        for _ in 0..n {
            let ops = if gen_name == "faults" {
                prop::collection::vec(fault_heavy_op(), 150)
                    .new_tree(&mut runner)
                    .unwrap()
                    .current()
            } else {
                prop::collection::vec(delivery_adversary_op(), 150)
                    .new_tree(&mut runner)
                    .unwrap()
                    .current()
            };
            let mut sim = Sim::default();
            for op in &ops {
                sim.run_op(op);
            }
            sim.drain();
            st.add(&sim);
        }
        total.merge(&st);
    }
    total.write("generator_paths");
    let minimum = [
        ("reprises (running → recovering)", 200),
        ("tentatives ≥ 2 démarrées", 200),
        ("sorties facturées sur accusé", 200),
        ("sorties facturées provisoirement (témoin)", 200),
        ("provisoires confirmées par le client", 20),
        ("provisoires confirmées par expiration de fenêtre", 20),
        ("sorties rejouées", 20),
        ("sorties annulées (retour arrière)", 20),
        ("retours arrière", 10),
        ("contestations de livraison ouvertes", 30),
        ("attestations tardives admises", 10),
        ("tampons purgés après rétention", 10),
        ("preuves complémentaires", 5),
        ("paiements de contributions", 100),
        ("paiements de récupération", 20),
        ("contributions en attente de livraison", 30),
        ("contributions annulées avec leur sortie", 3),
        ("éléments contestés", 10),
        ("paiements par arbitrage", 5),
        ("remboursements par arbitrage", 10),
        ("contestations de récompense", 10),
        ("récompenses libérées", 100),
    ];
    let missing: Vec<String> = minimum
        .iter()
        .filter(|(k, min)| total.counts.get(k).copied().unwrap_or(0) < *min)
        .map(|(k, min)| format!("{k}: {} < {min}", total.counts.get(k).copied().unwrap_or(0)))
        .collect();
    for refusal in ["InadmissibleProof", "LeaseExpired", "Precondition"] {
        assert!(
            total.refusals.get(refusal).copied().unwrap_or(0) > 0,
            "generator never triggered a {refusal} refusal"
        );
    }
    assert!(missing.is_empty(), "generator under-covers: {missing:#?}");
}
