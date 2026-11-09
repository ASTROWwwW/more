# More — modèle exécutable

Modèle exécutable de la spécification d'implémentation **v2.5** de More, réseau de partage GPU pair-à-pair : machine à états des jobs, cycle de vie des tranches, livraison des sorties (attestation, contestation close par accusé signé, rejeu, retour arrière, attestations tardives engagées, empreintes liées au flux), autorisations datées, preuves complémentaires, plafond anti-collusion glissant, règlement financier et registre comptable, sous forme de fonctions de transition pures. Pas de base de données, pas de réseau, pas de moteur GPU.

Les types et transitions de `gpu-domain` et `gpu-ledger` sont faits pour être réutilisés tels quels par le futur coordinateur, qui ajoutera la persistance (PostgreSQL), l'outbox et le réseau.

## Structure

| Chemin | Rôle |
| --- | --- |
| `crates/ledger` | Registre en partie double : clés d'idempotence, insertion seule, chaînage, vérification des invariants (LEDGER-001 à 010) |
| `crates/domain` | Coordinateur : jobs (JOB-T01 à T17), tranches (JOB-S01 à S07), règlement (JOB-S10 à S13), livraison des sorties (section 2.4), règles JOB-R01 à R35. Chaque commande est atomique |
| `crates/protocol` | Premier jet du contrat de messages : enveloppe, contrôle de taille avant décodage, codes d'erreur stables, anti-rejeu, attestant = signataire, empreintes de trames (PROTO-001 à 008) |
| `crates/simulation` | Vérificateur d'invariants (TEST-P01 à P28), monde simulé, générateurs `proptest` d'opérations nominales et adverses, phase de vidage (vivacité, équité), mesures de couverture |
| `tests/properties` | Tests de propriétés (`proptest`), quatre générateurs dont `delivery` (I-03) |
| `tests/scenarios` | Un test déterministe par scénario JOB-F01 à JOB-F41, plus les corrections v2.3 |
| `tests/regressions` | Contre-exemples trouvés, réduits et commentés (CE-01 à CE-06). Ne jamais supprimer |
| `tests/properties/proptest-regressions.txt` | Graines brutes des contre-exemples réels, rejouées en premier |
| `scripts/mutation.py` | Test des tests : réintroduit 52 bugs connus ou plausibles et vérifie que la suite échoue |

## Lancer

```sh
cargo test --release --workspace                         # suite complète (512 cas par propriété)
PROPTEST_CASES=5000 cargo test --release --workspace     # exécution de référence
cargo test -p more-conformance --test scenarios
python3 scripts/mutation.py                              # campagne de mutation (~30 min)
```

Les mesures de couverture de chaque test de propriétés sont écrites dans `target/coverage/*.tsv` pendant l'exécution elle-même.

Rust ≥ 1.75. Seule dépendance externe : `proptest` (tests).

## Comment le modèle vérifie

1. Chaque commande s'applique sur une copie de l'état et n'est conservée qu'en cas de succès (JOB-R01). Un refus ne laisse aucune trace (TEST-P16).
2. Après chaque commande, `check_step` et `check_state` vérifient toutes les propriétés, recalculées à partir du registre et du journal d'audit, sans réutiliser le code du domaine quand c'est possible (leçon de CE-03). Le fondement de chaque facturation est recontrôlé à partir de la commande qui l'a produite (TEST-P20).
3. En fin de trace, `Sim::drain` arrête toute activité, laisse passer les échéances et réconcilie : tout job doit finir terminal, réglé, escrow à zéro, aucune sortie provisoire ni récompense retenue (TEST-P06, P13), et l'équité est vérifiée (TEST-P23).
4. Un test de couverture impose un **nombre minimal** de passages par chemin profond (reprises, rejeux, retours arrière, litiges, arbitrages, libérations…).

## Ajouter une règle

Toute modification de la machine à états ou de la comptabilité doit être accompagnée d'un test qui démontre qu'elle préserve les invariants. Si `proptest` trouve un contre-exemple :

1. la graine est enregistrée automatiquement dans `proptest-regressions.txt` ;
2. recopier la séquence réduite dans `tests/regressions/` avec la règle corrigée ;
3. corriger **la spécification et le code ensemble**, jamais l'invariant pour faire passer le test.

## Limites

Pas d'outbox ni de persistance ; autorisations sur l'horloge du coordinateur, sans dérive des horloges des nœuds ; témoin, acquittement de transport, chiffrement, signatures et rejeu symboliques (empreintes FNV-1a) ; pas de scheduler ni de réseau ; signatures et empreintes symboliques (FNV-1a au lieu de SHA-256) ; vivacité et équité vérifiées sur des traces finies et non démontrées (ce que ferait TLA+). Le plafond anti-collusion est abaissé à 4 crédits (sur 24 h glissantes) dans la simulation pour que les litiges soient exercés.

Licence : AGPL-3.0.

## Documents

- [`docs/spec_v2.5.md`](docs/spec_v2.5.md) : spécification d'implémentation (journal des modifications inclus).
- [`RAPPORT_TESTS.md`](RAPPORT_TESTS.md) : tests réellement exécutés, couverture, mutations, invariants.
