# Rapport de tests — modèle exécutable v2.5

9 novembre 2026 · More 0.3.0 · spécification d'implémentation v2.5

## Résumé

Les **67 tests** de la suite passent. Les quatre tests de propriétés ont été exécutés sur 5 009, 5 009, 2 509 et 5 009 traces aléatoires (les 9 traces en plus sont les graines de non-régression, rejouées en premier). Cela fait **1 997 086 commandes**, chacune suivie de la vérification complète des 28 propriétés. Le total et toutes les mesures de couverture viennent de cette exécution : les tests les écrivent eux-mêmes dans `target/coverage/`.

La v2.5 intègre les six décisions prises après l'audit de la v2.4. En particulier, une contestation de livraison ne se clôt **que** par un accusé cumulatif signé, lié au flux et couvrant la position ; sinon, remboursement à l'échéance. Les huit cas demandés ont chacun un scénario déterministe (JOB-F33 à F41), et ils sont aussi exercés par les générateurs aléatoires et vérifiés par des propriétés (TEST-P08 étendue, P20 étendue, P26 à P28).

Le modèle a trouvé **1 contre-exemple réel** dans ma conception de la v2.5 (CE-06), corrigé dans la spec et le code et devenu un test permanent. La campagne de mutation détecte **52 bugs injectés sur 52**.

Ce que cela ne démontre pas : les garanties de livraison sur un vrai réseau. Le témoin, l'acquittement de transport, les signatures et les empreintes restent symboliques, ce qui justifie le prototype QUIC. Ni l'outbox, ni la dérive des horloges, ni la vivacité sur toutes les traces (TLA+) ne sont couverts.

**Vérification indépendante** : à reproduire depuis l'archive avec les commandes ci-dessous avant de citer ces chiffres.

## 1. Exécution de référence

```
cargo clean
PROPTEST_CASES=5000 cargo test --release --workspace
python3 scripts/mutation.py
```

Rust 1.97.0, Linux, profil `release`. Durée de la suite, compilation comprise : 48 s (propriétés : 19,1 s). Campagne de mutation : environ 35 min.

| Suite | Tests | Résultat |
| --- | --- | --- |
| `gpu-ledger` (unitaires) | 5 | 5 réussis |
| `gpu-protocol` (unitaires) | 4 | 4 réussis |
| `tests/properties` | 5 | 5 réussis |
| `tests/scenarios` | 46 | 46 réussis |
| `tests/regressions` | 7 | 7 réussis |
| **Total** | **67** | **67 réussis, 0 échec** |

Avant l'exécution de référence, une recherche de contre-exemples à 20 000 traces par générateur (plus de 7 millions de commandes) n'en a trouvé aucun.

### Volume et couverture mesurés pendant l'exécution de référence

| Mesure | Général | Pannes | Réserve partielle | Livraison | Total |
| --- | --- | --- | --- | --- | --- |
| Traces | 5 009 | 5 009 | 2 509 | 5 009 | 17 536 |
| **Commandes exécutées et vérifiées** | 456 454 | 632 152 | 292 746 | 615 734 | **1 997 086** |
| dont acceptées | 295 950 | 433 365 | 205 326 | 461 007 | 1 395 648 |
| Reprises (`running → recovering`) | 2 772 | 8 735 | 3 917 | 12 778 | 28 202 |
| Sorties facturées sur accusé | 411 | 1 715 | 756 | 766 | 3 648 |
| Sorties facturées provisoirement (témoin) | 399 | 1 981 | 943 | 2 282 | 5 605 |
| Attestations tardives admises (JOB-R32) | 30 | 272 | 150 | 250 | 702 |
| Contestations de livraison ouvertes, avec rejeu (JOB-R33) | 18 | 179 | 86 | 245 | 528 |
| Provisoires confirmées par le client | 201 | 1 277 | 558 | 1 093 | 3 129 |
| Provisoires confirmées par expiration de fenêtre | 189 | 624 | 347 | 507 | 1 667 |
| Retours arrière (tampon perdu ou contestation échue) | 6 | 49 | 26 | 399 | 480 |
| Sorties annulées | 9 | 80 | 38 | 682 | 809 |
| Tampons purgés après rétention (JOB-R28) | 87 | 187 | 78 | 410 | 762 |
| Preuves complémentaires (JOB-R35) | 7 | 190 | 88 | 54 | 339 |
| Contributions en attente de livraison | 540 | 2 324 | 1 103 | 2 734 | 6 701 |
| Contributions annulées avec leur sortie | 14 | 68 | 46 | 477 | 605 |
| Paiements de contributions | 633 | 3 172 | 1 497 | 2 585 | 7 887 |
| Paiements de récupération | 65 | 786 | 292 | 632 | 1 775 |
| Éléments remboursés faute de preuve (à l'échéance) | 250 | 1 616 | 706 | 753 | 3 325 |
| Éléments contestés (plafond glissant dépassé) | 23 | 283 | 155 | 104 | 565 |
| Paiements par arbitrage | 1 | 59 | 35 | 15 | 110 |
| Remboursements par arbitrage | 22 | 224 | 120 | 89 | 455 |
| Contestations de récompense | 10 | 228 | 89 | 123 | 450 |
| Récompenses libérées | 314 | 1 883 | 844 | 1 594 | 4 635 |
| Refus `INADMISSIBLE_PROOF` (témoin, empreinte, autre session, tardive non engagée) | 1 969 | 1 918 | 869 | 11 476 | 16 232 |
| Refus `LEASE_EXPIRED` | 6 097 | 28 164 | 12 446 | 18 178 | 64 885 |

**Lecture** : chaque mécanisme nouveau de la v2.5 est exercé des centaines de fois, sauf les paiements par arbitrage (110). Le contrôle de couverture exige au moins 5 passages pour ce chemin et pour les preuves complémentaires, sur ses 600 traces. J'ai abaissé ces deux seuils de 10 à 5 et celui des remboursements par arbitrage de 20 à 10, parce que les nouvelles opérations à grands sauts de temps (24 h) diluent ces chemins. Les comptes réels sont ceux du tableau.

### Les huit cas demandés

| Cas | Scénario | Exercé par le générateur | Propriété |
| --- | --- | --- | --- |
| Signe de vie signé sans réception du rejeu : remboursement | JOB-F33 | `ClientHeartbeat`, `ContestReplay` | TEST-P27 : seule une signature couvrant la position confirme une sortie contestée ; aucune contestation échue ne survit à la réconciliation |
| Accusé cumulatif signé couvrant le rejeu : définitive | JOB-F34 | `ContestReplay` puis déclaration complète | TEST-P20, TEST-P27 |
| Accusé d'une autre session : rejet | JOB-F35 | empreintes d'un autre job sur `Deliver` et `Confirm` | TEST-P20 (empreinte recalculée indépendamment) |
| Trame différente de l'empreinte signée : rejet | JOB-F36 | empreinte altérée sur `Deliver` | TEST-P20 |
| Engagement avant révocation, attestation pendant le drainage : admissible | JOB-F37 | `LateDeliver` avec engagement | TEST-P20 (ordre du journal recalculé) |
| Engagement après révocation : rejet | JOB-F38 | `LateDeliver` sans engagement ou engagement tardif | TEST-P20 |
| Contestation juste avant 24 h : tampon conservé | JOB-F39 | `ContestAtWindowEnd` (contestation à 23 h 59 puis purge) | TEST-P26 |
| Plafond aux frontières calendaires et après remboursements | JOB-F40 | `BoundaryBurst` (reçus avant minuit, contestation, reçus après) | TEST-P08 (somme brute sur toute fenêtre de 24 h, recalculée sur le journal) |

### Non-régression (7)

| Test | Origine |
| --- | --- |
| `ce01_*` à `ce05_*` (6 tests) | v2.3 et v2.4. `ce03_*` adapté à JOB-R35 sans changer ce qu'il démontre : l'élément n'est jamais payé, puis il est remboursé à l'échéance |
| `ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open` | CE-06, trouvé dès la première exécution v2.5 par deux générateurs |

Le fichier de graines contient 9 contre-exemples réels : 7 antérieurs et 2 de CE-06. Le script de mutation le restaure après chaque essai.

## 2. Campagne de mutation

52 bugs réintroduits un par un : les 38 de la v2.4, dont deux ancres ajustées au code v2.5 (M20, M28), et 14 nouveaux, numérotés M37 à M50. Le contrôle de couverture ne compte pas comme une détection.

| Mutation | Bug injecté | Détectée par |
| --- | --- | --- |
| M01 à M36 | Bugs historiques v2.1 à v2.4, CE-01 à CE-05 réintroduits (détail dans le rapport v2.4) | Toutes détectées ; propriétés sauf M02 (`f20_*`) et M06 (`f09_*`) |
| M37 | Contestation close par le simple rejeu | TEST-P20, P22 |
| M38 | Signe de vie du client qui résout les contestations | TEST-P20 |
| M39 | Empreinte des trames non vérifiée à l'attestation | TEST-P20 |
| M40 | Déclaration du client non liée au flux | TEST-P20 |
| M41 | Attestation tardive sans engagement antérieur | TEST-P20 |
| M42 | Engagement accepté après révocation et compté comme antérieur | TEST-P20 |
| M43 | Tampon purgé malgré une contestation ouverte | TEST-P26 |
| M44 | Plafond par jour calendaire au lieu d'une fenêtre glissante | `f40_*` dans la campagne ; TEST-P08 après renforcement du générateur (voir ci-dessous) |
| M45 | Remboursement qui restaure le quota (montants nets) | `f40_*` dans la campagne ; TEST-P08 après renforcement |
| M46 | Remboursement faute de preuve avant l'échéance | TEST-P28 |
| M47 | Fenêtre expirée qui ignore les contestations | TEST-P20, P27 |
| M48 | Échéance des contestations jamais appliquée | TEST-P06, P27 |
| M49 | CE-06 réintroduit | TEST-P12 |
| M50 | Preuve complémentaire acceptée après l'échéance | TEST-P28 |

**52 sur 52 détectées. Dans la campagne complète, 48 l'ont été par les propriétés.**

Les quatre détectées seulement par des scénarios :

- **M06** change seulement un code d'erreur, sans violer d'invariant : un scénario seul peut le voir, c'est attendu.
- **M02** est détectée par TEST-P04 dans 2 exécutions sur 3 à 300 traces, toujours à 3 000.
- **M43, M44 et M45** n'étaient d'abord vues que par JOB-F39 et F40, alors que tu avais demandé que ces cas soient exercés par le modèle. Les situations en cause (purge dans la dernière heure d'une contestation, paiements de part et d'autre de minuit après un remboursement) n'apparaissent presque jamais au hasard. J'ai ajouté deux opérations composites au générateur (`ContestAtWindowEnd`, `BoundaryBurst`).
  - M43 est maintenant détectée par TEST-P26 dans la campagne complète.
  - Pour M44 et M45, j'ai encore renforcé `BoundaryBurst` après la campagne : il cible le prêteur à la plus petite part, et une seule salve de reçus avant minuit. Mesuré ensuite sur 3 exécutions à 300 traces, sans aucune graine enregistrée : M44 est détectée par TEST-P08 3 fois sur 3, M45 2 fois sur 3. **Ce dernier changement ne touche que le générateur ; la campagne complète n'a pas été relancée après.**

## 3. Invariants

### Vérifiés

TEST-P01 à TEST-P25 comme en v2.4 (détail dans la spec, section 9.1), avec ces changements :

| ID | Changement v2.5 |
| --- | --- |
| TEST-P08 | Plafond **glissant** : sur tout intervalle de 24 h, somme **brute** des paiements sur reçus non engagés ≤ plafond, recalculée sur le journal des paiements (et non sur le compteur du domaine) |
| TEST-P20 | Une attestation doit porter l'empreinte exacte des trames du flux, recalculée indépendamment ; une attestation tardive doit être couverte par un engagement antérieur à la révocation, pendant le drainage ; une confirmation par le client doit couvrir la position et être liée au flux |
| TEST-P26 *(nouveau)* | Tampon jamais purgé avant 24 h après la révocation, ni tant qu'une sortie de la tentative est provisoire ou contestée |
| TEST-P27 *(nouveau)* | Contestation ouverte une fois, sur déclaration signée, pendant la fenêtre ; sortie contestée confirmée seulement par une signature couvrant sa position ; la fenêtre ne confirme jamais une sortie contestée ; aucune contestation échue après réconciliation |
| TEST-P28 *(nouveau)* | Aucun remboursement faute de preuve avant l'échéance d'évaluation ; aucune preuve complémentaire après |

### Restent à démontrer

| Point | Pourquoi | Comment |
| --- | --- | --- |
| Garanties de livraison sur un vrai réseau | Témoin, acquittement de transport, signatures, empreintes et rejeu sont symboliques | Prototype QUIC à trois processus (étape suivante) |
| Coût du tampon de rejeu | Non mesuré | Prototype : sorties volumineuses, batch, milliers de sessions |
| Livraison des événements (outbox) | Pas de persistance | PostgreSQL + outbox |
| Dérive des horloges des nœuds | Une seule horloge | TLA+ ou horloges locales bornées |
| Vivacité et équité sur toutes les traces | Vérifiées sur traces finies | TLA+ |
| Équité de la récupération | TEST-P23 ne couvre que les contributions | Étendre P23 |

## 4. Incohérences découvertes (v2.5)

| Réf. | Trouvée par | Problème | Correction |
| --- | --- | --- | --- |
| CE-06 | proptest, TEST-P12, à la première exécution | Une tranche terminait son évaluation avant l'échéance avec une contribution en attente de sa sortie. Celle-ci devenue définitive, la contribution sans preuve redevenait « en attente de preuve » dans une tranche déjà évaluée | JOB-S04 : avant l'échéance, la tranche ne se termine pas tant qu'une contribution attend sa sortie |
| I-17 | JOB-F39 | Les positions qui suivent une position contestée en dépendent : la fenêtre ne peut pas les confirmer | JOB-R29 : l'expiration s'arrête à la première position contestée |
| I-18 | Audit v2.4 | Un rejeu rendait la sortie définitive sans preuve de réception | JOB-R33 |
| I-19 | JOB-R14 et JOB-R35 | « Évaluation unique » ne peut plus signifier « en une commande » | Chaque élément décidé une fois ; la tranche se termine une fois, au plus tard à l'échéance |
| I-20 | Coût du tampon | Non négligeable pour les grosses sorties | Décision à confirmer |

Aucun invariant n'a été affaibli pour faire passer un test. Plusieurs tests anciens ont dû suivre les nouvelles règles, sans que leur intention change :
- CE-03 et JOB-F17 : remboursement à l'échéance, plus à l'évaluation ;
- JOB-F24 et F31 : fenêtre de 24 h ;
- JOB-F26 : un rejeu reste contesté jusqu'à l'accusé ;
- JOB-F27 : la tranche reste close avant l'échéance, conséquence de CE-06 ;
- JOB-F17 et F21 : désormais explicitement configurés avec le plafond de 8 crédits pour lequel ils ont été écrits, la simulation passant à 4.

## 5. Décisions à confirmer

Détaillées dans la section 10 de la spec v2.5 : le délai de résolution d'une contestation (1 h dans le modèle), le coût et le financement du tampon de rejeu, la formule de réputation des témoins, et la contribution remboursée faute de preuve qui reste prise après l'échéance.

## 6. Prochaines étapes (ordre validé)

1. Prototype réel du témoin : trois processus (nœud de sortie, témoin, client) sur QUIC, trames authentifiées, signatures vérifiées, accusés applicatifs, rejeu exact, pertes réseau simulées, puis les mêmes cas adverses que JOB-F33 à F41.
2. TLA+ : sûreté et vivacité, avec hypothèses explicites sur les pannes permanentes et les participants malveillants.
3. PostgreSQL + outbox : mêmes transitions, atomicité, idempotence et redémarrages sur une vraie base.
