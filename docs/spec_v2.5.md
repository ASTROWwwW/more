# More — Spécification d'implémentation v2.5

9 novembre 2026 · @Astrxw

Cette spécification décrit **comment** le système fonctionne, à partir des décisions du document d'architecture v1.1. Elle commence par la machine à états des jobs, dont découlent le protocole, la comptabilité et l'orchestration. Chaque exigence a un identifiant stable relié à au moins un test.

**Critère de validation** : aucune séquence de pannes, de retries, d'annulations ou de déconnexions ne doit pouvoir produire un double paiement d'une même sortie ou d'une même contribution, un solde négatif, une reprise sur une mauvaise tentative, une perte silencieuse de positions validées, un escrow jamais soldé, ou un transfert de crédits d'un payeur vers un autre (emprunteur, pool). Depuis la v2.4 s'y ajoutent : aucune facturation sans preuve admissible de livraison, aucune position livrée régénérée, une exposition de chaque partie bornée par le budget de flux, et aucune contribution honnête, prouvée et financée qui reste impayée sans décision explicite. Depuis la v2.5 : aucune sortie contestée rendue définitive sans accusé signé du client la couvrant, aucune preuve réutilisable dans un autre flux, et aucun tampon de rejeu libéré tant qu'une contestation peut encore en avoir besoin.

**Statut de la v2.5** : vérifiée contre le modèle exécutable More 0.3.0 (Rust, `proptest`). Dernière itération documentaire avant le prototype réseau du témoin (QUIC), sauf incohérence critique révélée par les tests. Les sections 2, 3 et 4 sont implémentées dans la crate `gpu-domain` et couvertes par les tests de la section 9. Les sections 5 à 8 restent à compléter. Toute modification importante de la machine à états ou de la comptabilité DOIT être accompagnée d'un test du modèle démontrant qu'elle préserve les invariants. Le protocole de livraison (section 2.4) a été soumis au modèle avant d'entrer dans cette spécification ; ses garanties restent à confirmer sur de vrais échanges réseau.

## Journal des modifications v2.4 → v2.5

### Décisions prises après l'audit de la v2.4

| Point | Décision | Exigences | Tests |
| --- | --- | --- | --- |
| Confiance du témoin | Réputation distincte des témoins dès le MVP ; sélection par phase (pool, puis opérateurs reconnus des deux pools, puis public avec limites d'exposition et contrôles aléatoires) ; caution reportée | JOB-R26 | — (hors modèle) |
| Fenêtre de livraison | 24 h de contestation (au lieu de 10 min) ; tampon conservé au moins 24 h **et** jusqu'à la résolution des contestations ouvertes ; récompenses retenues 48 h | JOB-R28, R29 | TEST-P26, JOB-F39 |
| Clôture d'une contestation | **Seul un accusé applicatif cumulatif signé, lié au flux et couvrant la position** la rend définitive. Un rejeu, un rejeu attesté ou un simple signe de vie ne suffisent pas. Sans accusé à l'échéance : remboursement | JOB-R33 | TEST-P27, JOB-F33, F34 |
| Lien cryptographique | Empreinte chaînée signée par le nœud de sortie couvrant job, flux client, modèle, type, position et génération de facturation ; une trame substituée ou d'une autre session est refusée | JOB-R34 | TEST-P20, JOB-F35, F36 |
| Attestations tardives | Nouvelles livraisons refusées après révocation ; attestation complète recevable pendant le drainage **si** un engagement court du témoin a été enregistré avant la révocation | JOB-R32 | TEST-P20, JOB-F37, F38 |
| Contributions sans preuve | Preuve complémentaire possible jusqu'à l'échéance d'évaluation ; remboursement définitif à l'échéance seulement ; après la clôture, aucune modification (correction = nouvelle écriture financée) | JOB-R35, JOB-S04 | TEST-P28, JOB-F41 |
| Plafond anti-collusion | Fenêtre glissante de 24 h sur les **montants bruts** admis ; un remboursement ne restaure pas le quota | JOB-R19 | TEST-P08, JOB-F40 |

### Découvertes pendant l'implémentation

| Réf. | Comment | Problème | Correction |
| --- | --- | --- | --- |
| CE-06 | Contre-exemple `proptest` (TEST-P12), générateurs général et réserve partielle, dès la première exécution | Une tranche terminait son évaluation avant l'échéance alors qu'une contribution attendait la livraison de sa sortie. La sortie devenue définitive, la contribution sans preuve redevenait « en attente de preuve » (JOB-R35) dans une tranche déjà évaluée : tranche finale avec un montant en attente | JOB-S04 : avant l'échéance, l'évaluation ne se termine pas tant qu'une contribution attend sa sortie. Test `ce06_*` |
| I-17 | JOB-F39 | L'expiration de la fenêtre ne peut pas rendre définitives les positions qui **suivent** une position contestée : elles en dépendent, et un remboursement de la position contestée les annulera | JOB-R29 : l'expiration s'arrête à la première position contestée ou non échue |
| I-18 | JOB-R33 | Le v2.4 rendait une sortie définitive dès son rejeu, avant toute preuve de réception (point soulevé par l'audit) | JOB-R33 ; `ChargeBasis::Replayed` supprimé du modèle |
| I-19 | JOB-R14 avec JOB-R35 | « Évaluation unique » ne peut plus signifier « en une seule commande » : les paiements prouvés sont immédiats, les remboursements faute de preuve attendent l'échéance | JOB-R14 reformulée : chaque élément est décidé une seule fois, et la tranche se termine une seule fois |
| I-20 | Coût du tampon | Pour quelques tokens, la conservation est négligeable ; pour des sorties volumineuses ou des milliers de sessions, il faudra la mesurer | Décision à confirmer (section 10) |

## Journal des modifications v2.3 → v2.4

### Décision I-03 : livraison prouvée et rejeu

La v2.3 rendait l'accusé du client indispensable à la facturation : un emprunteur pouvait recevoir une réponse puis refuser systématiquement de confirmer. La v2.4 adopte la variante avec preuve de livraison et rejeu, en distinguant trois situations.

| Situation | Comportement | Règles |
| --- | --- | --- |
| Token reçu et acquitté par le client | Facturation définitive de la sortie | JOB-R23 |
| Token livré avec attestation du témoin, accusé perdu | Facturation provisoire, token conservé pour rejeu ; définitive à la confirmation du client, au rejeu ou à l'expiration de la fenêtre de livraison | JOB-R26 à JOB-R30 |
| Token produit sans preuve de livraison | Pas de facturation ; travail non confirmé, perte du prêteur ≤ `K` | JOB-R06, JOB-R13 |

Une preuve d'envoi n'est pas une preuve de réception : seule l'attestation d'un **témoin de livraison** indépendant des prêteurs et de l'emprunteur (le relais par lequel passe le flux chiffré vers le client) est recevable, et seule la signature du client est définitive par elle-même. Un hash signé par le prêteur ne prouve rien (JOB-R26).

| Exigence | Changement | Tests |
| --- | --- | --- |
| JOB-R26 *(nouvelle)* | Témoin de livraison assigné à chaque tentative, indépendant ; seul habilité à attester | TEST-P20, JOB-F25, `delivery_attested_by_a_lender_is_inadmissible` |
| JOB-R27 *(nouvelle)* | Facturation provisoire sur attestation ; positions livrées ≥ positions validées | TEST-P05, TEST-P19, TEST-P21, JOB-F24 |
| JOB-R28 *(nouvelle)* | Tampon de rejeu ; déclaration signée du client à la reprise ; rejeu sans refacturation | TEST-P25, JOB-F26, JOB-F30 |
| JOB-R29 *(nouvelle)* | Fenêtre de livraison, contestation unique, retour arrière si le tampon est perdu | TEST-P20, JOB-F27, JOB-F31, JOB-F32 |
| JOB-R30 *(nouvelle)* | Une contribution n'est jamais payée tant que sa sortie est provisoire | TEST-P22, JOB-F27 |
| JOB-R31 *(nouvelle)* | Autorisations datées, renouvelées par heartbeat ; expiration = refus immédiat puis révocation | TEST-P24, JOB-F28, JOB-F29 |
| JOB-R06, R13, R23, R25 | Accusé non indispensable ; budget de flux mesuré depuis la signature du client ; validée ≠ livrée ; fenêtre mesurée depuis les positions livrées | TEST-P09, TEST-P18, TEST-P21 |
| JOB-T05, T08, T13 | Reprise aux positions **livrées** ; T08 déclenchée aussi par l'expiration d'autorisation et par un retour arrière ; T13 exige que tout le produit soit livré | TEST-P07, TEST-P25 |
| JOB-S04, S06, S12 | Contributions de sorties provisoires mises en attente, jamais arbitrées à part ; règlement après résolution des livraisons | TEST-P22, TEST-P06 |

### Demandes de l'audit de la v2.3

| Demande | Réponse | Tests |
| --- | --- | --- |
| Propriété d'équité | TEST-P23 : en fin de vidage, toute contribution réclamée par le bon prêteur sur une sortie restée facturée est réservée ; toute contribution prouvée par engagement antérieur et financée est payée et sa récompense libérée ou contestée ; un reçu non engagé n'est remboursé que par arbitrage | TEST-P23 |
| Récompenses retenues et arbitrages peu exercés | Libération automatique à la fin de la fenêtre (JOB-R22, JOB-R20). Opérations dédiées dans le générateur (litiges, arbitrage explicite). Le contrôle de couverture impose désormais un **nombre minimal** de passages par chemin, pas un seul | `generator_reaches_interesting_paths` |
| Horloge et expiration des leases | JOB-R31 ; heartbeat ; refus immédiat sous autorisation expirée ; révocation par la réconciliation | TEST-P24, JOB-F28, JOB-F29 |
| Tests adverses sur I-03 | Nouveau générateur `delivery` : client qui n'acquitte pas, prêteur qui atteste sa propre livraison, perte d'accusé, perte du tampon, client qui ment à la reprise, pannes simultanées. Scénarios JOB-F24 à JOB-F32 | Section 9 |
| Total de commandes incohérent (1,3 million annoncé, 1,6 million dans le tableau) | Les deux chiffres venaient de deux exécutions différentes : le tableau de couverture avait été mesuré à part, avec 5 000 traces pour la réserve partielle, alors que l'exécution de référence en utilisait 2 500. Les mesures sont désormais écrites par les tests eux-mêmes pendant l'exécution de référence (`target/coverage/`) : une seule source | `RAPPORT_TESTS.md` |

### Découvertes pendant l'implémentation

| Réf. | Comment | Problème | Correction |
| --- | --- | --- | --- |
| CE-04 | Contre-exemple `proptest` (TEST-P06), générateur `delivery` | Tranche close, contribution réservée mais pas encore évaluée, puis sortie annulée par retour arrière : l'évaluation retranchait l'élément déjà remboursé, échouait, et la réconciliation avalait l'erreur. Job bloqué en `finalizing` | JOB-S04 : seuls les éléments encore `pending_evaluation` sont évalués. JOB-R20 : une erreur interne n'est jamais avalée par la réconciliation. Test `ce04_*` |
| CE-05 | Contre-exemple `proptest` (TEST-P23, nouvelle propriété), trouvé par les quatre générateurs | En partage libre, une contribution payée vaut 0 : rien n'est retenu, donc rien n'est jamais libéré, et la récompense restait « ni libérée ni contestée » pour toujours | JOB-R22 : une récompense nulle est complète dès son paiement. Test `ce05_*` |
| D-01 | TEST-P22, pendant l'écriture de JOB-F27 | Défaut d'implémentation (pas de la spec) : une contribution en attente remboursée par annulation gardait son marqueur « en attente » | Marqueur effacé à tout paiement ou remboursement |
| I-11 | Conception de JOB-R28 | Contester une sortie de la tentative **vivante** n'a pas de sens : le témoin est en ligne, il suffit de retransmettre. Autoriser la contestation y créerait un retour arrière inutile | JOB-R28 : seules les sorties de tentatives révoquées peuvent être déclarées manquantes |
| I-12 | TEST-P21 | L'exposition n'est pas bornée « par interruption » mais **pour tout le job** : le budget de flux étant mesuré depuis la dernière signature du client, au plus `K` positions par type sont livrées sans signature, quel que soit le nombre de reprises | JOB-R27 ; JOB-F15 et JOB-F24 reformulés |
| I-13 | JOB-F32 | Un retour arrière invalide toute production construite sur les sorties annulées, y compris celle d'une tentative de reprise déjà démarrée | JOB-R29 : la tentative vivante est révoquée (JOB-T08 ou JOB-T06) |
| I-14 | JOB-F27 | Une sortie annulée puis régénérée est une nouvelle facturation : ses contributions ne peuvent pas porter le même identifiant que celles de l'ancienne | `contribution_id` inclut la génération de facturation de la sortie |
| I-15 | JOB-R08 appliqué à JOB-R22 | « Libération possible après la fenêtre » n'était pas une transition automatique : une récompense pouvait rester retenue indéfiniment, contrairement à JOB-R08 | JOB-R22 : la réconciliation libère les récompenses à la fin de la fenêtre |
| I-16 | JOB-F32 | Avec un budget de flux mesuré depuis la signature du client, une reprise après une fin de flux provisoire démarre avec une fenêtre réduite : elle ne produit que `K − (livrées − validées)` unités avant le premier accusé | Comportement voulu (borne d'exposition). Documenté en JOB-R27 |

## Journal des modifications v2.2 → v2.3

### Corrections demandées (audit de la v2.2)

| Exigence | Problème corrigé | Nouvelle règle | Tests |
| --- | --- | --- | --- |
| JOB-R17, JOB-R21 | Une « unité logique » `(job, type, position)` ne distinguait pas les plages de couches : 4 GPU produisant le même token semblaient faire le même travail | Séparation `output_id = (job, type, position)` (facturé une fois à l'emprunteur) et `contribution_id = (output_id, plage de couches, rôle)` (chaque contribution rémunérée une fois). Somme des contributions d'une sortie ≤ prix de la sortie | `r21_every_stage_paid_once_and_sum_le_price`, `r21_rounding_never_exceeds_price`, TEST-P03, TEST-P15 |
| JOB-R24, JOB-S03 | `paid + refunded + disputed = claimed` faux entre clôture et évaluation | Ajout de `pending_evaluation` : `claimed = pending + paid + refunded + disputed`. Réservation atomique de toutes les lignes à la clôture, plafonnée par les sorties réellement facturées | `r24_pending_evaluation_balances_line_between_close_and_evaluate`, TEST-P12 |
| JOB-R22, JOB-S12 | Origine des remboursements après clôture du job non définie | Fenêtre unique de contestation : les récompenses restent retenues, une contestation rembourse depuis elles, une libération est définitive. Aucune contestation ne crée de crédits | `r22_contest_after_job_closed_refunds_from_held_rewards`, TEST-P12 |
| Section 9 | Tests déterministes limités à JOB-F01 à F14 | Un test par scénario JOB-F01 à JOB-F23 | Section 9.2 |

### Découvertes pendant l'implémentation

| Réf. | Comment | Problème | Correction |
| --- | --- | --- | --- |
| CE-01 | Contre-exemple `proptest` (TEST-P13), réduit à une commande | Le pool pouvait financer la récupération d'un job encore `queued` ; le rejet du job (JOB-S13, « aucune écriture ») laissait ces crédits sans responsable | JOB-R18 : relais du pool seulement si `settlement_status = active` |
| CE-02 | En écrivant le test de CE-01 ; aucune propriété ne le surveillait | JOB-S12 rendait tout le budget de récupération non utilisé à l'emprunteur, y compris la part avancée par le pool | JOB-R18 : budget de l'emprunteur consommé d'abord, puis relais du pool. JOB-S12 et JOB-R22 rendent à chaque payeur sa part. Nouvelle propriété TEST-P17 |
| CE-03 | Contre-exemple `proptest` (TEST-P08), réduit à 8 opérations, une fois le vérificateur rendu indépendant du domaine | Un engagement enregistré après la clôture d'une tranche (mais avant son évaluation) était accepté comme preuve. De plus, l'antériorité se jugeait sur l'heure : un engagement et une révocation à la même seconde étaient indiscernables | JOB-R09, JOB-R12, JOB-R15 : l'antériorité se juge sur le numéro de séquence du journal du coordinateur, avant la plus ancienne de la révocation et de la clôture de la tranche |
| I-03 | Implémentation de JOB-F15 avec JOB-R17 | Contradiction : JOB-F15 payait des unités non acquittées couvertes par des engagements, alors que la reprise repart de la dernière position validée et les régénère. Une même position pouvait être facturée deux fois, ou une contribution de la tentative suivante ne jamais être payée | JOB-R23 : une sortie n'est facturée qu'à sa validation, liée à la tentative qui l'a validée. JOB-R06 reformulée. JOB-F15 réécrit : la fenêtre non acquittée n'est jamais facturée, la perte est bornée par le budget de flux. **Décision à confirmer** (voir section 10) |
| I-04 | Définition de « position validée » | « Inscrite par le client » laissait deux autorités possibles (client et coordinateur) | JOB-R23 : la position est validée quand le coordinateur accepte l'accusé du client pour la tentative courante |
| I-05 | JOB-F10 inatteignable | Avec un escrow égal au coût complet, la fenêtre non validée est toujours couverte : JOB-F10 ne pouvait pas se produire | JOB-T02 : réserve initiale plafonnable, compléments par JOB-T12. Nouvelle règle JOB-R25 (couverture de la fenêtre) |
| I-06 | Preuve du travail de récupération | Un recalcul n'a pas de position à engager : la preuve « engagement de reçus » ne s'y applique pas | JOB-R18 : le travail de récupération est attesté par l'acceptation de la tentative (JOB-T05), observée par le coordinateur |
| I-07 | Engagements de reçus | Ne garder que le dernier engagement effaçait la preuve d'antériorité des plus anciens | JOB-R15 : l'historique complet des engagements horodatés est conservé |
| I-08 | Enveloppe de récupération | Une enveloppe attribuée à une tentative échouée restait perdue pour les reprises suivantes | JOB-R18 : enveloppe non utilisée rendue au budget quand la tentative est révoquée et ses tranches finales |
| I-09 | Commission | Prélevée à l'évaluation, elle rendait la contestation incomplète | LEDGER-008 : commission prélevée à la libération de la récompense |
| I-10 | JOB-T13 | « Dernière unité livrée » était ambigu | JOB-T13 exige que toutes les unités produites soient validées ; sinon, chemin du client silencieux (JOB-T11) |

## Journal des modifications v2.1 → v2.2

| Exigence | Problème corrigé | Nouvelle règle | Tests |
| --- | --- | --- | --- |
| JOB-T04, JOB-T05, JOB-T06, JOB-T12 | `recovery_mode` remis à `false` par JOB-T04 après une pause | Remplacé par `execution_intent` (`initial` / `resume`), monotone. JOB-T06 renvoie vers l'état d'origine du placement | TEST-P07, JOB-F19 |
| JOB-R14, JOB-R17 | Deux tentatives pouvaient être payées pour les mêmes positions | Facturation par unité logique, au plus une fois ; recalcul de reprise facturé à part | TEST-P03, JOB-F20 |
| JOB-S01 à JOB-S07 | Règlement partiel et litige ambigus | Montants explicites par tranche et par prêteur ; évaluation atomique unique | TEST-P12, JOB-F21 |
| JOB-T14 à JOB-T17, section 2.3 | Job terminal avec escrow non soldé | `execution_status` et `settlement_status` séparés | TEST-P13, JOB-F22 |
| JOB-T02, JOB-T09, JOB-R18 | Recalcul de reprise non financé | Budget de récupération de 10 % du coût estimé, provisionné à la réservation | TEST-P14, JOB-F23 |
| JOB-R12, JOB-R19 | Deux comptes ≠ deux participants indépendants | Reçus = preuves de transmission ; plafond sur reçus non engagés | TEST-P10 |
| JOB-R08, JOB-R20 | Une alerte n'est pas une récupération | Réconciliation automatique avec échéances | TEST-P06 |
| JOB-R13, JOB-R16 | K ne couvrait que la génération | Trois budgets de flux | TEST-P09 |

## Journal des modifications v2.0 → v2.1

| Exigence | Problème corrigé | Nouvelle règle |
| --- | --- | --- |
| JOB-T09 | Reprise en `running` sans acceptation de la nouvelle grappe | `recovering → placing`, `running` seulement après JOB-T05 |
| JOB-T08, JOB-T11, JOB-T13 | Tranches ouvertes non réglées à l'interruption | Drainage des tranches |
| JOB-T15, JOB-T16 | Contradiction avec JOB-F09 sur `settling` | `settling` n'est ni annulable ni en échec |
| JOB-T03, JOB-T12 | Solde insuffisant = annulation ; reprise en partage libre impossible | Attente en `queued` ; crédits ou quota selon le pool |
| JOB-R05, JOB-R06, JOB-R08 | Rejet trop large, veto du client, timeouts incomplets | Reçus antérieurs recevables, preuves admissibles, table complète des échéances |

## 1. Conventions

Les exigences sont numérotées par domaine et ne sont jamais renumérotées : une exigence retirée garde son numéro avec le statut « retirée ».

| Préfixe | Domaine |
| --- | --- |
| `JOB-T` | Transitions de la machine à états |
| `JOB-S` | Cycle de vie des tranches (S01 à S07) et statut de règlement du job (S10 à S13) |
| `JOB-R` | Règles globales |
| `JOB-F` | Scénarios d'échec |
| `PROTO` | Messages et protocole |
| `ENGINE` | Interface moteur |
| `LEDGER` | Comptabilité |
| `ORCH` | Orchestration |
| `TEST` | Tests de conformité |

**Mots-clés** : DOIT (obligatoire), NE DOIT PAS (interdit), DEVRAIT (recommandé, écart justifié).

**Versions** : architecture v1.1 = ce que fait le système ; spécification v2.x = comment. En cas de contradiction, la spécification fait foi et l'architecture est corrigée. La v2.0 ajoute `settling` ; la v2.1 le cycle de vie des tranches et le contrôle de flux ; la v2.2 sépare exécution et règlement ; la v2.3 sépare sortie et contribution, et est vérifiée par le modèle exécutable ; la v2.4 ajoute la livraison prouvée, le rejeu et les autorisations datées ; la v2.5 ajoute la contestation close par accusé signé, le lien des preuves au flux, les attestations tardives engagées, les preuves complémentaires et le plafond glissant.

**Correspondance avec le code** : chaque identifiant cité ici apparaît dans le code de `gpu-domain` à l'endroit qui l'implémente.

### Vocabulaire

| Terme | Définition |
| --- | --- |
| Job | Une demande d'exécution d'un modèle par un emprunteur |
| `execution_status` | État d'exécution du job (section 2.1) |
| `settlement_status` | État financier du job (section 2.3), indépendant de l'exécution |
| `execution_intent` | `initial` ou `resume`. Passe à `resume` dès qu'une position est validée ou qu'un checkpoint existe ; ne revient jamais à `initial` |
| Tentative (`attempt`) | Une exécution du job sur une grappe donnée, numérotée à partir de 1 ; une seule tentative active à la fois |
| Autorisation (`lease`) | Droit signé et daté donné à un nœud pour un rôle sur une tentative. Expire sans heartbeat (JOB-R31) |
| Tranche de facturation (`slice`) | Unité de règlement, identifiant global `(job, attempt, slice_no)` |
| Sortie (`output_id`) | `(job, type, position)` : un résultat livré à l'emprunteur. Identité logique stable, indépendante de la tentative. Facturée au plus une fois à la fois (facturation nette ≤ 1), liée à la tentative qui l'a produite |
| Contribution (`contribution_id`) | `(output_id, génération de facturation, plage de couches, rôle)` : la part d'un prêteur dans une sortie. Chaque contribution est rémunérée au plus une fois ; plusieurs contributions d'une même sortie le sont |
| Génération de facturation | Numéro de la facturation d'une sortie : 0 à la première, incrémenté si une sortie provisoire annulée est régénérée (JOB-R29) |
| Témoin de livraison | Relais par lequel passe le flux chiffré vers le client, assigné à chaque tentative, indépendant des prêteurs et de l'emprunteur (JOB-R26) |
| Attestation de livraison | Déclaration signée du témoin : positions transmises **et acquittées au niveau transport** par le point d'accès authentifié du client, avec l'empreinte des trames. Ne prouve ni la réception applicative ni le traitement par le client |
| Engagement du témoin | Message court du témoin, horodaté et numéroté par le coordinateur, annonçant les positions attestées ; rend recevable une attestation complète arrivée pendant le drainage (JOB-R32) |
| Flux client | Session de l'emprunteur pour un job ; son identifiant est couvert par l'empreinte de chaque trame et de chaque déclaration (JOB-R34) |
| Empreinte de trame | Empreinte chaînée signée par le nœud de sortie : job, flux, modèle, type, position, génération de facturation (JOB-R34) |
| Contestation | Déclaration de non-réception d'une sortie provisoire pendant la fenêtre ; une seule par sortie ; close par accusé cumulatif signé couvrant la position, sinon remboursement à l'échéance (JOB-R33) |
| Preuve complémentaire | Preuve plus forte ajoutée à un élément réservé avant l'échéance d'évaluation (JOB-R35) |
| Position livrée | Position facturée, définitivement ou provisoirement. `validée ≤ livrée` (JOB-R27) |
| Facturation provisoire | Facturation sur attestation du témoin, en attente de la signature du client, d'un rejeu ou de l'expiration de la fenêtre de livraison |
| Tampon de rejeu | Trames chiffrées des sorties attestées, conservées par le témoin pour les renvoyer au client sans recalcul, au moins 24 h et jusqu'à la résolution des contestations (JOB-R28) |
| Fenêtre de livraison | Période de 24 h ouverte à la révocation de la tentative productrice, pendant laquelle le client peut contester une sortie provisoire (JOB-R29) |
| Retour arrière | Annulation des sorties provisoires à partir d'une position perdue, avec remboursement de leur prix à l'escrow (JOB-R29) |
| Travail de récupération (`recovery_work_id`) | `(job, attempt, segment)` : recalcul nécessaire pour reconstruire un état perdu, payé sur le budget de récupération |
| Travail gaspillé | Calcul jamais livré (ni acquitté, ni attesté) d'une tentative interrompue, ou sortie provisoire annulée. Jamais facturé, jamais payé |
| Position validée | Position couverte par une signature du client : accusé accepté pour la tentative courante, ou déclaration de reprise (JOB-R23, JOB-R28). Ne recule jamais |
| Budget de récupération | 10 % du coût estimé, accepté à la soumission, versé dans l'escrow à la réservation |
| Relais du pool | Crédits que la trésorerie du pool verse en escrow de récupération quand le budget de l'emprunteur est épuisé |
| Enveloppe de récupération | Part du budget de récupération attribuée à une tentative de reprise lors de son placement |
| Types de travail | `prefill` (tokens d'entrée), `generate` (tokens de sortie), `batch` (éléments livrés) |
| Reçu (`receipt`) | Accusé signé par le destinataire d'une unité. Prouve la transmission, pas la validité du calcul |
| Engagement de reçus | Empreinte d'un lot de reçus envoyée au coordinateur et horodatée par lui. L'historique complet est conservé |
| Drainage | Période après révocation où aucune nouvelle unité n'est acceptée, mais où les reçus du travail antérieur restent recevables |
| Budget de flux (`K_prefill`, `K_generate`, `K_batch`) | Nombre maximal d'unités produites et non validées (non signées par le client), par type |
| Réserve initiale | Part « travail » versée en escrow à la réservation, plafonnable ; le reste arrive par compléments |
| Escrow | Crédits bloqués pour le job : travail + budget de récupération (+ relais du pool) |
| Récompense retenue | Part payée d'une ligne, gardée en compte d'attente pendant la fenêtre de contestation |
| Outbox | Table des événements à émettre, écrite dans la même transaction que le changement d'état |

## 2. Machine à états des jobs

Un job a deux statuts indépendants : `execution_status` (10 états, dont 3 terminaux : `completed`, `failed`, `cancelled`) et `settlement_status` (section 2.3). Un job n'est clos que lorsque les deux sont finaux. Toute transition non listée ici est interdite et DOIT être rejetée.

Le chemin nominal va de `queued` à `completed`. Une panne passe par `recovering` puis repasse par `placing` (un échec de placement en reprise renvoie en `recovering`) ; le manque de crédits ou de secours passe par `paused`, d'où l'on revient en `reserved`. `settling` ne peut être ni annulé ni mis en échec.

### 2.1 Transitions du job

| ID | Transition | Déclencheur | Préconditions | Effets atomiques | Événements | Récupération |
| --- | --- | --- | --- | --- | --- | --- |
| JOB-T01 | ∅ → `queued` | `SubmitJob` | Compte actif ; pool autorisé ; modèle autorisé ; budget ≤ plafond du niveau de confiance ; budget de récupération accepté ; clé d'idempotence inconnue | Création du job (`attempt = 0`, `execution_intent = initial`, `settlement_status = none`) | `JobQueued` | Même clé et mêmes paramètres : on retourne le job existant ; mêmes clé, autres paramètres : refus |
| JOB-T02 | `queued` → `reserved` | Automatique, dès que les ressources le permettent | Mode crédits : solde ≥ réserve initiale + budget de récupération. Partage libre : quota disponible. Sinon, attente en `queued` | Écriture solde → escrow travail (réserve initiale = min(coût estimé, plafond)) et solde → escrow récupération, ou réservation de quota ; `settlement_status = active` | `CreditsReserved` | Clé `(job, reserve)` |
| JOB-T03 | `queued` → `cancelled` | Rejet définitif : attente dépassée, modèle retiré, budget impossible | Aucune | `settlement_status = closed` (JOB-S13), aucune écriture | `JobRejected(raison)` | Idempotent |
| JOB-T04 | `reserved` → `placing` | Le scheduler a trouvé une grappe éligible | Grappe éligible (ORCH) ; une plage de couches par prêteur ; tentatives < maximum ; **témoin indépendant** des prêteurs et de l'emprunteur (JOB-R26). Si `execution_intent = resume` : enveloppe de récupération ≤ budget non attribué (JOB-R18) | `attempt += 1` ; autorisations datées (JOB-R31) ; témoin assigné ; `placing_from = reserved` ; production de la tentative initialisée aux **positions livrées** *(v2.4)*. **`execution_intent` n'est pas modifié** | `AssignmentsIssued` | Réémission des `Assign` depuis l'outbox (idempotent par `lease_id`) |
| JOB-T05 | `placing` → `running` | Tous les nœuds ont accepté et chargé leur tranche | Autorisations non expirées (JOB-R31). État restauré **exactement** jusqu'aux positions **livrées** *(v2.4)* (au premier lancement : 0) ; échantillonneur restauré. Les positions livrées et non reçues par le client lui sont rejouées (JOB-R28), jamais recalculées | `running` ; ouverture d'une tranche ; la tentative est attestée comme démarrée (preuve du travail de récupération, JOB-R18) | `JobStarted` ou `JobResumed` | Un `AssignAck` tardif ou d'une autre tentative est refusé |
| JOB-T06 | `placing` → `placing_from` (`reserved` ou `recovering`) | Timeout de placement ou refus d'un nœud | Placements échoués < maximum | Révocation de la tentative ; son enveloppe de récupération est rendue | `PlacementFailed` | Au maximum : JOB-T16 |
| JOB-T07 | `running` → `running` | Clôture d'une tranche | Tranche `open` de la tentative courante | Tranche → `closed` (JOB-S03) ; nouvelle tranche ouverte | `SliceClosed` | Voir JOB-S04 |
| JOB-T08 | `running` → `recovering` | Nœud perdu, erreur moteur, **autorisation expirée** (JOB-R31) ou **retour arrière** sous la tentative (JOB-R29) *(v2.4)* | Tentative courante active | Révocation d'exécution ; tranches `open` → `draining` ; `execution_intent = resume` ; ouverture de la fenêtre de livraison des sorties provisoires de la tentative | `NodeLost`, `RecoveryStarted` | Toute unité de l'ancienne tentative refusée (JOB-R11) |
| JOB-T09 | `recovering` → `placing` | Remplaçants trouvés | Timeout de reprise non dépassé ; enveloppe ≤ budget non attribué (JOB-R18) | `attempt += 1` ; nouvelles autorisations ; `placing_from = recovering` | `AssignmentsIssued` | Comme JOB-T04 |
| JOB-T10 | `recovering` → `paused` | Aucun remplaçant à l'échéance, ou budget de récupération épuisé | Aucune | Checkpoint persistant si possible ; libération de la grappe | `JobPaused(no_capacity` ou `recovery_budget)` | Reprise par JOB-T12 |
| JOB-T11 | `running` → `paused` | Escrow insuffisant ; pause demandée ; préemption ; client silencieux | Aucune | Révocation d'exécution ; tranches `open` → `draining` ; checkpoint | `JobPaused(raison)` | Reprise par JOB-T12 |
| JOB-T12 | `paused` → `reserved` | Reprise | Mode crédits : escrow travail après complément ≥ prix de la sortie restante la moins chère. Partage libre : aucun crédit accepté. Pause non expirée | Écriture solde → escrow travail (complément). `execution_intent` conservé | `JobResumeRequested` | Clé `(job, topup, version)` |
| JOB-T13 | `running` → `settling` | Fin de génération | **Toutes les unités produites sont livrées** (acquittées ou attestées) *(v2.4)* | Révocation d'exécution ; tranches `open` → `draining` ; fenêtre de livraison ouverte pour les sorties provisoires | `JobFinished` | Unités non livrées : JOB-T11 (client silencieux) |
| JOB-T14 | `settling` → `completed` | Plus aucune tranche `open` ou `draining` | Aucune | `settlement_status = finalizing` | `JobCompleted` | Idempotent |
| JOB-T15 | Tout état actif **sauf `settling`** → `cancelled` | Annulation, ou attente maximale en `reserved` dépassée | Pas en `settling` (sinon refus `JOB_SETTLING`) | Révocation ; tranches → `draining` ; `settlement_status = finalizing` (ou `closed` si jamais réservé) | `JobCancelled` | Idempotent |
| JOB-T16 | Tout état actif **sauf `settling`** → `failed` | Maximum de tentatives ou de placements, modèle invalide, violation | Pas en `settling` | Comme JOB-T15 ; le travail prouvé reste payé | `JobFailed(raison)` | Idempotent |
| JOB-T17 | `paused` → `cancelled` | Pause expirée | Durée de pause ≥ maximum | Suppression du checkpoint ; `settlement_status = finalizing` | `JobExpired` | Idempotent |

Un état d'exécution terminal ne libère jamais l'escrow directement : c'est le statut de règlement (section 2.3) qui le fait, une fois toutes les tranches finales.

### 2.2 Cycle de vie des tranches

Le drainage est un état de la **tranche**, pas du job : une tranche de l'ancienne tentative peut être réglée pendant que la nouvelle tentative tourne.

`open` → `draining` → `closed` → `final`, avec `closed` → `disputed` → `final` quand une ligne est contestée. L'évaluation d'une tranche fermée est **une seule transition atomique** (JOB-S04).

| ID | Transition | Déclencheur | Effets |
| --- | --- | --- | --- |
| JOB-S01 | ∅ → `open` | JOB-T05 ou JOB-T07 | Réclamations et engagements acceptés |
| JOB-S02 | `open` → `draining` | Révocation d'exécution | Plus aucune nouvelle unité ; `receipt_deadline` = maintenant + fenêtre de drainage ; au plus « budget de flux » éléments non engagés par prêteur et par type (JOB-R12 b) |
| JOB-S03 | `open` ou `draining` → `closed` | Clôture normale, ou `receipt_deadline` atteinte (jamais avant) | **Réservation atomique** de toutes les lignes (JOB-R24) : chaque élément structurellement valide est réservé, les autres sont rejetés. Une contribution est valide si sa sortie est liée à la tentative de la tranche, si le prêteur est celui assigné à cette plage dans cette tentative et si la contribution n'est pas déjà prise. Un élément de récupération est valide s'il tient dans l'enveloppe de la tentative et si la tentative a démarré |
| JOB-S04 | `closed` → `final` ou `disputed` | Évaluation, dès la clôture et au plus tard à l'échéance | Pour chaque élément **encore** en `pending_evaluation` (CE-04) : contribution d'une sortie **provisoire** → en attente de livraison (JOB-R30) ; preuve engagée vérifiée → payé ; reçu non engagé sous le plafond glissant JOB-R19 → payé, au-delà → contesté ; preuve absente ou introuvable → **remboursé à l'échéance seulement**, l'élément restant en attente de preuve avant (JOB-R35). La tranche passe en `final` ou `disputed` quand plus aucun élément n'attend de preuve, et, avant l'échéance, quand plus aucune contribution n'attend sa sortie (CE-06). `final` si aucune ligne contestée |
| JOB-S05 | *(retirée en v2.2, fusionnée dans JOB-S04)* | — | — |
| JOB-S06 | `disputed` → `final` | Arbitrage de chaque ligne contestée, ou échéance ; ou résolution des livraisons en attente (JOB-R30) | Par ligne : payée ou remboursée. Règle par défaut à l'échéance : non prouvé = remboursé. Les éléments en attente de livraison ne sont **jamais arbitrés à part** : ils sont évalués par les règles de JOB-S04 quand leur sortie devient définitive, ou remboursés si elle est annulée |
| JOB-S07 | `closed` → (évaluation) | Échéance d'évaluation | La réconciliation exécute JOB-S04 |

### Montants d'une tranche

Les montants sont suivis **par ligne** `(tranche, prêteur)` et par élément : un litige concernant plusieurs prêteurs se règle ligne par ligne.

| Montant | Définition |
| --- | --- |
| `claimed` | Total réservé à la clôture pour la ligne |
| `pending_evaluation` | Part réservée, pas encore évaluée |
| `paid` | Part payée (vers les récompenses retenues) |
| `refunded` | Part rendue à l'escrow du job |
| `disputed` | Part contestée, bloquée jusqu'à l'arbitrage ou, pour une contribution en attente de livraison, jusqu'au sort de sa sortie |
| `held` | Récompense retenue, ni libérée ni contestée |
| `released` / `contested` | Récompense libérée au prêteur / rendue par contestation |

**Invariants de ligne** (JOB-R24) : `claimed = pending_evaluation + paid + refunded + disputed` à tout instant ; `paid = held + released + contested` ; une tranche `final` a `pending_evaluation = disputed = 0` ; le solde du compte de ligne = `pending_evaluation + disputed` ; le solde du compte de récompense retenue = `held`.

Chaque opération partielle a sa clé : `(tranche, prêteur, type d'opération, élément)` avec type ∈ {`claim`, `pay`, `refund`, `release`, `commission`, `contest`}. Chaque remboursement porte son motif : preuve absente, preuve introuvable, tentative non démarrée, arbitrage, sortie annulée.

Le travail de récupération suit le même cycle, sur des éléments `recovery_work_id` payés depuis l'escrow de récupération.

### 2.3 Statut de règlement du job

`none` → `active` → `finalizing` → `closed`.

| ID | Transition | Déclencheur | Effets |
| --- | --- | --- | --- |
| JOB-S10 | `none` → `active` | JOB-T02 | Escrow constitué |
| JOB-S11 | `active` → `finalizing` | `execution_status` devient terminal | La réconciliation devient responsable du job |
| JOB-S12 | `finalizing` → `closed` | Toutes les tranches `final` **et aucune sortie provisoire** *(v2.4)* | Escrow travail et sorties facturées non réparties → emprunteur. Escrow récupération : part du relais du pool non consommée → pool, reste → emprunteur (JOB-R18). Escrow = 0 |
| JOB-S13 | `none` → `closed` | JOB-T03, ou JOB-T15 avant réservation | Aucune écriture (aucun crédit ne peut avoir bougé, JOB-R18) |

Un job est **clos** quand `execution_status` est terminal et `settlement_status = closed`. Les récompenses retenues gardent ensuite leur fenêtre de contestation (JOB-R22), qui ne rouvre pas le job.

### 2.4 Livraison des sorties *(nouvelle en v2.4)*

Une sortie a sa propre vie, indépendante de la tentative qui l'a produite :

`non facturée` → `provisoire` (attestation du témoin) → `définitive` (signature du client couvrant la position, ou fenêtre expirée sans contestation) ; `provisoire` → `contestée` (déclarée non reçue, rejeu demandé) → `définitive` (accusé cumulatif signé couvrant la position) ou `annulée` (échéance sans accusé, ou tampon perdu) ; `annulée` → `non facturée`, puis éventuellement refacturée par une autre tentative, avec une nouvelle génération. Une sortie `définitive` ne redevient jamais provisoire ni annulée. *(v2.5 : un rejeu ne rend plus une sortie définitive.)*

| Événement | Avant | Après | Règle | Écritures |
| --- | --- | --- | --- | --- |
| Accusé du client jusqu'à `p` | non facturée | définitive | JOB-R23 | escrow travail → sorties facturées |
| Accusé du client jusqu'à `p` | provisoire | définitive | JOB-R23 | aucune |
| Attestation du témoin jusqu'à `p` | non facturée | provisoire | JOB-R26, R27 | escrow travail → sorties facturées |
| Attestation tardive pendant le drainage, couverte par un engagement antérieur à la révocation | non facturée | provisoire | JOB-R32 | escrow travail → sorties facturées |
| Déclaration signée du client (empreinte du flux) : position `< confirmée` | provisoire ou contestée | définitive | JOB-R28, R33 | aucune |
| Déclaration : position manquante, fenêtre ouverte, tampon disponible | provisoire | **contestée** (rejeu, échéance 1 h) | JOB-R33 | aucune |
| Déclaration : position manquante, déjà contestée ou définitive, tampon disponible | inchangé | inchangé (retransmission seulement) | JOB-R28, R33 | aucune |
| Déclaration : position manquante, tampon perdu | provisoire ou contestée | annulée, ainsi que toutes les suivantes du même type | JOB-R29 | contributions réservées → sorties facturées ; sorties facturées → escrow travail |
| Déclaration : position manquante, tampon perdu | définitive | refus de la déclaration | JOB-R29 | aucune |
| Signe de vie du client | toute | inchangé | JOB-R33 | aucune |
| Échéance d'une contestation sans accusé couvrant | contestée | annulée, ainsi que toutes les suivantes du même type | JOB-R33 | comme ci-dessus |
| Fenêtre de livraison expirée, position non contestée et précédant toute position contestée | provisoire | définitive | JOB-R29 | aucune |

**Invariants de livraison** : positions facturées = exactement `[0, livrées)` par type ; `validées ≤ livrées` ; préfixe définitif puis suffixe provisoire ; toute position validée est définitive ; `livrées − validées ≤ K` par type (TEST-P05, P19, P21).

**Preuves admissibles** (JOB-R26) :

| Niveau | Preuve | Effet |
| --- | --- | --- |
| P0 | Le prêteur déclare avoir produit | Aucun |
| P1 | Journal d'envoi signé par le prêteur, hash du token | Aucun : une preuve d'envoi n'est pas une preuve de réception. Sert seulement à demander une retransmission |
| P2 | Attestation du témoin assigné, avec l'empreinte des trames signée par le nœud de sortie (JOB-R34) : trames transmises et acquittées au niveau transport par le point d'accès authentifié du client | Facturation **provisoire**. Ne prouve pas la réception applicative : insuffisant pour clore une contestation |
| P3 | Signature du client liée au flux : accusé cumulatif, ou déclaration « je détiens `0..n` » avec l'empreinte du préfixe | Facturation **définitive** des positions couvertes, seule clôture possible d'une contestation |

## 3. Règles globales

- **JOB-R01 — Transaction unique** : une transition DOIT s'exécuter dans une seule transaction contenant le changement d'état, les écritures comptables et l'insertion des événements dans l'outbox. Soit tout est écrit, soit rien.
- **JOB-R02 — Outbox** : les messages sortants NE DOIVENT être envoyés qu'après le commit, depuis l'outbox. Les destinataires DOIVENT tolérer les doublons.
- **JOB-R03 — Verrou optimiste** : chaque job, tranche et ligne porte une `version` ; une transition DOIT être conditionnée à la version lue.
- **JOB-R04 — Idempotence** : chaque commande externe et chaque écriture comptable DOIT porter une clé d'idempotence. Une commande déjà appliquée ne modifie rien, pas même le numéro de séquence.
- **JOB-R05 — Tentative courante** : tout message d'un nœud, du témoin ou du client DOIT porter `(job, attempt, lease_id, seq)`. Une nouvelle unité, une attestation ou un accusé sous une autorisation révoquée, expirée ou d'une tentative non courante DOIT être refusé. Les reçus de travail antérieur relèvent de JOB-R12.
- **JOB-R06 — Facturation et rémunération** *(modifiée en v2.4)* : une **sortie** est facturée à l'emprunteur seulement sur preuve admissible de livraison : signature du client (définitive, JOB-R23) ou attestation du témoin (provisoire, JOB-R27). L'accusé du client n'est donc **pas** indispensable. Une **contribution** est rémunérée seulement si sa sortie est facturée **définitivement** (JOB-R30) et si des preuves admissibles la couvrent. Aucune preuve n'est considérée comme infaillible isolément, et aucun paiement NE DOIT reposer uniquement sur la déclaration d'un seul participant. Sans attestation ni accusé, la perte d'un prêteur est bornée par le budget de flux (JOB-R13).
- **JOB-R07 — Pas de solde négatif** : aucune transition NE DOIT rendre négatif un solde, un escrow, une ligne ou une récompense retenue.
- **JOB-R08 — Timeouts** : chaque état non final du job, de son règlement, d'une tranche, d'une ligne contestée, d'une sortie provisoire et d'une récompense retenue a une échéance **et une transition automatique**.
- **JOB-R09 — Horloge et ordre** *(modifiée en v2.3)* : seuls les horodatages du coordinateur font foi pour les délais. L'**ordre** des événements se juge sur le numéro de séquence du journal du coordinateur, jamais sur l'heure : deux événements peuvent partager la même seconde (CE-03).
- **JOB-R10 — Journal** : chaque transition est journalisée, sans données de l'emprunteur.
- **JOB-R11 — Révocation** : après `execution_revoked`, aucune nouvelle unité ni aucun accusé de la tentative NE DOIT être accepté.
- **JOB-R12 — Reçus en drainage** : un reçu prouve une transmission, pas un calcul. Un élément est admissible si (a) sa position est couverte par un engagement enregistré, dans l'ordre du journal, **avant la plus ancienne de la révocation de la tentative et de la clôture de la tranche** (CE-03), ou (b) il fait partie du dernier intervalle non engagé (au plus le budget de flux par type) et est cosigné. Un engagement enregistré après la révocation ou après la clôture ne prouve rien. L'indépendance des signataires n'est jamais présumée : les éléments (b) sont soumis à JOB-R19.
- **JOB-R13 — Contrôle de flux** *(modifiée en v2.4)* : pour chaque type de travail, le nombre d'unités produites et non **validées** (non signées par le client) NE DOIT jamais dépasser son budget, toutes tentatives confondues. Une attestation du témoin ne libère pas de place dans la fenêtre : c'est ce qui borne l'exposition des deux parties (JOB-R27). Les accusés sont asynchrones et ne bloquent qu'une fenêtre pleine.
- **JOB-R14 — Évaluation unique** *(précisée en v2.5)* : chaque élément d'une tranche est décidé une seule fois, et la tranche termine son évaluation une seule fois (clé `(job, attempt, slice_no)`), au plus tard à l'échéance d'évaluation (I-19).
- **JOB-R15 — Engagements de reçus** *(modifiée en v2.3)* : chaque destinataire envoie un engagement au plus toutes les « budget de flux » unités, sans bloquer le flux. Un engagement ne peut couvrir que des unités produites. Le coordinateur DOIT conserver l'historique complet des engagements, chacun avec son heure et son numéro de séquence, pas seulement le dernier.
- **JOB-R16 — Budgets de flux** : chaque budget couvre au moins les unités produites pendant un aller-retour d'accusé. Valeurs MVP : `K_generate = 4`, `K_prefill = 1` bloc, `K_batch = 1`.
- **JOB-R17 — Sortie unique** *(modifiée en v2.3)* : une sortie `(job, type, position)` NE DOIT être facturée à l'emprunteur qu'une fois, toutes tentatives confondues. Elle est liée à la tentative qui l'a validée ; les positions non validées d'une tentative interrompue sont du travail gaspillé.
- **JOB-R18 — Budget de récupération** *(modifiée en v2.3)* : le recalcul de reprise est payé au nœud qui le fait, sur un budget cumulé de 10 % du coût estimé, provisionné à la réservation. Chaque reprise reçoit une enveloppe à son placement ; une reprise NE DOIT pas être lancée si son enveloppe n'est pas financée. L'enveloppe non utilisée d'une tentative révoquée est rendue au budget une fois ses tranches finales. Le pool peut relayer le budget **seulement si `settlement_status = active`** (CE-01), en versant ses crédits avant la reprise. Ordre de consommation : **budget de l'emprunteur d'abord, puis relais du pool** ; à la clôture ou en cas de contestation, chaque payeur récupère sa propre part (CE-02). Le travail de récupération est attesté par l'acceptation de la tentative (JOB-T05).
- **JOB-R19 — Plafond anti-collusion** *(modifiée en v2.5)* : sur toute fenêtre glissante de 24 h, la somme des montants **bruts** admis sur reçus non engagés pour un compte NE DOIT PAS dépasser le plafond (valeur initiale : 50 crédits). Au-delà : litige. Un remboursement ou une contestation ne restaure pas le quota pendant la fenêtre. La vérification porte sur le journal des paiements, pas sur un compteur. Une fenêtre glissante n'a pas de frontière calendaire : une série à 23 h 59 puis une autre à 00 h 01 tombent dans la même fenêtre.
- **JOB-R20 — Réconciliation** *(modifiée en v2.4)* : un processus automatique, redémarrable et idempotent applique toutes les transitions arrivées à échéance (jobs, autorisations, tranches, lignes contestées, fenêtres de livraison, récompenses retenues, règlements). Un humain n'intervient que sur les litiges que les règles ne tranchent pas, avec la même échéance. Une erreur interne rencontrée pendant la réconciliation NE DOIT PAS être ignorée : elle est remontée et bloque toute nouvelle émission (LEDGER-007) (CE-04).
- **JOB-R21 — Contribution unique** *(nouvelle en v2.3)* : une contribution `(output_id, plage de couches, rôle)` NE DOIT être rémunérée qu'une fois. Elle est payable seulement si sa sortie est liée à la tentative de la tranche et si le prêteur est celui assigné à cette plage dans cette tentative. La part d'une contribution est proportionnelle au nombre de couches de sa plage, arrondie vers le bas : la somme des contributions d'une sortie ne dépasse jamais son prix, le reste revient à l'emprunteur.
- **JOB-R22 — Récompenses retenues** *(modifiée en v2.4)* : un paiement va d'abord en récompense retenue. Pendant une fenêtre unique de contestation (48 h après la finalisation de la tranche), une contestation rembourse **depuis la récompense retenue** chaque payeur de sa part. À la fin de la fenêtre, la réconciliation **libère** la récompense (I-15) ; la libération est définitive, aucune reprise sur le solde d'un prêteur. Aucune contestation ne crée de crédits. Une récompense nulle (partage libre) est complète dès son paiement (CE-05).
- **JOB-R23 — Validation** *(modifiée en v2.4)* : une position est validée quand le coordinateur accepte une signature du client la couvrant : accusé cumulatif pour la tentative courante, ou déclaration de reprise (JOB-R28). La validation rend la sortie définitive ; si elle n'était pas encore facturée, elle la facture (escrow travail → sorties facturées) dans la même transaction et la lie à la tentative courante. Les positions validées ne reculent jamais. Une reprise repart des positions **livrées** (JOB-R27), pas des positions validées.
- **JOB-R24 — Réservation atomique** *(nouvelle en v2.3)* : à la clôture, toutes les lignes de la tranche sont réservées dans la même transaction, depuis les sorties facturées (contributions) ou l'escrow de récupération (récupération). Une contribution réservée ne peut plus être réservée par une autre tranche.
- **JOB-R25 — Couverture de la fenêtre** *(modifiée en v2.4)* : une unité ne peut être produite que si l'escrow travail couvre le prix de toutes les unités produites et pas encore facturées (au-delà des positions livrées). Une validation ou une attestation ne peut donc jamais manquer de fonds.
- **JOB-R26 — Témoin de livraison** *(nouvelle en v2.4)* : chaque tentative a un témoin assigné à son placement, par lequel passe le flux chiffré de bout en bout vers le client. Il NE DOIT être ni l'un des prêteurs de la tentative, ni l'emprunteur. Seule son attestation est une preuve de livraison recevable ; une attestation signée par un autre (en particulier par le nœud de sortie) est refusée avec `INADMISSIBLE_PROOF`. Une attestation n'est acceptée que pendant que la tentative est vivante et sous autorisation valide, et seulement pour des unités produites. Un témoin qui a perdu son tampon n'atteste plus. *(v2.5)* Chaque témoin a une **réputation distincte** de celle des prêteurs, nourrie par ses attestations suivies de remboursements et par des contrôles aléatoires. Sélection par phase : MVP privé, témoin du pool ou de son coordinateur ; fédération, opérateurs reconnus par les deux pools ; public, réputation, limites d'exposition par témoin et contrôles aléatoires, caution éventuelle plus tard.
- **JOB-R27 — Facturation provisoire** *(nouvelle en v2.4)* : une attestation facture provisoirement les positions qu'elle couvre (escrow travail → sorties facturées) et les lie à la tentative productrice ; elles deviennent des positions **livrées**. Une sortie provisoire devient définitive par signature du client, par rejeu (JOB-R28) ou à l'expiration de la fenêtre de livraison (JOB-R29). Comme le budget de flux se mesure depuis la signature du client (JOB-R13), au plus `K` positions par type sont livrées sans signature à tout instant, pour tout le job : c'est la borne de ce qu'un témoin complice peut facturer à tort, et de ce qu'un client de mauvaise foi peut retenir (I-12). Conséquence : une reprise après une fin de flux provisoire ne produit que `K − (livrées − validées)` unités avant le premier accusé (I-16).
- **JOB-R28 — Rejeu** *(modifiée en v2.5)* : le témoin conserve les trames chiffrées de chaque sortie attestée **au moins 24 h après la révocation de la tentative productrice, et tant qu'une sortie de cette tentative est provisoire ou contestée** ; il NE DOIT PAS purger avant. À la reprise ou après la fin, le client signe une déclaration « je détiens exactement `0..confirmée` », liée au flux par l'empreinte du préfixe (JOB-R34), avec `validées ≤ confirmée ≤ livrées` (sinon refus). Les positions `< confirmée` deviennent validées et définitives ; les positions manquantes lui sont **rejouées** depuis le tampon, sans recalcul ni refacturation, **sans devenir définitives** (JOB-R33). Une sortie de la tentative vivante ne peut pas être déclarée manquante : elle est retransmise (I-11). Le financement du stockage du tampon est à décider (I-20).
- **JOB-R29 — Fenêtre de livraison et retour arrière** *(modifiée en v2.5)* : la fenêtre de livraison (**24 h**) s'ouvre à la révocation de la tentative productrice. Si une sortie provisoire est déclarée manquante alors que le tampon est perdu, elle est **annulée avec toutes les sorties suivantes du même type** (elles dépendent d'elle) : contributions réservées rendues, prix rendu à l'escrow, positions livrées ramenées à la position perdue (jamais sous les validées). Une tentative vivante construite sur ces sorties est révoquée (JOB-T08, ou JOB-T06 en placement) (I-13). Sans contestation pendant la fenêtre, les sorties provisoires deviennent définitives, **dans l'ordre des positions, jusqu'à la première position contestée** : les suivantes en dépendent et attendent sa résolution (I-17). Après la fenêtre, une sortie définitive dont le tampon est perdu ne peut plus être déclarée manquante : la perte du client est bornée par `K`.
- **JOB-R30 — Contributions de sorties provisoires** *(nouvelle en v2.4)* : une contribution N'EST JAMAIS payée tant que sa sortie est provisoire. À l'évaluation, elle est mise en attente (contestée, jamais arbitrée à part). Quand la sortie devient définitive, la contribution est évaluée selon les règles ordinaires de JOB-S04 ; quand elle est annulée, la contribution est remboursée. Une sortie régénérée est une nouvelle génération de facturation, dont les contributions sont distinctes (I-14).
- **JOB-R32 — Attestations tardives** *(nouvelle en v2.5)* : après la révocation d'une tentative, aucune nouvelle livraison n'est acceptée. Une attestation complète arrivée **pendant le drainage** est recevable seulement si un engagement court du témoin, couvrant ces positions, a été enregistré par le coordinateur **avant la révocation, dans l'ordre du journal** (JOB-R09), et si aucune tentative plus récente n'a été placée. Un engagement n'est accepté que de la tentative vivante : un engagement créé après coup ne peut pas se faire passer pour ancien.
- **JOB-R33 — Contestation** *(nouvelle en v2.5)* : une sortie provisoire déclarée manquante pendant la fenêtre est **contestée**, une seule fois ; le témoin la rejoue ; une échéance est fixée (1 h). Elle ne devient définitive que par un **accusé applicatif cumulatif signé, lié au même flux, couvrant sa position** (un accusé d'une position ultérieure dans le même flux ordonné couvre toutes les précédentes). Un rejeu, un rejeu attesté au niveau transport, un signe de vie ou toute autre activité signée du client ne suffisent pas. À l'échéance sans tel accusé, ou si le témoin ne peut présenter le tampon ou les preuves exigées : remboursement, par retour arrière (JOB-R29).
- **JOB-R34 — Lien des preuves au flux** *(nouvelle en v2.5)* : le nœud de sortie signe l'empreinte chaînée de chaque trame, couvrant job, identifiant du flux client, modèle, type, position et génération de facturation. Une attestation dont l'empreinte diffère de celle des trames signées (trame substituée, ou trame valide d'une autre session) est refusée avec `INADMISSIBLE_PROOF` ; de même pour une déclaration du client dont l'empreinte de préfixe n'est pas celle de ce flux. La signature et l'empreinte prouvent l'intégrité et l'origine d'une trame, pas sa réception : c'est pourquoi JOB-R33 exige l'accusé du client.
- **JOB-R35 — Preuves complémentaires** *(nouvelle en v2.5)* : jusqu'à l'échéance d'évaluation d'une tranche, un prêteur peut remplacer la preuve d'un élément non encore décidé par une preuve plus forte (absente < reçu non engagé < engagement). Un remboursement faute de preuve ne devient effectif qu'à l'échéance. À l'échéance, règlement définitif selon les preuves disponibles et les règles d'arbitrage. Après la clôture, le registre n'est jamais modifié : toute correction exceptionnelle est une nouvelle opération comptable explicitement financée.
- **JOB-R31 — Autorisations datées** *(nouvelle en v2.4)* : chaque autorisation a une échéance (45 s), renouvelée par heartbeat tant qu'elle n'a pas expiré. Une autorisation expirée ne se renouvelle pas. Le coordinateur refuse immédiatement, selon sa propre horloge (JOB-R09), toute unité, attestation, acceptation ou accusé reçu sous une autorisation expirée, avant même la révocation ; la réconciliation révoque ensuite la tentative (JOB-T08, ou JOB-T06 en placement). Un nœud DOIT cesser de produire avant l'échéance selon son horloge locale, avec une marge couvrant la dérive.

### Délais et limites (valeurs initiales à calibrer)

| État | Délai initial | À expiration |
| --- | --- | --- |
| `queued` (attente de ressources) | 15 min | JOB-T03 |
| `reserved` (attente de placement) | 15 min | JOB-T15 (raison : délai) |
| `placing` | 60 s | JOB-T06 |
| `running`, client silencieux | 60 s sans accusé, avec une fenêtre non validée | JOB-T11 |
| Autorisation sans heartbeat | 45 s | Refus immédiat, puis JOB-T08 ou JOB-T06 par la réconciliation |
| Sortie provisoire non contestée | 24 h après la révocation de la tentative productrice | Définitive, jusqu'à la première position contestée (JOB-R29) |
| Sortie contestée | 1 h après la contestation | Annulée sans accusé couvrant (JOB-R33) |
| Élément sans preuve | Échéance d'évaluation (10 min après la clôture) | Remboursé (JOB-R35) |
| `recovering` | 2 min | JOB-T10 |
| `paused` | 30 jours | JOB-T17 |
| `settling` | Fenêtre de drainage | Clôture des tranches (JOB-S03), puis JOB-T14 |
| Tranche `draining` | 2 min | JOB-S03 |
| Tranche `closed` non évaluée | 10 min | JOB-S07 |
| Ligne `disputed` | 48 h | JOB-S06, règle par défaut |
| Règlement `finalizing` | Dès que toutes les tranches sont `final` | JOB-S12 |
| Récompense retenue | 48 h après finalisation de la tranche | Libération automatique (JOB-R22) |

| Limite | Valeur initiale |
| --- | --- |
| Placements échoués avant `failed` | 5 |
| Tentatives maximales par job | 8 |
| `K_generate` / `K_prefill` / `K_batch` | 4 / 1 / 1 |
| Budget de récupération | 10 % cumulé du coût estimé |
| Plafond sur reçus non engagés | 50 crédits par compte sur toute fenêtre glissante de 24 h, montants bruts |
| Commission | 10 %, prélevée à la libération |
| Réserve initiale | Coût estimé complet (plafond configurable par pool) |
| Conservation du tampon de rejeu | Au moins 24 h après la révocation, et jusqu'à la résolution de toute contestation ouverte |
| Contestations par sortie | 1 (close par accusé cumulatif signé, ou remboursement à l'échéance) |
| Engagement court du témoin | À chaque attestation, ou au plus toutes les `K` unités |

## 4. Scénarios d'échec

Chaque scénario a un test déterministe (dossier `tests/scenarios/`), qui vérifie aussi tous les invariants à chaque pas et la vivacité en fin de test.

| ID | Scénario | Comportement exigé | Test |
| --- | --- | --- | --- |
| JOB-F01 | Le coordinateur s'arrête au milieu d'une transition à plusieurs écritures | Rien n'est écrit (JOB-R01). L'outbox renvoie les événements non livrés | `f01_partial_transition_leaves_no_trace` |
| JOB-F02 | Redémarrage après JOB-T04 ou JOB-T09, avant l'envoi des `Assign` | `Assign` renvoyés ; doublons sans effet ; timeout de placement : JOB-T06 | `f02_redelivered_assignments_are_harmless` |
| JOB-F03 | Une unité produite après révocation ou expiration | Refusée, jamais payée. Les reçus du travail antérieur restent recevables en drainage | `f03_work_after_revocation_rejected_prior_receipts_paid` |
| JOB-F04 | Règlement fait, accusé perdu | Rapport renvoyé : contribution déjà prise, aucun second paiement | `f04_duplicate_report_after_settlement_pays_once` |
| JOB-F05 | Le nœud tombé revient après son remplacement | Ses unités et accusés sont refusés ; ses reçus antérieurs sont réglés par drainage | `f05_returning_node_is_ignored_but_keeps_prior_pay` |
| JOB-F06 | Un accusé arrive deux fois | Sans effet, sortie facturée une fois | `f06_duplicate_ack_charges_once` |
| JOB-F07 | Le client se déconnecte | Production arrêtée par le budget de flux ; après 60 s, JOB-T11. Sans attestation, la fenêtre non validée n'est pas facturée ; la reprise repart de la dernière position livrée | `f07_client_disconnect_stops_after_k_then_pauses` |
| JOB-F08 | Le coordinateur perd le contact avec la grappe | Les autorisations expirent, les nœuds s'arrêtent ; rien de postérieur n'est facturé ni payé | `f08_lost_contact_revocation_stops_payment`, et JOB-F29 pour l'expiration réelle |
| JOB-F09 | Annulation et fin de génération simultanées | Verrou optimiste : la première gagne ; en `settling`, annulation et échec refusés | `f09_cancel_and_finish_race` |
| JOB-F10 | L'escrow ne couvre plus la fenêtre | Production refusée (JOB-R25), pause, reprise avec complément | `f10_low_escrow_blocks_window_then_pause_and_topup` |
| JOB-F11 | Deux rapports identiques | Le second élément est rejeté à la clôture | `f11_identical_reports_counted_once` |
| JOB-F12 | Message mal formé ou trop gros | Rejet avant décodage, code stable | `f12_oversized_frame_rejected_before_decoding` |
| JOB-F13 | Le scheduler redémarre pendant un placement | Rejouer ses décisions est sans effet | `f13_scheduler_restart_replays_nothing` |
| JOB-F14 | Préemption d'un job différé | JOB-T11 ; tranche drainée et réglée ; reprise | `f14_preemption_settles_slice_then_resumes` |
| JOB-F15 *(précisé en v2.4)* | Le client refuse d'acquitter **et le témoin n'a rien attesté** | La fenêtre non livrée n'est jamais facturée ni payée ; la production s'arrête à `K` unités ; JOB-T11 après 60 s ; refus répétés : réputation de l'emprunteur réduite. Perte d'un prêteur ≤ `K` unités. Avec attestation : JOB-F24 | `f15_withheld_acks_bound_loss_to_k` |
| JOB-F16 | Un GPU tombe, un autre avait du travail valide | Drainage ; le survivant est payé, ligne par ligne | `f16_survivor_paid_after_other_gpu_fails` |
| JOB-F17 | Reçus fabriqués après coup | Engagement postérieur à la révocation ou à la clôture de la tranche : rien n'est prouvé, remboursé ; reçus non engagés limités à `K` par type puis plafond JOB-R19, au-delà litige | `f17_receipts_fabricated_after_revocation` |
| JOB-F18 | Nouvelle tentative pendant le drainage de l'ancienne | Chaque tranche suit son cycle ; chaque sortie appartient à une seule tentative. Fonctionne aussi en partage libre | `f18_new_attempt_runs_while_old_slice_drains`, `f18b_free_pool_resume_uses_quota_not_credits` |
| JOB-F19 | Pause, puis reprise via `reserved` → `placing` | `execution_intent` reste `resume` ; JOB-T05 refuse un état non restauré | `f19_resume_after_pause_keeps_intent` |
| JOB-F20 | Tentative 1 : positions 0-1 validées, 2-4 produites, panne. Tentative 2 | Positions 0-1 : tentative 1. Positions 2-4 de la tentative 1 : gaspillées. Reconstruction : récupération. Positions 2-4 : tentative 2 | `f20_unvalidated_positions_are_wasted_not_billed` |
| JOB-F21 | Litige sur une tranche à plusieurs prêteurs | Seule la ligne concernée est contestée ; les autres sont payées à l'évaluation | `f21_dispute_isolated_to_one_lender_line` |
| JOB-F22 | Annulation pendant un drainage | `cancelled` + `finalizing` ; la réconciliation finit les tranches puis solde l'escrow | `f22_cancel_while_draining_settles_everything` |
| JOB-F23 | Budget de récupération épuisé | Reprise refusée tant que non financée ; relais du pool possible ; sinon pause | `f23_recovery_budget_exhausted_then_pool_relay` |
| JOB-F24 *(v2.4)* | Le client reçoit des tokens attestés par le témoin et n'acquitte jamais | Facturation provisoire ; JOB-T11 ; à la fin de la fenêtre (24 h), définitive ; contributions payées aux prêteurs. Contestation tardive : retransmission gratuite, aucun remboursement | `f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders` |
| JOB-F25 *(v2.4)* | Le prêteur ment sur la livraison | Attestation signée par le nœud de sortie refusée (`INADMISSIBLE_PROOF`) ; un prêteur ne peut pas être assigné comme témoin ; rien n'est facturé | `f25_lender_cannot_attest_its_own_delivery` |
| JOB-F26 *(v2.4)* | Accusé perdu, panne, reprise | Le client déclare ce qu'il a reçu ; le reste est contesté et rejoué ; la reprise démarre aux positions livrées ; l'accusé cumulatif suivant couvre le rejeu ; chaque position facturée une fois | `f26_lost_ack_then_resume_replays_without_double_billing` |
| JOB-F27 *(v2.4)* | Tampon du témoin perdu, le client déclare des tokens non reçus | Retour arrière : sorties manquantes et suivantes annulées, prix rendu, contributions en attente remboursées ; régénération par la tentative suivante, nouvelle génération | `f27_lost_replay_buffer_contest_refunds_and_rewinds` |
| JOB-F28 *(v2.4)* | Déconnexion simultanée : client silencieux et autorisation expirée à la même échéance ; puis perte du nœud et du témoin dans la même seconde | Une seule transition gagne, une seule révocation ; les sorties attestées restent dues mais ne sont plus rejouables | `f28_simultaneous_client_silence_and_lease_expiry` |
| JOB-F29 *(v2.4)* | Grappe muette au-delà de l'échéance de l'autorisation | Production et heartbeat refusés (`LEASE_EXPIRED`) avant toute révocation ; la réconciliation révoque | `f29_expired_lease_rejects_work_until_reconciliation_revokes` |
| JOB-F30 *(v2.4)* | Le client ment à la reprise | Déclarer plus que livré ou moins que validé : refus ; contester une sortie de la tentative vivante : refus (retransmission) | `f30_client_cannot_overstate_or_unconfirm_or_contest_live_output` |
| JOB-F31 *(v2.4)* | Contestation après la fenêtre de livraison (24 h) | Retransmission si le tampon existe, sans contestation ni écriture comptable ; tampon perdu : refus, la sortie reste due | `f31_contest_after_window_replays_but_never_refunds` |
| JOB-F32 *(v2.4)* | Retour arrière alors qu'une reprise tourne déjà | La reprise, construite sur des sorties annulées, est révoquée et repart de la position perdue ; budget de flux réduit tant que le client n'a pas signé | `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| JOB-F33 *(v2.5)* | Signe de vie signé du client sans réception du rejeu | Aucune résolution ; à l'échéance, sorties contestées et suivantes remboursées | `f33_signed_heartbeat_without_replay_receipt_is_refunded` |
| JOB-F34 *(v2.5)* | Accusé cumulatif signé couvrant le rejeu | Facturation définitive ; rien remboursé à l'échéance | `f34_cumulative_ack_covering_the_replay_bills_definitively` |
| JOB-F35 *(v2.5)* | Attestation ou déclaration d'une autre session | Refus `INADMISSIBLE_PROOF`, état inchangé | `f35_declaration_or_attestation_from_another_session_is_rejected` |
| JOB-F36 *(v2.5)* | Témoin présentant une trame différente de l'empreinte signée | Refus `INADMISSIBLE_PROOF`, rien facturé | `f36_frame_different_from_the_signed_digest_is_rejected` |
| JOB-F37 *(v2.5)* | Engagement avant révocation, attestation complète pendant le drainage | Recevable : facturation provisoire | `f37_commitment_before_revocation_makes_late_attestation_admissible` |
| JOB-F38 *(v2.5)* | Engagement créé après révocation, ou attestation après le drainage | Refus | `f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing` |
| JOB-F39 *(v2.5)* | Contestation à 23 h 59 | Tampon conservé après 24 h ; positions suivantes en attente ; purge possible seulement après résolution | `f39_contest_just_before_window_end_keeps_the_buffer` |
| JOB-F40 *(v2.5)* | Plafond aux frontières calendaires et après remboursement | 23 h 55 puis 00 h 01 : même fenêtre, litige ; une contestation ne restaure pas le quota ; 24 h plus tard, quota disponible | `f40_sliding_cap_holds_across_midnight_and_after_refunds` |
| JOB-F41 *(v2.5)* | Preuve complémentaire | Ajoutée avant l'échéance : payée ; sans complément : remboursée à l'échéance ; après l'échéance : refusée | `f41_supplementary_proof_before_deadline_is_paid_after_is_refused` |

## 5. Protocole

Statut : **à compléter**. Les messages découlent des transitions de la section 2. La crate `gpu-protocol` fige déjà l'enveloppe, le contrôle de taille, les codes d'erreur et l'anti-rejeu.

### Messages par transition

| Message | Sens | Transition | Champs minimaux |
| --- | --- | --- | --- |
| `SubmitJob` | Client → coordinateur | JOB-T01 | clé d'idempotence, pool, modèle, classe, budget max |
| `CancelJob` / `ResumeJob` | Client → coordinateur | JOB-T15, JOB-T12 | job, clé d'idempotence, complément |
| `Assign` | Coordinateur → nœud, témoin | JOB-T04, JOB-T09 | job, attempt, lease\_id, rôle, plage de couches, voisins, témoin, budgets de flux, expiration, `execution_intent`, signature |
| `AssignAck` / `AssignReject` | Nœud → coordinateur | JOB-T05, JOB-T06 | lease\_id, positions restaurées par type, raison |
| `Heartbeat` | Nœud → coordinateur | JOB-R31, JOB-T08 | node\_id, job, attempt, leases actives, état GPU, seq |
| `LeaseRenew` / `Revoke` / `Release` | Coordinateur → nœud | JOB-R05, JOB-R11, JOB-F05 | lease\_id, expiration ou raison, `receipt_deadline` |
| `ActivationFrame` | Pair → pair | Exécution | job, attempt, lease\_id, slice, seq, tenseur (format binaire fixe) |
| `Produced` | Nœud de sortie → coordinateur | JOB-R13, JOB-R25 | job, attempt, type, jusqu'à |
| `TokenAck` | Client → coordinateur | JOB-R23 | job, attempt, type, positions validées jusqu'à, signature du client |
| `DeliveryAttestation` | Témoin → coordinateur | JOB-R26, R27, R32 | job, attempt, type, livré jusqu'à, empreinte chaînée des trames signées par le nœud de sortie (job, flux, modèle, type, position, génération), offset acquitté au niveau transport, signature du témoin |
| `WitnessCommitment` | Témoin → coordinateur | JOB-R32 | job, attempt, type, attesté jusqu'à ; horodaté et numéroté par le coordinateur |
| `DeliveryConfirm` | Client → coordinateur | JOB-R28, R33, R34 | job, type, position confirmée (« je détiens exactement `0..confirmée` »), empreinte du préfixe détenu, signature du client |
| `ClientHeartbeat` | Client → coordinateur | JOB-R33 | job, signature du client ; ne couvre aucune position |
| `EvidenceSupplement` | Prêteur → coordinateur | JOB-R35 | slice, sortie, nouvelle preuve |
| `Replay` | Témoin → client | JOB-R28 | job, type, positions, trames chiffrées d'origine (identiques octet pour octet) |
| `Receipt` | Destinataire → producteur | JOB-R12 | slice, attempt, seq, hash du contenu, signature |
| `ReceiptCommit` | Destinataire → coordinateur | JOB-R15 | attempt, producteur, type, couvert jusqu'à, empreinte ; horodaté par le coordinateur |
| `UsageReport` / `UsageAck` | Nœud ↔ coordinateur | JOB-S03, JOB-F04 | slice, éléments (`contribution_id` ou `recovery_work_id`) avec preuve, signature |
| `DisputeOpened` / `DisputeResolved` | Coordinateur → parties | JOB-S04, JOB-S06 | slice, ligne, montant contesté, décision |
| `Checkpoint` | Contrôleur de grappe → stockage | JOB-T10, JOB-T11 | job, attempt, positions, état de l'échantillonneur, caches si exportables |

### Exigences fixées

- **PROTO-001** : tout message DOIT porter une version de protocole, un identifiant d'émetteur, un numéro de séquence et une signature. *(implémenté : `Envelope`, `ReplayGuard`)*
- **PROTO-002** : la taille d'une trame DOIT être vérifiée avant tout décodage. *(implémenté : `check_frame`)*
- **PROTO-003** : aucun format de sérialisation dynamique NE DOIT être utilisé.
- **PROTO-004** : chaque refus DOIT avoir un code stable : `UNKNOWN_JOB`, `INVALID_TRANSITION`, `VERSION_CONFLICT`, `STALE_ATTEMPT`, `JOB_SETTLING`, `FLOW_BUDGET_EXCEEDED`, `WINDOW_NOT_COVERED`, `RECOVERY_BUDGET`, `INADMISSIBLE_PROOF` *(v2.4)*, `LEASE_EXPIRED` *(v2.4)*, `PRECONDITION_FAILED`, `LEDGER_REJECTED`, `FRAME_TOO_LARGE`, `REPLAY`, `MISSING_SIGNATURE`, `UNSUPPORTED_VERSION`. *(implémenté : `domain_code`, `ProtoError::code`)*
- **PROTO-005** : un numéro de séquence DOIT être strictement croissant par émetteur ; un message rejoué est refusé avant d'atteindre le domaine.
- **PROTO-006** *(nouvelle en v2.4)* : l'attestant d'une `DeliveryAttestation` est le signataire de l'enveloppe, jamais un champ du message. *(implémenté : `to_command`, test `delivery_attested_by_a_lender_is_inadmissible`)*
- **PROTO-007** *(v2.4)* : le flux vers le client est chiffré de bout en bout ; le témoin voit des trames chiffrées, pas les tokens. Un rejeu renvoie les trames d'origine : le client vérifie leur empreinte contre l'attestation. *(non modélisé : cryptographie symbolique)*
- **PROTO-008** *(nouvelle en v2.5)* : l'empreinte de trame couvre job, identifiant du flux client, modèle, type, position et génération de facturation ; elle est signée par le nœud de sortie. Une trame ou une déclaration valide ne peut pas être réutilisée dans un autre flux. *(modélisé par une empreinte FNV-1a, vérifiée par le domaine et recalculée indépendamment par le vérificateur)*

**À décider** : Protobuf ou format binaire maison ; limites de taille définitives ; encodage des tenseurs.

## 6. Interface moteur

Statut : **à compléter**, inchangé depuis la v2.2. Le contrat est défini comme un trait Rust ; Petals l'implémente via un adaptateur IPC.

```rust
trait Engine {
    fn describe(&self) -> EngineInfo;            // version, architectures, capacités
    fn load_slice(&mut self, s: SliceSpec) -> Result<SliceHandle, EngineError>;
    fn execute(&mut self, h: SliceHandle, input: Activations, pos: Position) -> Result<Activations, EngineError>;
    fn cancel(&mut self, h: SliceHandle) -> Result<(), EngineError>;
    fn metrics(&self) -> EngineMetrics;
    fn unload(&mut self, h: SliceHandle) -> Result<(), EngineError>;
    // Optionnelles, déclarées dans EngineInfo.capabilities
    fn snapshot_session(&self, h: SliceHandle) -> Result<SessionState, EngineError>;
    fn restore_session(&mut self, s: SessionState) -> Result<SliceHandle, EngineError>;
    fn set_sampler_state(&mut self, st: SamplerState) -> Result<(), EngineError>;
}
```

- **ENGINE-001** : capacités déclarées dans `describe` ; une méthode optionnelle non déclarée renvoie `Unsupported`, jamais une simulation.
- **ENGINE-002** : `load_slice` vérifie le hash de la tranche contre le manifeste signé.
- **ENGINE-003** : un `SessionState` n'est restauré que sur moteur, version, quantification et hash identiques.
- **ENGINE-004** : le moteur n'a aucun accès réseau.
- **ENGINE-005** : sans export de session, reprise par recalcul ; sans contrôle de l'échantillonneur, échantillonnage côté client ou contrôleur de grappe.
- **ENGINE-006** *(nouvelle)* : `AssignAck` DOIT déclarer les positions restaurées par type ; JOB-T05 les compare exactement aux positions validées.

## 7. Comptabilité

Statut : **implémenté dans le modèle** (`gpu-ledger`) ; la persistance PostgreSQL reste à écrire.

### Comptes

| Compte | Rôle |
| --- | --- |
| `Issuance` | Seul compte qui crée des crédits ; seul compte autorisé à être négatif |
| `Burn` | Crédits détruits |
| `User(compte)` | Solde disponible |
| `PoolReserve(pool)` | Trésorerie du pool (amorçage, relais de récupération) |
| `EscrowWork(job)` | Escrow « travail » |
| `EscrowRecovery(job)` | Escrow « récupération » (budget de l'emprunteur + relais du pool) |
| `OutputHold(job)` | Prix des sorties facturées (définitives et provisoires), en attente de répartition entre contributions |
| `SliceLine(job, attempt, slice, prêteur)` | Réserve d'une ligne (`pending_evaluation + disputed`) |
| `PendingReward(job, attempt, slice, prêteur)` | Récompense retenue (`held`) |
| `Commission` | Commissions |

### Exigences

- **LEDGER-001** : chaque écriture a un compte source, un compte destination, un montant, une clé d'idempotence unique et un motif.
- **LEDGER-002** : insertion seule ; une correction est une écriture inverse.
- **LEDGER-003** : seul `Issuance` crée des crédits.
- **LEDGER-004** : la somme de tous les comptes vaut zéro (`Issuance` négatif = total émis).
- **LEDGER-005** : aucun compte autre qu'`Issuance` n'est négatif ; refus de l'écriture sinon (en base : contrainte, pas seulement code).
- **LEDGER-006** : chaque écriture est chaînée par empreinte à la précédente (le modèle utilise FNV-1a ; la production DOIT utiliser SHA-256 ou BLAKE3).
- **LEDGER-007** : un contrôle d'invariants tourne en continu et bloque toute nouvelle émission en cas d'écart.
- **LEDGER-008** *(nouvelle)* : la commission est prélevée à la libération d'une récompense, jamais avant.
- **LEDGER-009** : les montants sont des entiers en plus petite unité ; jamais de flottants.
- **LEDGER-010** *(nouvelle en v2.4)* : l'annulation d'une sortie provisoire est une écriture inverse (sorties facturées → escrow travail), jamais une suppression. Les clés de facturation et d'annulation incluent la génération : `charge/{job}/{type}/{position}/{génération}`, `void/…/{génération}`.

## 8. Orchestration

Statut : **à compléter**, inchangé depuis la v2.2 (ORCH-001 à ORCH-006). Le modèle ne contient pas de scheduler : les placements y sont des commandes.

## 9. Tests de conformité

### 9.1 Propriétés (générées par `proptest`)

Vérifiées après **chaque** commande sur des séquences aléatoires de commandes, pannes, doublons, versions concurrentes, messages périmés, reçus fabriqués, sauts d'horloge et comportements adverses de livraison, puis en fin de séquence après une phase de vidage. Quatre générateurs : aléatoire général, orienté pannes, réserve partielle, et `delivery` (I-03).

| ID | Propriété | Exigences |
| --- | --- | --- |
| TEST-P01 | Aucune transition hors table, ni pour les jobs ni pour les tranches | Section 2 |
| TEST-P02 | Registre : somme nulle, pas de négatif, soldes recalculables, chaîne intacte, insertion seule | LEDGER-001 à 006 |
| TEST-P03 | Facturation nette d'une sortie ∈ {0, 1} à tout instant ; une contribution réservée et payée une fois | JOB-R14, R17, R21 |
| TEST-P04 | Aucune unité ni aucun accusé accepté hors de la tentative vivante ; aucune contribution payée sur une autre tentative que celle de sa sortie | JOB-R05, R11, R21 |
| TEST-P05 | Positions facturées = exactement `[0, livrées)` ; `validées ≤ livrées` ; les positions validées ne reculent jamais | JOB-R23, R27 |
| TEST-P06 | Après arrêt de l'activité, tout job finit terminal et réglé, toute tranche finale, sans intervention humaine | JOB-R08, R20 |
| TEST-P07 | Toute (re)prise démarre exactement aux positions **livrées** ; `execution_intent` ne revient jamais à `initial` | JOB-T04, T05, T12 |
| TEST-P08 | Un paiement « engagé » est couvert par un engagement antérieur (dans l'ordre du journal) à la révocation et à la clôture, recalculé indépendamment du code du domaine ; *(v2.5)* sur tout intervalle de 24 h, la somme brute des paiements sur reçus non engagés, recalculée sur le journal, ne dépasse pas le plafond | JOB-R12, R15, R19 |
| TEST-P09 | Fenêtre non validée ≤ budget de flux, par type ; la production vivante n'est jamais en retard sur les positions livrées | JOB-R13 |
| TEST-P10 | Aucun paiement sans preuve, hors arbitrage | JOB-R06 |
| TEST-P11 | `settling` ne mène qu'à `completed` | JOB-T14 à T16 |
| TEST-P12 | Invariants de ligne et cohérence avec les comptes `SliceLine` et `PendingReward` | JOB-R22, R24 |
| TEST-P13 | Règlement clos ⇒ escrows et sorties facturées à zéro, tranches finales, exécution terminale | JOB-S12 |
| TEST-P14 | Récupération réservée ≤ enveloppe ; récupération payée ≤ crédits entrés en escrow de récupération | JOB-R18 |
| TEST-P15 *(nouveau)* | Somme des contributions payées d'une sortie ≤ prix de la sortie | JOB-R21 |
| TEST-P16 *(nouveau)* | Un refus ne modifie pas l'état ; une commande idempotente ne change rien ; aucune erreur interne | JOB-R01, R04 |
| TEST-P17 *(nouveau, CE-02)* | Budget de l'emprunteur consommé avant le relais du pool ; à la clôture, chacun récupère exactement sa part non consommée | JOB-R18 |
| TEST-P18 | Les unités produites et non facturées de la tentative vivante sont toujours couvertes par l'escrow travail | JOB-R25 |
| TEST-P19 *(v2.4)* | Registre des sorties cohérent avec le journal ; préfixe définitif puis suffixe provisoire ; toute position validée est définitive | JOB-R17, R27, R29 |
| TEST-P20 *(v2.4, étendue en v2.5)* | Fondement de chaque facturation, recalculé indépendamment : provisoire seulement sur attestation du témoin assigné et indépendant, avec l'empreinte exacte des trames du flux, et, si tardive, couverte par un engagement antérieur à la révocation pendant le drainage ; définitive seulement sur signature du client couvrant la position et liée au flux, ou fenêtre réellement expirée ; annulation seulement d'une sortie provisoire, sur déclaration du client ou à l'échéance d'une contestation | JOB-R26 à R29, R32, R34 |
| TEST-P21 *(v2.4)* | Exposition bornée : `livrées − validées ≤ K` par type, pour tout le job | JOB-R13, R27 |
| TEST-P22 *(v2.4)* | Aucune contribution payée tant que sa sortie est provisoire ; une contribution d'une facturation annulée est remboursée ; une contribution en attente concerne une sortie encore provisoire | JOB-R30 |
| TEST-P23 *(v2.4)* | **Équité**, en fin de vidage : aucune réclamation valide perdue à la clôture ; toute contribution prouvée par engagement antérieur et financée est payée, et sa récompense libérée ou contestée ; un reçu non engagé n'est remboursé que par arbitrage | JOB-R06, R12, R19, R22 |
| TEST-P24 *(v2.4)* | Rien n'est accepté sous une autorisation expirée ; après une réconciliation, aucune tentative vivante n'a d'autorisation expirée ; une autorisation n'est jamais prolongée au-delà d'un TTL | JOB-R31 |
| TEST-P25 *(v2.4)* | Une position facturée n'est jamais recalculée : les positions livrées sont rejouées, pas régénérées ; une tentative vivante n'est jamais construite au-delà des positions livrées | JOB-R28 |
| TEST-P26 *(v2.5)* | Tampon de rejeu jamais purgé avant 24 h après la révocation, ni tant qu'une sortie de la tentative est provisoire ou contestée | JOB-R28 |
| TEST-P27 *(v2.5)* | Une contestation s'ouvre une fois, sur déclaration signée, pendant la fenêtre ; une sortie contestée ne devient définitive que par une signature du client couvrant sa position ; la fenêtre ne confirme jamais une sortie contestée ; aucune contestation échue ne survit à la réconciliation | JOB-R33 |
| TEST-P28 *(v2.5)* | Aucun remboursement faute de preuve avant l'échéance d'évaluation ; aucune preuve complémentaire après | JOB-R35 |

**Résultats (exécution de référence du 9 novembre 2026)** : 67 tests réussis sur 67. Propriétés exécutées sur 5 009, 5 009, 2 509 et 5 009 traces (dont 9 graines de non-régression), soit **1 997 086 commandes** vérifiées une à une ; total et mesures de couverture écrits par les tests pendant l'exécution (`target/coverage/`). Recherche préalable à 20 000 traces par générateur : aucun contre-exemple. Campagne de mutation : 52 bugs injectés sur 52 détectés, dont 48 par les propriétés dans la campagne complète. Détail dans `RAPPORT_TESTS.md`.

### 9.2 Scénarios déterministes

JOB-F01 à JOB-F41 : un test chacun (tableau de la section 4 ; JOB-F18 en a deux), plus les tests ciblés des corrections v2.3 (`r21_*`, `r22_*`, `r24_*`). Chaque scénario passe par le vérificateur complet et finit par la phase de vidage, qui vérifie aussi l'équité (TEST-P23).

### 9.3 Non-régression

Chaque contre-exemple trouvé est conservé deux fois : la graine brute dans `tests/properties/proptest-regressions.txt` (rejouée en premier à chaque exécution) et une version réduite et commentée dans `tests/regressions/` (CE-01 à CE-06). Ces tests ne sont jamais supprimés. En v2.5, deux d'entre eux ont été adaptés à la nouvelle règle JOB-R35 sans changer ce qu'ils démontrent : CE-03 vérifie maintenant que l'élément n'est jamais payé, puis qu'il est remboursé à l'échéance.

### 9.4 Tests sur grappe réelle (à venir)

- **TEST-G01** : débrancher un GPU sur 4 pendant la génération d'un 70B ; reprise sans perte de position validée.
- **TEST-G02** : rejeu des mêmes tranches sur GPU et quantifications variés pour calibrer les tolérances numériques.
- **TEST-G03** : RTT simulés de 2 à 50 ms et pertes de paquets.
- **TEST-G04** : nœud tricheur simulé ; détection mesurée.

## 10. Décisions à confirmer et limites du modèle

### Décisions prises

- **I-03** (v2.4) : preuve de livraison et rejeu.
- **v2.5** : les six décisions du journal (réputation des témoins, fenêtre de 24 h, clôture par accusé cumulatif lié au flux, empreinte de trame, attestations tardives engagées, preuves complémentaires jusqu'à l'échéance, plafond glissant sur montants bruts).

### Décisions à confirmer

1. **Délai de résolution d'une contestation** : 1 h dans le modèle. Trop court pour un client mobile, trop long pour libérer vite le tampon ? À calibrer avec le prototype.
2. **Coût et financement du tampon de rejeu (I-20)** : négligeable pour quelques tokens ; à mesurer pour les sorties volumineuses, le batch et des milliers de sessions. Qui paie le stockage, et que se passe-t-il si le témoin disparaît définitivement (aujourd'hui : traité comme un tampon perdu) ?
3. **Formule de réputation des témoins** : quels signaux (attestations suivies de remboursements, contrôles aléatoires, disponibilité) et quelles limites d'exposition par témoin en phase publique.
4. **Contribution remboursée faute de preuve** *(inchangé)* : après l'échéance, elle reste prise et ne peut plus être réclamée.

### Limites du modèle exécutable

- Pas d'outbox ni de persistance : l'atomicité (JOB-R01) est démontrée en mémoire, pas la livraison des événements (JOB-R02).
- Autorisations : l'échéance et le heartbeat sont modélisés sur l'horloge du coordinateur ; la dérive des horloges des nœuds (marge de JOB-R31) ne l'est pas.
- Témoin : attestation, engagement, tampon et rejeu sont des commandes. L'acquittement de transport, le chiffrement de bout en bout, les signatures et l'égalité octet pour octet des trames rejouées sont symboliques ; l'empreinte est un FNV-1a, pas un hash cryptographique. **Les garanties de livraison restent à confirmer sur de vrais échanges réseau (prototype QUIC, étape suivante).**
- Pas de scheduler, pas de réseau, pas de moteur : placements, productions et accusés sont des commandes.
- Les propriétés de vivacité et d'équité sont vérifiées par une phase de vidage sur des traces finies, pas démontrées pour toutes les traces (ce que ferait TLA+).
- Le plafond anti-collusion est abaissé à 4 crédits dans la simulation pour que les litiges soient exercés.
