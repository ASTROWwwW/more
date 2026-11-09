# More

More permet de partager la puissance de son GPU. Quand ta carte ne sert pas, tu la prêtes au réseau et tu gagnes des crédits. Quand tu veux faire tourner un modèle trop gros pour ta machine, tu dépenses ces crédits : le modèle est découpé en tranches de couches, et chaque tranche tourne sur le GPU d'un prêteur.

Un coordinateur tient les comptes et organise l'exécution, mais le calcul circule directement entre les machines. Les crédits ne s'achètent pas et ne se transfèrent pas : on les gagne en prêtant et on les dépense en empruntant, à l'intérieur d'un pool. Un pool peut rester privé, se fédérer avec d'autres pools ou s'ouvrir au public, et chacun peut héberger son propre coordinateur.

## Contenu du dépôt

Pour l'instant, le dépôt contient la spécification du système et un modèle exécutable en Rust de ses règles. Il n'y a pas encore de réseau ni de moteur GPU. Le modèle sert à vérifier, avant d'écrire le vrai coordinateur, que les règles résistent aux pannes et à la triche. Un job interrompu doit reprendre sans perdre ni refacturer un résultat déjà livré. Chaque sortie est facturée une seule fois, chaque contribution d'un prêteur est payée au plus une fois, et aucun crédit n'est créé ni perdu en route.

Les tests génèrent des séquences aléatoires de commandes : nœuds qui tombent, messages en double, clients qui n'acquittent pas, prêteurs qui mentent sur la livraison, horloges qui expirent. Les invariants sont vérifiés après chaque commande, et une campagne de mutation réintroduit des bugs connus pour s'assurer que les tests les attrapent.

| Chemin | Rôle |
| --- | --- |
| `crates/ledger` | Registre comptable en partie double, en insertion seule |
| `crates/domain` | Coordinateur : jobs, tentatives, tranches de facturation, livraison des sorties, règlement |
| `crates/protocol` | Contrat des messages : enveloppe, contrôle de taille, codes d'erreur, anti-rejeu |
| `crates/simulation` | Vérificateur d'invariants et générateurs de scénarios aléatoires |
| `tests/` | Tests de propriétés, scénarios d'échec et contre-exemples trouvés |
| `scripts/mutation.py` | Campagne de mutation |
| `docs/specification.md` | Spécification complète |
| `RAPPORT_TESTS.md` | Tests exécutés et résultats |

## Lancer les tests

```sh
cargo test --release --workspace
PROPTEST_CASES=5000 cargo test --release --workspace   # plus de traces aléatoires
python3 scripts/mutation.py                            # environ 30 min
```

Il faut Rust 1.75 ou plus récent.

## Licence

AGPL-3.0.
