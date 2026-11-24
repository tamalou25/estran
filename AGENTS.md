# Estran — règles du projet

Plateforme locale d'analyse de données ouvertes : une ontologie d'objets reliés, avec provenance.
Thèse : *Internet est un territoire* (couches Territoire, Infrastructure, Menace).

## Limites non négociables
- Données ouvertes uniquement ; licence, attribution et limites de requêtes de chaque source respectées.
- Aucune donnée personnelle : pas de type « Personne », le validateur d'ontologie refuse les termes interdits.
- Aucun scan actif. Collecte passive de jeux de données publiés.
- Identité visuelle originale.
- Une source non redistribuable n'entre jamais dans `data/snapshot/`.

## Conventions
- Code, tables et identifiants en anglais ; interface, ontologie (`label`) et documentation en français.
- Test écrit avant le code. `translate()` d'un connecteur est une fonction pure, testée sur un extrait enregistré : aucun appel réseau dans les tests.
- Ajouter une source = un dossier `server/estran/collector/connectors/<id>/` (`manifest.yaml` + `connector.py`) et, si besoin, des types dans `ontology/ontology.yaml`. Pas de changement de schéma de base.
- L'API est en lecture seule. SQL toujours paramétré.
- Indicateurs techniques (adresses IP, domaines, URL) : jamais stockés. Une source qui en fournit les ramène à des comptes par réseau avant toute écriture.
- Une source qui exige une clé est optionnelle : `is_configured()` renvoie faux sans elle, la clé se lit dans un fichier de `secrets/`, jamais dans le dépôt ni dans un message.
- Avant d'écrire un connecteur : lire les conditions d'usage de la source, les noter dans `docs/sources.md`, et ne jamais collecter un champ qui nomme une personne.
- Une source qui complète les objets d'une autre le déclare dans son manifeste (`after`, `enriches`) et figure après elle dans le registre.
- Ajouter un domaine à un manifeste impose de régénérer la liste blanche du proxy :
  `python -m estran.collector allowlist --write infra/proxy/allowlist.txt` (un test échoue sinon).
- Toute mesure de sécurité annoncée dans `docs/security.md` a sa vérification dans
  `scripts/check-hardening.sh` ou `scripts/security-scan.sh`. Pas de mot de passe dans le dépôt
  ni en variable d'environnement.
- Aucun commit ni push sans demande explicite.

## Commandes
- Lancer : `docker compose up -d --build`
- Tests : `docker compose -f compose.test.yaml run --rm tests`
- Collecte manuelle : `docker compose exec collector python -m estran.collector run kev`
- Preuve du durcissement : `bash scripts/check-hardening.sh` (pile en marche)
- Scans : `bash scripts/security-scan.sh` (images construites)

## Feuille de route
0a socle · 0b durcissement · 1a couche Menace · 1b infrastructure d'attaque (abuse.ch, avec clé) · 2 Mon parc (fin du MVP) · bonus : 3 Territoire + Infrastructure, 4 Fils et hypothèses, 5 assistant local.
