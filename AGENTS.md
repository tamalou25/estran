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
- Aucun commit ni push sans demande explicite.

## Commandes
- Lancer : `docker compose up -d --build`
- Tests : `docker compose -f compose.test.yaml run --rm tests`
- Collecte manuelle : `docker compose exec collector python -m estran.collector run kev`

## Feuille de route
0a socle · 0b durcissement · 1 couche Menace · 2 Mon parc (fin du MVP) · bonus : 3 Territoire + Infrastructure, 4 Fils et hypothèses, 5 assistant local.
