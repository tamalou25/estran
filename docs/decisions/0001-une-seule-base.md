# 0001 — Une seule base : PostgreSQL + PostGIS

Date : 24/11/2026 · État : acceptée

## Contexte

Estran doit stocker un graphe d'objets typés, de la géographie, du temps et du texte, et se
lancer en une commande sur une machine personnelle.

## Décision

Une seule base PostgreSQL 18 avec PostGIS. Le graphe est un modèle générique à deux tables
(`objects`, `links`) ; les parcours se font en SQL.

## Alternatives écartées

| Option | Pourquoi non |
|---|---|
| Neo4j en plus de PostgreSQL | Deux bases à synchroniser et à sauvegarder pour un graphe de quelques centaines de milliers de nœuds |
| Apache AGE (graphe dans PostgreSQL) | Seule une version candidate existait pour PostgreSQL 18 au moment du choix |
| Kùzu (graphe embarqué) | Dépôt archivé depuis octobre 2025 |

## Conséquences

- Un seul service à faire tourner, à sauvegarder et à durcir.
- Les parcours profonds (plus de trois sauts) seront moins confortables qu'en Cypher. Si
  l'explorateur de graphe en a besoin, cette décision sera réexaminée.
- `pgvector` pourra être ajouté à la même base pour l'assistant local.
