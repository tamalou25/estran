# Sources et licences

Règle : une source n'est branchée que si elle est publique, légale, et que ses conditions
d'usage autorisent une collecte automatisée au rythme prévu. Chaque connecteur déclare ces
informations dans son `manifest.yaml` ; l'interface les affiche sur la page « Sources ».

## Sources branchées

| Source | Contenu | Licence | Redistribution | Cadence | Vérifié le |
|---|---|---|---|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnérabilités dont l'exploitation réelle est confirmée | [CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | Autorisée | 1 requête / 6 h | 24/11/2026 |

Flux utilisé : `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
La licence CC0 ne couvre pas le logo ni le sceau de la CISA, qu'Estran n'utilise pas.

## Instantané embarqué

`data/snapshot/` contient une copie figée des sources **redistribuables uniquement**, pour que
la démonstration fonctionne sans Internet.

| Fichier | Source | Version | Entrées |
|---|---|---|---|
| `kev.json` | CISA KEV | 2026.11.23 | 1 792 |

Le programme refuse qu'un connecteur déclare à la fois `redistributable: false` et un
instantané.

## Comment Estran se comporte vis-à-vis d'une source

- HTTPS uniquement, et uniquement vers les domaines déclarés dans le manifeste.
- Requête conditionnelle (`If-None-Match`) : si rien n'a changé, rien n'est retéléchargé.
- En cas d'échec, nouvelle tentative au plus tôt 15 minutes après, jamais en boucle.
- Le collecteur s'identifie par l'en-tête `User-Agent: Estran/<version> (open-data collector)`.

## Ce qu'Estran ne collecte pas

- Aucune donnée personnelle : pas de type « Personne », pas de coordonnées de contact.
- Aucun scan actif de machines ou de réseaux : uniquement des jeux de données publiés.
