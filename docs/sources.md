# Sources et licences

Règle : une source n'est branchée que si elle est publique, légale, et que ses conditions
d'usage autorisent une collecte automatisée au rythme prévu. Chaque connecteur déclare ces
informations dans son `manifest.yaml` ; l'interface les affiche sur la page « Sources ».

## Sources branchées

Conditions lues le 24/11/2026 sur les pages indiquées.

| Source | Ce qu'elle apporte | Licence / conditions | Redistribution | Cadence |
|---|---|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnérabilités dont l'exploitation réelle est confirmée ; produits, éditeurs | [CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | Autorisée | 6 h |
| [MITRE ATT&CK](https://attack.mitre.org/) v20.1 | Techniques, tactiques, groupes, logiciels d'attaque et leurs liens | [Licence ATT&CK](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) : usage libre avec la mention MITRE | Autorisée avec la mention | 24 h |
| [Correspondances KEV → ATT&CK](https://ctid.mitre.org/mappings/) (MITRE CTID) | Liens faille → technique | [Apache-2.0](https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/LICENSE.txt) | Autorisée | 7 j |
| [NIST NVD](https://nvd.nist.gov/) | Gravité CVSS et date de publication des failles KEV | [Conditions de l'API](https://nvd.nist.gov/developers/terms-of-use) : mention à afficher | Données publiques | 24 h |
| [FIRST EPSS](https://www.first.org/epss/) | Probabilité d'exploitation sous 30 jours | Accès « freely and openly », sans licence explicite | **Non** : collectée et affichée, jamais redistribuée | 24 h |
| [CERT-FR, alertes](https://www.cert.cyber.gouv.fr/alerte/) | Alertes de sécurité et failles qu'elles citent | [Licence Ouverte 2.0](https://www.etalab.gouv.fr/licence-ouverte-open-licence/) | Autorisée avec attribution | 6 h |

Mentions obligatoires, affichées sur la page « Sources » et dans la provenance des objets :

- MITRE ATT&CK : « © 2026 The MITRE Corporation. This work is reproduced and distributed with
  the permission of The MITRE Corporation. »
- NVD : « This product uses the NVD API but is not endorsed or certified by the NVD. »

### Choix et limites

- **NVD plutôt que la liste CVE complète.** Une requête (`hasKev`) renvoie les failles du
  catalogue KEV avec leur CVSS, au lieu d'une requête par faille. C'est aussi le sous-ensemble
  que le NVD analyse encore en entier. Sans clé d'API : 5 requêtes par 30 secondes au plus ;
  Estran attend 6,5 s entre deux pages.
- **Correspondances faille → technique.** Fichier de juillet 2025, établi pour ATT&CK 16.1 :
  environ un quart du catalogue KEV est couvert, et les techniques retirées depuis sont
  ignorées (comptées dans les « ignorés » de la collecte). Son adresse contient sa date : une
  nouvelle édition demande de mettre à jour le manifeste.
- **ATT&CK.** Les entrées retirées (révoquées ou dépréciées) ne sont pas collectées, ni les
  mesures de défense, détections et campagnes. Les noms des contributeurs (personnes) que le
  fichier contient ne sont **jamais** lus.
- **CERT-FR.** Seul le flux des alertes cite les identifiants CVE ; les avis ne sont pas
  collectés. Une alerte citant une faille absente du catalogue KEV garde sa fiche, sans lien.
- **EPSS.** Le fichier note toutes les CVE publiées ; Estran ne garde que les scores des
  failles qu'il connaît déjà.

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
