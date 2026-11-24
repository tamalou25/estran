#!/usr/bin/env bash
# Scans de sécurité, identiques sur un poste et dans la CI. Les images doivent être construites :
#
#   docker compose build
#   bash scripts/security-scan.sh
#
# 1. gitleaks : aucun secret dans l'historique git ;
# 2. trivy config : pas de mauvaise configuration grave dans les Dockerfiles ;
# 3. trivy fs : pas de dépendance vulnérable dans les fichiers de verrou ;
# 4. trivy image : aucune vulnérabilité CRITIQUE ou ÉLEVÉE disposant d'un correctif ;
# 5. SBOM : inventaire CycloneDX de chaque image, écrit dans sbom/.
#
# Code de sortie 0 si tout est propre. Fonctionne sous Linux, macOS et Git Bash (Windows).

set -u
export MSYS_NO_PATHCONV=1

GITLEAKS="zricethezav/gitleaks:v8.30.1"
TRIVY="aquasec/trivy:0.76.2"
IMAGES="estran-server estran-web estran-proxy estran-db"

# Chemin du dépôt tel que Docker l'attend (C:/... sous Git Bash).
if pwd -W >/dev/null 2>&1; then REPO="$(pwd -W)"; else REPO="$(pwd)"; fi
mkdir -p sbom

FAILED=0
step() {  # step "description" commande...   Le détail n'est affiché qu'en cas d'échec.
  local what="$1" output; shift
  if output="$("$@" 2>&1)"; then
    printf '  OK     %s\n' "$what"
  else
    FAILED=$((FAILED + 1)); printf '  ECHEC  %s\n%s\n' "$what" "$output"
  fi
}

trivy() { docker run --rm -v estran-trivy-cache:/root/.cache "$@"; }
trivy_repo() { trivy -v "${REPO}:/repo:ro" "$TRIVY" "$@"; }
trivy_image() { trivy -v /var/run/docker.sock:/var/run/docker.sock -v "${REPO}/sbom:/sbom" "$TRIVY" image --quiet "$@"; }

printf '\nSecrets\n'
step "aucun secret dans l'historique git" \
  docker run --rm -v "${REPO}:/repo:ro" "$GITLEAKS" git /repo --no-banner --redact --log-level error

printf '\nConfiguration et dépendances\n'
step "Dockerfiles sans mauvaise configuration grave" \
  trivy_repo config --quiet --exit-code 1 --severity CRITICAL,HIGH \
    --skip-dirs /repo/server/.venv --skip-dirs /repo/web/node_modules /repo
step "dépendances verrouillées (uv, npm) sans vulnérabilité critique ou élevée" \
  trivy_repo fs --quiet --exit-code 1 --scanners vuln --severity CRITICAL,HIGH \
    --skip-dirs /repo/server/.venv --skip-dirs /repo/web/node_modules /repo

printf '\nImages\n'
for image in $IMAGES; do
  step "$image : aucune vulnérabilité critique ou élevée corrigeable" \
    trivy_image --exit-code 1 --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed "$image"
  step "$image : inventaire écrit dans sbom/${image}.cdx.json" \
    trivy_image --format cyclonedx --output "/sbom/${image}.cdx.json" "$image"
done

printf '\n'
if [ "$FAILED" -eq 0 ]; then echo "Scans propres."; else echo "${FAILED} scan(s) en échec : voir le détail ci-dessus."; fi
[ "$FAILED" -eq 0 ]
