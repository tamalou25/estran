#!/usr/bin/env bash
# Preuve du durcissement : interroge la pile EN MARCHE et vérifie chaque propriété annoncée.
#
#   docker compose up -d --build --wait
#   bash scripts/check-hardening.sh
#
# Fonctionne sous Linux, macOS et Git Bash (Windows). Code de sortie 0 si tout est vérifié.
# Ce script ne modifie rien : il essaie des actions qui DOIVENT échouer.

set -u
export MSYS_NO_PATHCONV=1   # Git Bash : ne pas transformer /chemin en C:\...

PORT="${ESTRAN_WEB_PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"
# Le curl de Windows ne connaît pas /dev/null.
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) DEVNULL=NUL ;; *) DEVNULL=/dev/null ;; esac
PASSED=0
FAILED=0

ok()   { PASSED=$((PASSED + 1)); printf '  OK     %s\n' "$1"; }
ko()   { FAILED=$((FAILED + 1)); printf '  ECHEC  %s\n' "$1"; }
title() { printf '\n%s\n' "$1"; }

# expect_success "description" commande...   → la commande doit réussir
expect_success() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else ko "$what"; fi; }
# expect_failure "description" commande...   → la commande doit échouer
expect_failure() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ko "$what"; else ok "$what"; fi; }

inside() { local service="$1"; shift; docker compose exec -T "$service" "$@"; }
py() { inside "$1" python -c "$2"; }

# Connexion TCP brute, sans DNS ni proxy : 1.1.1.1:443 répond toujours si une route existe.
RAW_EGRESS="import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)"

# Envoie une requête brute au proxy et réussit si la réponse commence par le code attendu.
proxy_answers() {  # $1 = première ligne de requête, $2 = code attendu
  py collector "
import socket, sys
s = socket.create_connection(('proxy', 3128), timeout=10)
s.sendall(b'$1\r\nHost: x\r\n\r\n')
status = s.recv(64).split(b' ')[1].decode()
sys.exit(0 if status == '$2' else 1)"
}

# Exécute du SQL avec le rôle de base du service et réussit si la base l'accepte.
sql_as() {  # $1 = service, $2 = SQL
  py "$1" "
from sqlalchemy import text
from estran.db.engine import create_db_engine
from estran.settings import get_settings
with create_db_engine(get_settings().db_url()).begin() as connection:
    connection.execute(text('''$2'''))"
}

RUNNING="db api collector proxy web"

# ---------------------------------------------------------------------------------------------
title "1. Surface exposée sur la machine"

published="$(docker compose ps --format '{{.Service}} {{.Ports}}' | grep -- '->' || true)"
if [ "$(printf '%s\n' "$published" | grep -c .)" = "1" ] \
   && printf '%s' "$published" | grep -q "^web 127\.0\.0\.1:${PORT}->8080/tcp$"; then
  ok "un seul port publié : web, sur 127.0.0.1:${PORT}"
else
  ko "ports publiés inattendus : ${published:-aucun}"
fi
expect_success "l'interface répond sur ${BASE}" curl -fsS -o "$DEVNULL" "${BASE}/"
expect_failure "la base n'est pas joignable depuis la machine (5432)" curl -s --max-time 3 telnet://127.0.0.1:5432
expect_failure "l'API n'est pas joignable directement (8000)" curl -s --max-time 3 "http://127.0.0.1:8000/api/health"
expect_failure "le proxy n'est pas joignable depuis la machine (3128)" curl -s --max-time 3 telnet://127.0.0.1:3128

# ---------------------------------------------------------------------------------------------
title "2. Cloisonnement réseau : qui peut sortir vers Internet"

expect_failure "api : aucune route vers Internet" py api "$RAW_EGRESS"
expect_failure "api : ne résout aucun nom extérieur" py api "import socket; socket.getaddrinfo('www.cisa.gov', 443)"
expect_failure "collector : aucune sortie directe (sans proxy)" py collector "$RAW_EGRESS"
expect_failure "db : aucune route vers Internet" inside db bash -c "exec 3<>/dev/tcp/1.1.1.1/443"
# Témoin : la même sonde réussit vers un port ouvert, donc l'échec ci-dessus est bien un blocage.
expect_success "db : la sonde utilisée fonctionne (témoin)" inside db bash -c "exec 3<>/dev/tcp/127.0.0.1/5432"
expect_failure "api : ne voit pas le proxy" py api "import socket; socket.create_connection(('proxy', 3128), timeout=3)"
expect_failure "web : ne voit pas la base" inside web nc -z -w 3 db 5432
expect_failure "web : ne voit pas le proxy" inside web nc -z -w 3 proxy 3128
expect_success "web : joint l'API (seul chemin prévu)" inside web nc -z -w 3 api 8000

# ---------------------------------------------------------------------------------------------
title "3. Proxy sortant : liste blanche, HTTPS seul"

expect_success "hôte déclaré (www.cisa.gov:443) : tunnel accepté" proxy_answers "CONNECT www.cisa.gov:443 HTTP/1.1" 200
expect_success "hôte non déclaré (example.org:443) : refusé (403)" proxy_answers "CONNECT example.org:443 HTTP/1.1" 403
expect_success "sous-domaine non déclaré (evil.www.cisa.gov) : refusé (403)" proxy_answers "CONNECT evil.www.cisa.gov:443 HTTP/1.1" 403
expect_success "hôte déclaré mais autre port (22) : refusé (403)" proxy_answers "CONNECT www.cisa.gov:22 HTTP/1.1" 403
expect_success "HTTP en clair vers un hôte déclaré : refusé (403)" proxy_answers "GET http://www.cisa.gov/ HTTP/1.1" 403
expect_success "adresse IP au lieu d'un nom : refusée (403)" proxy_answers "CONNECT 1.1.1.1:443 HTTP/1.1" 403

# ---------------------------------------------------------------------------------------------
title "4. Conteneurs : sans privilèges, système de fichiers en lecture seule"

for service in $RUNNING; do
  uid="$(inside "$service" id -u 2>/dev/null | tr -d '\r')"
  if [ -n "$uid" ] && [ "$uid" != "0" ]; then ok "$service : utilisateur ordinaire (uid $uid)"; else ko "$service : tourne en root"; fi
  expect_failure "$service : système de fichiers en lecture seule" inside "$service" sh -c "touch /estran-write-test"
  status="$(inside "$service" cat /proc/1/status 2>/dev/null | tr -d '\r')"
  if printf '%s' "$status" | grep -q '^CapEff:[[:space:]]*0000000000000000$'; then ok "$service : aucune capacité Linux"; else ko "$service : capacités présentes"; fi
  if printf '%s' "$status" | grep -q '^NoNewPrivs:[[:space:]]*1$'; then ok "$service : élévation de privilèges interdite"; else ko "$service : no-new-privileges absent"; fi
done

# ---------------------------------------------------------------------------------------------
title "5. Base de données : moindre privilège"

expect_success "api : peut lire" sql_as api "SELECT count(*) FROM objects"
expect_failure "api : ne peut pas écrire" sql_as api "UPDATE objects SET title = title"
expect_failure "api : ne peut pas supprimer" sql_as api "DELETE FROM objects WHERE false"
expect_failure "api : ne peut pas créer de table" sql_as api "CREATE TABLE estran_check (id int)"
expect_success "collector : peut écrire ses collectes" sql_as collector "UPDATE runs SET error = error WHERE false"
expect_failure "collector : ne peut pas supprimer" sql_as collector "DELETE FROM objects WHERE false"
expect_failure "collector : ne peut pas vider une table" sql_as collector "TRUNCATE runs"
expect_failure "collector : ne peut pas modifier le schéma" sql_as collector "ALTER TABLE objects ADD COLUMN estran_check int"

for service in api collector; do
  seen="$(inside "$service" sh -c 'find /run/secrets /run/estran-secrets -type f 2>/dev/null' | tr -d '\r' | tr '\n' ' ')"
  if [ "$seen" = "/run/secrets/estran/password " ]; then ok "$service : ne voit que son propre mot de passe"; else ko "$service : voit d'autres secrets ($seen)"; fi
done
if docker compose config | grep -Eiq '(password|secret)[a-z_]*: *[^/ ]'; then
  ko "un mot de passe figure en clair dans la configuration"
else
  ok "aucun mot de passe en clair dans la configuration (fichiers uniquement)"
fi

# ---------------------------------------------------------------------------------------------
title "6. Entrée HTTP : en-têtes, méthodes, débit"

headers="$(curl -fsS -D - -o "$DEVNULL" "${BASE}/" | tr -d '\r')"
api_headers="$(curl -fsS -D - -o "$DEVNULL" "${BASE}/api/health" | tr -d '\r')"
for header in "Content-Security-Policy: default-src 'none'" "X-Content-Type-Options: nosniff" "X-Frame-Options: DENY" "Referrer-Policy: no-referrer"; do
  name="${header%%:*}"
  if printf '%s' "$headers" | grep -qi "^${header}" && printf '%s' "$api_headers" | grep -qi "^${header}"; then
    ok "en-tête ${name} présent (pages et API)"
  else
    ko "en-tête ${name} absent"
  fi
done
if printf '%s' "$headers" | grep -qi '^Server: nginx$'; then ok "version du serveur web masquée"; else ko "version du serveur web visible"; fi

code() { curl -s -o "$DEVNULL" -w '%{http_code}' "$@"; }
[ "$(code -X POST "${BASE}/api/objects")" = "405" ] && ok "POST refusé (405)" || ko "POST accepté"
[ "$(code -X DELETE "${BASE}/api/objects/vendor/microsoft")" = "405" ] && ok "DELETE refusé (405)" || ko "DELETE accepté"
[ "$(code "${BASE}/api/docs")" = "404" ] && ok "pas de page de documentation chargeant des scripts tiers" || ko "/api/docs exposé"
[ "$(code "${BASE}/api/objects?type=vulnerability&sort=title;DROP%20TABLE%20objects")" = "422" ] && ok "tri invalide refusé (422)" || ko "tri invalide accepté"

limited="$(seq 1 200 | xargs -P 40 -I{} curl -s -o "$DEVNULL" -w '%{http_code}\n' "${BASE}/api/health" | grep -c '^429$' || true)"
if [ "${limited:-0}" -gt 0 ]; then ok "limite de débit active : ${limited} requêtes sur 200 refusées (429)"; else ko "aucune requête limitée sur une rafale de 200"; fi
sleep 3
[ "$(code "${BASE}/api/health")" = "200" ] && ok "service de nouveau disponible après la rafale" || ko "service indisponible après la rafale"

# ---------------------------------------------------------------------------------------------
printf '\n%d vérifications réussies, %d en échec.\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
