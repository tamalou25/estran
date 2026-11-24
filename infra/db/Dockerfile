# PostgreSQL + PostGIS, avec les correctifs de sécurité du système appliqués.
#
# L'image d'origine n'est reconstruite que de temps en temps : entre deux versions, des
# correctifs Debian sortent et y manquent. On les applique ici au moment du build.
#
# « gosu » sert au script d'entrée à quitter root pour l'utilisateur postgres. Estran lance
# le conteneur directement sous cet utilisateur (compose : user "999:999") : l'outil ne sert
# plus, on le retire plutôt que de traîner ses vulnérabilités.

FROM postgis/postgis:18-3.7
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/local/bin/gosu
USER postgres
