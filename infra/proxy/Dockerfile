# Proxy sortant à liste blanche. Contexte de build : la racine du dépôt.
# Squid est lancé directement sous l'utilisateur « proxy », jamais root : le script d'entrée
# de l'image d'origine (qui écrit des fichiers et génère un certificat) n'est pas utilisé.

FROM ubuntu/squid:6.6-24.04_edge
COPY infra/proxy/squid.conf /etc/squid/squid.conf
COPY infra/proxy/allowlist.txt /etc/squid/allowlist.txt
USER proxy
EXPOSE 3128
ENTRYPOINT ["/usr/sbin/squid"]
# -N : au premier plan, sans processus fils ; le conteneur vit et meurt avec Squid.
CMD ["-N", "-f", "/etc/squid/squid.conf"]
