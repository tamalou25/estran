# Image unique pour l'API, le collecteur, la migration et la création des secrets :
# seule la commande change. Contexte de build : la racine du dépôt.
#
#   base     Python + utilisateur ordinaire, sans pip
#   build    installe les dépendances avec uv (n'est pas livrée)
#   runtime  ce qui tourne : l'environnement Python et le code, rien d'autre
#   test     build + outils de développement + tests

FROM python:3.14-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
# pip et setuptools ne servent pas à l'exécution : les retirer supprime leurs vulnérabilités
# et prive un intrus d'un moyen d'installer des paquets.
RUN python -m pip uninstall --yes --quiet setuptools wheel pip 2>/dev/null; \
    rm -rf /usr/local/lib/python3.14/site-packages/pip* /usr/local/lib/python3.14/ensurepip
# Utilisateur ordinaire, sans mot de passe ni shell de connexion.
RUN groupadd --system --gid 10001 estran \
    && useradd --system --uid 10001 --gid estran --no-create-home --shell /usr/sbin/nologin estran \
    # Le volume des secrets, monté ici, hérite de ce propriétaire à sa création.
    && install -d -o estran -g estran -m 0750 /run/estran-secrets
WORKDIR /app/server

FROM base AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
# Les dépendances d'abord : cette couche n'est reconstruite que si le verrou change.
COPY server/pyproject.toml server/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY server/estran ./estran
RUN uv sync --locked --no-dev

FROM base AS runtime
COPY --from=build /opt/venv /opt/venv
COPY server/estran ./estran
COPY ontology /app/ontology
COPY data/snapshot /app/data/snapshot
USER estran
EXPOSE 8000
CMD ["uvicorn", "estran.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM build AS test
RUN uv sync --locked
COPY server/tests ./tests
COPY ontology /app/ontology
COPY data/snapshot /app/data/snapshot
COPY infra /app/infra
USER estran
# Utilisateur ordinaire : les outils n'écrivent leurs caches nulle part dans le projet.
ENV RUFF_NO_CACHE=true \
    MYPY_CACHE_DIR=/tmp/mypy
CMD ["sh", "-c", "ruff check . && ruff format --check . && mypy && pytest -p no:cacheprovider"]
