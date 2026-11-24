# Image unique pour l'API, le collecteur et la migration : seule la commande change.
# Contexte de build : la racine du dépôt (l'image embarque aussi l'ontologie et l'instantané).

FROM python:3.14-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
WORKDIR /app/server
# Les dépendances d'abord : cette couche n'est reconstruite que si le verrou change.
COPY server/pyproject.toml server/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM base AS runtime
COPY server/estran ./estran
RUN uv sync --locked --no-dev
COPY ontology /app/ontology
COPY data/snapshot /app/data/snapshot
EXPOSE 8000
CMD ["uvicorn", "estran.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Cible de test : mêmes dépendances, plus les outils de développement et les tests.
FROM base AS test
RUN uv sync --locked --no-install-project
COPY server/estran ./estran
COPY server/tests ./tests
RUN uv sync --locked
COPY ontology /app/ontology
COPY data/snapshot /app/data/snapshot
CMD ["sh", "-c", "ruff check . && ruff format --check . && mypy && pytest"]
