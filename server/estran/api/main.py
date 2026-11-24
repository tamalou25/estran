"""API application. Served by uvicorn: `uvicorn estran.api.main:app`."""

from fastapi import FastAPI
from sqlalchemy import Engine

from estran import __version__
from estran.api.routes import router
from estran.ontology import Ontology


def create_app(*, engine: Engine, ontology: Ontology) -> FastAPI:
    app = FastAPI(
        title="Estran",
        version=__version__,
        description="API en lecture seule sur l'ontologie d'Estran.",
        # Pas de page de documentation interactive : elle chargerait des scripts depuis un
        # serveur tiers. Le schéma reste disponible sur /api/openapi.json.
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.engine = engine
    app.state.ontology = ontology
    app.include_router(router)
    return app


def __getattr__(name: str) -> FastAPI:
    """Build `app` lazily so importing this module needs no database (tests, tooling)."""
    if name != "app":
        raise AttributeError(name)
    from estran.db.engine import create_db_engine
    from estran.ontology import load_ontology
    from estran.settings import get_settings

    settings = get_settings()
    return create_app(
        engine=create_db_engine(settings.db_url()),
        ontology=load_ontology(settings.ontology_path),
    )
