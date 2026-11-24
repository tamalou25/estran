"""Alembic environment. The database URL is handed over by estran.db.migrate."""

from alembic import context
from sqlalchemy import create_engine

from estran.db.tables import metadata

url: str = context.config.attributes["url"]

if context.is_offline_mode():
    context.configure(url=url, target_metadata=metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
