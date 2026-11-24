from sqlalchemy import URL, Engine, create_engine


def create_db_engine(url: str | URL) -> Engine:
    """`url` looks like postgresql+psycopg://user:password@host:5432/database."""
    return create_engine(url, pool_pre_ping=True)
