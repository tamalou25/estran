from sqlalchemy import Engine, create_engine


def create_db_engine(url: str) -> Engine:
    """`url` looks like postgresql+psycopg://user:password@host:5432/database."""
    return create_engine(url, pool_pre_ping=True)
