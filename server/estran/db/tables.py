"""Table definitions used to build queries. The schema itself is created by the migrations.

`objects.geom` (PostGIS geometry, for the map layers) exists in the database but is not
listed here: nothing reads or writes it before the Territory and Infrastructure layers.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()


def _timestamp(name: str, *, nullable: bool = False) -> Column[object]:
    default = None if nullable else func.now()
    return Column(name, DateTime(timezone=True), nullable=nullable, server_default=default)


sources = Table(
    "sources",
    metadata,
    Column("id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("url", Text, nullable=False),
    Column("homepage", Text, nullable=False),
    Column("licence", Text, nullable=False),
    Column("licence_url", Text, nullable=False),
    Column("attribution", Text, nullable=False),
    Column("redistributable", Boolean, nullable=False),
    _timestamp("updated_at"),
)

runs = Table(
    "runs",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("source_id", Text, ForeignKey("sources.id"), nullable=False),
    Column("connector_version", Text, nullable=False),
    Column("mode", Text, nullable=False),
    Column("status", Text, nullable=False),
    _timestamp("started_at"),
    _timestamp("finished_at", nullable=True),
    Column("objects_count", Integer, nullable=False, server_default="0"),
    Column("links_count", Integer, nullable=False, server_default="0"),
    Column("skipped_count", Integer, nullable=False, server_default="0"),
    Column("content_sha256", Text),
    Column("etag", Text),
    Column("error", Text),
)

objects = Table(
    "objects",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("type", Text, nullable=False),
    Column("key", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("properties", JSONB, nullable=False, server_default="{}"),
    Column("search_text", Text, nullable=False, server_default=""),
    _timestamp("first_seen"),
    _timestamp("last_seen"),
)

links = Table(
    "links",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("type", Text, nullable=False),
    Column("source_object_id", BigInteger, ForeignKey("objects.id"), nullable=False),
    Column("target_object_id", BigInteger, ForeignKey("objects.id"), nullable=False),
    Column("properties", JSONB, nullable=False, server_default="{}"),
    Column("nature", Text, nullable=False, server_default="fact"),
    _timestamp("first_seen"),
    _timestamp("last_seen"),
)

provenance = Table(
    "provenance",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("object_id", BigInteger, ForeignKey("objects.id")),
    Column("link_id", BigInteger, ForeignKey("links.id")),
    Column("source_id", Text, ForeignKey("sources.id"), nullable=False),
    Column("first_run_id", BigInteger, ForeignKey("runs.id"), nullable=False),
    Column("last_run_id", BigInteger, ForeignKey("runs.id"), nullable=False),
    Column("fields", JSONB, nullable=False, server_default="[]"),
    _timestamp("first_seen"),
    _timestamp("last_seen"),
)
