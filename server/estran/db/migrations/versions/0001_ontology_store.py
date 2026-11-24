"""Ontology store: sources, runs, objects, links, provenance.

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # postgis: geometry of objects (map layers). pg_trgm: fast substring search.
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.execute(
        """
        CREATE TABLE sources (
            id              text PRIMARY KEY,
            name            text NOT NULL,
            url             text NOT NULL,
            homepage        text NOT NULL,
            licence         text NOT NULL,
            licence_url     text NOT NULL,
            attribution     text NOT NULL,
            redistributable boolean NOT NULL,
            updated_at      timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE runs (
            id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            source_id         text NOT NULL REFERENCES sources (id),
            connector_version text NOT NULL,
            mode              text NOT NULL CHECK (mode IN ('live', 'snapshot')),
            status            text NOT NULL
                              CHECK (status IN ('running', 'success', 'unchanged', 'failed')),
            started_at        timestamptz NOT NULL DEFAULT now(),
            finished_at       timestamptz,
            objects_count     integer NOT NULL DEFAULT 0,
            links_count       integer NOT NULL DEFAULT 0,
            skipped_count     integer NOT NULL DEFAULT 0,
            content_sha256    text,
            etag              text,
            error             text
        )
        """
    )
    op.execute("CREATE INDEX ix_runs_source ON runs (source_id, id DESC)")

    op.execute(
        """
        CREATE TABLE objects (
            id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            type        text NOT NULL,
            key         text NOT NULL,
            title       text NOT NULL,
            properties  jsonb NOT NULL DEFAULT '{}',
            search_text text NOT NULL DEFAULT '',
            geom        geometry(Geometry, 4326),
            first_seen  timestamptz NOT NULL DEFAULT now(),
            last_seen   timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_objects_type_key UNIQUE (type, key)
        )
        """
    )
    op.execute("CREATE INDEX ix_objects_search ON objects USING gin (search_text gin_trgm_ops)")
    op.execute("CREATE INDEX ix_objects_geom ON objects USING gist (geom)")

    op.execute(
        """
        CREATE TABLE links (
            id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            type             text NOT NULL,
            source_object_id bigint NOT NULL REFERENCES objects (id) ON DELETE CASCADE,
            target_object_id bigint NOT NULL REFERENCES objects (id) ON DELETE CASCADE,
            properties       jsonb NOT NULL DEFAULT '{}',
            nature           text NOT NULL DEFAULT 'fact'
                             CHECK (nature IN ('fact', 'hypothesis')),
            first_seen       timestamptz NOT NULL DEFAULT now(),
            last_seen        timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_links_type_source_target
                UNIQUE (type, source_object_id, target_object_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_links_source ON links (source_object_id)")
    op.execute("CREATE INDEX ix_links_target ON links (target_object_id)")

    # Exactly one of object_id / link_id is set: a row says "this source provided that".
    op.execute(
        """
        CREATE TABLE provenance (
            id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            object_id    bigint REFERENCES objects (id) ON DELETE CASCADE,
            link_id      bigint REFERENCES links (id) ON DELETE CASCADE,
            source_id    text NOT NULL REFERENCES sources (id),
            first_run_id bigint NOT NULL REFERENCES runs (id),
            last_run_id  bigint NOT NULL REFERENCES runs (id),
            fields       jsonb NOT NULL DEFAULT '[]',
            first_seen   timestamptz NOT NULL DEFAULT now(),
            last_seen    timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT ck_provenance_one_subject CHECK ((object_id IS NULL) <> (link_id IS NULL))
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_provenance_object_source ON provenance (object_id, source_id) "
        "WHERE object_id IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_provenance_link_source ON provenance (link_id, source_id) "
        "WHERE link_id IS NOT NULL"
    )


def downgrade() -> None:
    for table in ("provenance", "links", "objects", "runs", "sources"):
        op.execute(f"DROP TABLE {table}")
