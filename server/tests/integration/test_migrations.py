from sqlalchemy import inspect, text

from estran.db.migrate import downgrade, upgrade

TABLES = {"sources", "runs", "objects", "links", "provenance"}


def test_migration_creates_the_ontology_tables(engine):
    assert set(inspect(engine).get_table_names()) >= TABLES


def test_objects_can_carry_a_geometry_for_the_map_layers(engine):
    with engine.connect() as connection:
        column_type = connection.execute(
            text(
                "SELECT udt_name FROM information_schema.columns "
                "WHERE table_name = 'objects' AND column_name = 'geom'"
            )
        ).scalar_one()

    assert column_type == "geometry"


def test_an_object_is_unique_by_type_and_key(engine):
    insert = text(
        "INSERT INTO objects (type, key, title, properties, search_text) "
        "VALUES ('vendor', 'acme', 'Acme', '{}', 'acme')"
    )
    with engine.begin() as connection:
        connection.execute(insert)

    try:
        with engine.begin() as connection:
            connection.execute(insert)
    except Exception as error:
        assert "uq_objects_type_key" in str(error)
    else:
        raise AssertionError("a duplicate (type, key) was accepted")


def test_migration_can_be_rolled_back_and_replayed(engine, database_url):
    downgrade(database_url, "base")
    assert not TABLES & set(inspect(engine).get_table_names())

    upgrade(database_url)
    assert set(inspect(engine).get_table_names()) >= TABLES
