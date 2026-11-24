"""Command line of the collector.

python -m estran.collector serve        run every connector on schedule (the container's job)
python -m estran.collector run kev      run one connector now
python -m estran.collector list         list available connectors
python -m estran.collector health       exit 0 if the scheduler loop is alive
python -m estran.collector allowlist    print the hosts the egress proxy must let through
"""

import argparse
import logging
import sys
from pathlib import Path

from estran.collector import allowlist
from estran.collector.connectors import REGISTRY
from estran.collector.runner import run_connector
from estran.collector.scheduler import is_alive, serve
from estran.db.engine import create_db_engine
from estran.ontology import load_ontology
from estran.settings import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="estran.collector", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    commands.add_parser("list")
    commands.add_parser("health")
    allow = commands.add_parser("allowlist")
    allow.add_argument("--write", type=Path, help="write the file instead of printing it")
    run = commands.add_parser("run")
    run.add_argument("connector", choices=sorted(REGISTRY))
    run.add_argument("--mode", choices=["live", "snapshot"])
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # These two need no database: they only read the connector manifests.
    if args.command == "allowlist":
        if args.write:
            args.write.write_text(allowlist.render(), encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(allowlist.render())
        return 0
    if args.command == "list":
        for name, connector in sorted(REGISTRY.items()):
            manifest = connector.manifest
            print(f"{name}\t{manifest.name}\t{manifest.licence}")  # noqa: T201
        return 0

    settings = get_settings()
    if args.command == "health":
        return 0 if is_alive(settings.heartbeat_file) else 1

    engine = create_db_engine(settings.db_url())
    ontology = load_ontology(settings.ontology_path)
    if args.command == "serve":
        serve(
            engine,
            ontology,
            mode=settings.mode,
            snapshot_dir=settings.snapshot_dir,
            heartbeat=settings.heartbeat_file,
        )
        return 0

    if not REGISTRY[args.connector]().is_configured():
        print(f"{args.connector}: not configured (optional source, see secrets/README.md)")  # noqa: T201
        return 1
    result = run_connector(
        engine,
        ontology,
        REGISTRY[args.connector](),
        mode=args.mode or settings.mode,
        snapshot_dir=settings.snapshot_dir,
    )
    print(  # noqa: T201
        f"{args.connector}: {result.status}, {result.objects} objects, {result.links} links, "
        f"{result.skipped} skipped" + (f" ({result.error})" if result.error else "")
    )
    return 0 if result.status != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
