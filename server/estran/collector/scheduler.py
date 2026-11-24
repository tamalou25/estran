"""Keep the sources fresh: run each connector when it is due, at the pace its manifest allows."""

import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import Engine

from estran.collector.connectors import REGISTRY
from estran.collector.runner import Mode, run_connector
from estran.collector.sdk import Manifest
from estran.ontology import Ontology

logger = logging.getLogger(__name__)

FAILURE_RETRY = timedelta(minutes=15)
TICK_SECONDS = 30
HEARTBEAT_MAX_AGE_SECONDS = 120


def next_run_time(status: str, *, schedule_hours: int, now: datetime) -> datetime:
    """A healthy source is asked again after its declared period; a failed one a bit sooner."""
    period = timedelta(hours=schedule_hours)
    return now + (min(FAILURE_RETRY, period) if status == "failed" else period)


def dependents(manifests: dict[str, Manifest], source_id: str) -> list[str]:
    """Names of the connectors that build on `source_id` and must follow its changes."""
    return [name for name, manifest in manifests.items() if source_id in manifest.after]


def serve(
    engine: Engine, ontology: Ontology, *, mode: Mode, snapshot_dir: Path, heartbeat: Path
) -> None:
    """Run forever. Every connector is due at start; the heartbeat file proves the loop is alive."""
    connectors = {name: cls() for name, cls in REGISTRY.items()}
    if mode == "snapshot":
        # Offline: only the sources that ship a snapshot can be loaded.
        connectors = {n: c for n, c in connectors.items() if c.manifest.snapshot}
    manifests = {name: connector.manifest for name, connector in connectors.items()}
    due = {name: datetime.now(UTC) for name in connectors}
    forced: set[str] = set()
    while True:
        # Registry order matters: a source runs before the ones that build on it.
        for name, connector in connectors.items():
            if datetime.now(UTC) < due[name]:
                continue
            try:
                status = run_connector(
                    engine,
                    ontology,
                    connector,
                    mode=mode,
                    snapshot_dir=snapshot_dir,
                    force=name in forced,
                ).status
            except Exception:
                logger.exception("%s: unexpected error, will retry", name)
                status = "failed"
            forced.discard(name)
            due[name] = next_run_time(
                status, schedule_hours=connector.manifest.schedule_hours, now=datetime.now(UTC)
            )
            if status == "success":
                # New or changed objects: what builds on them is applied again, in full.
                for dependent in dependents(manifests, connector.manifest.id):
                    due[dependent] = datetime.now(UTC)
                    forced.add(dependent)
        heartbeat.touch()
        time.sleep(TICK_SECONDS)


def is_alive(heartbeat: Path) -> bool:
    try:
        return time.time() - heartbeat.stat().st_mtime < HEARTBEAT_MAX_AGE_SECONDS
    except OSError:
        return False
