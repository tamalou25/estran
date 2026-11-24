"""Keep the sources fresh: run each connector when it is due, at the pace its manifest allows."""

import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import Engine

from estran.collector.connectors import REGISTRY
from estran.collector.runner import Mode, run_connector
from estran.ontology import Ontology

logger = logging.getLogger(__name__)

FAILURE_RETRY = timedelta(minutes=15)
TICK_SECONDS = 30
HEARTBEAT_MAX_AGE_SECONDS = 120


def next_run_time(status: str, *, schedule_hours: int, now: datetime) -> datetime:
    """A healthy source is asked again after its declared period; a failed one a bit sooner."""
    period = timedelta(hours=schedule_hours)
    return now + (min(FAILURE_RETRY, period) if status == "failed" else period)


def serve(
    engine: Engine, ontology: Ontology, *, mode: Mode, snapshot_dir: Path, heartbeat: Path
) -> None:
    """Run forever. Every connector is due at start; the heartbeat file proves the loop is alive."""
    connectors = {name: cls() for name, cls in REGISTRY.items()}
    due = {name: datetime.now(UTC) for name in connectors}
    while True:
        for name, connector in connectors.items():
            if datetime.now(UTC) < due[name]:
                continue
            try:
                status = run_connector(
                    engine, ontology, connector, mode=mode, snapshot_dir=snapshot_dir
                ).status
            except Exception:
                logger.exception("%s: unexpected error, will retry", name)
                status = "failed"
            due[name] = next_run_time(
                status, schedule_hours=connector.manifest.schedule_hours, now=datetime.now(UTC)
            )
        heartbeat.touch()
        time.sleep(TICK_SECONDS)


def is_alive(heartbeat: Path) -> bool:
    try:
        return time.time() - heartbeat.stat().st_mtime < HEARTBEAT_MAX_AGE_SECONDS
    except OSError:
        return False
