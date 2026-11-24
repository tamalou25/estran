from datetime import UTC, datetime, timedelta

from estran.collector.scheduler import FAILURE_RETRY, next_run_time

NOW = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)


def test_successful_source_is_asked_again_after_its_declared_period():
    assert next_run_time("success", schedule_hours=6, now=NOW) == NOW + timedelta(hours=6)


def test_unchanged_source_waits_the_same_period():
    assert next_run_time("unchanged", schedule_hours=6, now=NOW) == NOW + timedelta(hours=6)


def test_failed_source_is_retried_sooner_but_not_hammered():
    retry = next_run_time("failed", schedule_hours=6, now=NOW)

    assert retry == NOW + FAILURE_RETRY
    assert timedelta(minutes=5) <= FAILURE_RETRY < timedelta(hours=6)


def test_retry_never_comes_sooner_than_the_declared_period_allows():
    assert next_run_time("failed", schedule_hours=1, now=NOW) <= NOW + timedelta(hours=1)
