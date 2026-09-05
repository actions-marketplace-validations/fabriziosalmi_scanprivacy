"""How much of the machine one caller may occupy.

A scan launches a Chromium and the result — observation included — was kept in
a module-level dict for the lifetime of the process. Neither limit needed an
attacker to become a problem: a well-meaning script with a list of domains
would exhaust both.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import scanprivacy.api as api


@pytest.fixture(autouse=True)
def clean_store():
    api._SCANS.clear()
    yield
    api._SCANS.clear()


def _entry(status: str, persisted: bool = True) -> dict:
    # `persisted` is part of the contract: eviction is only safe because the
    # result is already on disk, so an entry that was never written is not
    # eligible however old it is.
    return {"status": status, "url": "https://x.it/", "created_at": "", "result": None,
            "error": None, "persisted": persisted}


# --------------------------------------------------------------- in flight


def test_a_flood_of_submissions_is_refused_rather_than_accepted(monkeypatch):
    """Accepting work the service cannot do is worse than refusing it: the
    caller gets an id, polls it, and watches the machine fall over."""
    monkeypatch.setattr(api, "MAX_SCANS_IN_FLIGHT", 3)
    for i in range(3):
        api._SCANS[f"queued{i}"] = _entry("queued")

    with TestClient(api.app) as client:
        response = client.post("/v1/scans", json={"url": "https://example.org/"})
    assert response.status_code == 429
    assert response.headers.get("retry-after") == "30"


def test_finished_scans_do_not_count_against_the_ceiling(monkeypatch):
    """The limit is on work in progress, not on history, or a busy day would
    permanently close the service."""
    monkeypatch.setattr(api, "MAX_SCANS_IN_FLIGHT", 3)
    for i in range(20):
        api._SCANS[f"done{i}"] = _entry("done")

    with TestClient(api.app) as client:
        response = client.post("/v1/scans", json={"url": "https://example.org/"})
    assert response.status_code == 202


# ---------------------------------------------------------------- eviction


def test_the_store_stops_growing(monkeypatch):
    monkeypatch.setattr(api, "SCAN_RETENTION", 10)
    for i in range(25):
        api._SCANS[f"done{i}"] = _entry("done")
        api._evict_if_needed()
    assert len(api._SCANS) <= 10


def test_eviction_drops_the_oldest_first(monkeypatch):
    monkeypatch.setattr(api, "SCAN_RETENTION", 3)
    for name in ("a", "b", "c", "d", "e"):
        api._SCANS[name] = _entry("done")
        api._evict_if_needed()
    assert list(api._SCANS) == ["c", "d", "e"]


def test_unfinished_work_is_never_evicted(monkeypatch):
    """The caller is still holding an id we told them to poll. Dropping it
    would answer 404 for a scan that is running right now."""
    monkeypatch.setattr(api, "SCAN_RETENTION", 2)
    api._SCANS["still_running"] = _entry("running")
    for i in range(10):
        api._SCANS[f"done{i}"] = _entry("done")
        api._evict_if_needed()
    assert "still_running" in api._SCANS


def test_the_concurrency_ceiling_is_a_real_semaphore():
    """Not merely a counter someone forgot to await on."""
    import asyncio

    assert isinstance(api._SCAN_SLOTS, asyncio.Semaphore)
    assert api.MAX_CONCURRENT_SCANS >= 1


def test_a_result_that_was_never_written_is_not_evicted(monkeypatch):
    """Eviction trades memory for disk. If the write failed, dropping the entry
    destroys the only copy — so the store is allowed to exceed its bound rather
    than lose evidence, and says so in the log."""
    monkeypatch.setattr(api, "SCAN_RETENTION", 2)
    api._SCANS["unwritten"] = _entry("done", persisted=False)
    for i in range(10):
        api._SCANS[f"done{i}"] = _entry("done")
        api._evict_if_needed()
    assert "unwritten" in api._SCANS


def test_persist_reports_whether_it_succeeded(tmp_path, monkeypatch):
    """It used to swallow OSError and return nothing, which was defensible
    until eviction started relying on it."""
    from scanprivacy.core.enums import ScanStatus
    from scanprivacy.core.models import ScanResult

    result = ScanResult(scan_id="p1", url="https://x.it/", final_url="https://x.it/",
                        started_at="", finished_at="", status=ScanStatus.OK)

    monkeypatch.setattr(api, "SCANS_DIR", tmp_path / "scans")
    assert api._persist(result) is True
    assert (tmp_path / "scans" / "p1.json").exists()

    # a directory where the file should go: the write cannot succeed
    blocked = tmp_path / "blocked"
    (blocked / "p1.json").mkdir(parents=True)
    monkeypatch.setattr(api, "SCANS_DIR", blocked)
    assert api._persist(result) is False
