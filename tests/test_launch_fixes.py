"""Behaviour that the first public audit found missing, each held by a test
that fails when the fix is taken out.

The scenarios are the ones from the audit: a scan id that stopped existing when
it left memory, a failed target reported as cached, a rule that raised and left
the grade looking clean, and a rate limit that did not cover every request.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scanprivacy import api, batch
from scanprivacy.analyze import predicates
from scanprivacy.analyze.context import Context
from scanprivacy.analyze.engine import evaluate
from scanprivacy.analyze.verdict import grade
from scanprivacy.core.enums import Grade, ScanStatus
from scanprivacy.core.models import ScanResult
from scanprivacy.observe.browser import Observation
from scanprivacy.observe.rate import PerHostLimiter


# ---------------------------------------------------------------- read-back


@pytest.fixture
def scans_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "SCANS_DIR", tmp_path)
    monkeypatch.setattr(api, "_SCANS", api.OrderedDict())
    monkeypatch.delenv("SCANPRIVACY_API_KEY", raising=False)
    return tmp_path


def _stored(scans_dir: Path, scan_id: str = "abcdef012345") -> str:
    result = ScanResult(
        scan_id=scan_id,
        url="https://example.org/",
        final_url="https://example.org/",
        started_at="t0",
        finished_at="t1",
        status=ScanStatus.OK,
        verdict=grade([], observed_ok=True),
    )
    assert api._persist(result)
    return scan_id


def test_a_scan_that_left_memory_is_served_from_disk(scans_dir):
    scan_id = _stored(scans_dir)
    assert scan_id not in api._SCANS  # a restart, or an eviction
    response = TestClient(api.app).get(f"/v1/scans/{scan_id}")
    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_an_id_that_was_never_issued_is_still_unknown(scans_dir):
    client = TestClient(api.app)
    assert client.get("/v1/scans/ffffffffffff").status_code == 404
    # the id is matched against the issued shape before it can reach a path
    assert client.get("/v1/scans/..%2F..%2Fetc%2Fpasswd").status_code == 404


def test_a_stored_result_that_cannot_be_read_is_not_reported_as_unknown(scans_dir):
    (scans_dir / "abcdef012345.json").write_text("{not json", encoding="utf-8")
    assert TestClient(api.app).get("/v1/scans/abcdef012345").status_code == 500


def test_healthz_says_so_when_results_cannot_be_stored(scans_dir, monkeypatch):
    client = TestClient(api.app)
    assert client.get("/healthz").status_code == 200
    monkeypatch.setattr(api, "_storage_writable", lambda: False)
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["ok"] is False


# -------------------------------------------------------------- batch resume


def test_a_failed_target_is_retried_not_reported_as_cached(tmp_path, monkeypatch):
    url = "https://example.org/"
    failure = {"scan_id": "", "url": url, "status": ScanStatus.ERROR.value, "error": "boom", "verdict": None}
    (tmp_path / f"{batch._slug(url)}.json").write_text(json.dumps(failure), encoding="utf-8")

    calls: list[str] = []

    async def fake_scan(target, settings, limiter=None):
        calls.append(target)
        raise RuntimeError("still down")

    monkeypatch.setattr(batch, "scan", fake_scan)
    results, _ = asyncio.run(batch.run_batch([url], tmp_path))
    assert calls == [url], "the failed target was not tried again"
    assert results[0]["status"] == ScanStatus.ERROR.value


def test_only_a_finished_scan_of_the_same_target_is_a_cache_hit():
    good = {"status": "ok", "url": "https://a.example/", "verdict": {"grade": "A"}}
    assert batch._is_finished_scan_of(good, "https://a.example/")
    assert not batch._is_finished_scan_of(good, "https://b.example/")
    assert not batch._is_finished_scan_of({**good, "status": "error"}, "https://a.example/")
    assert not batch._is_finished_scan_of({**good, "verdict": None}, "https://a.example/")
    assert not batch._is_finished_scan_of(["not", "a", "scan"], "https://a.example/")


# ------------------------------------------------------ rule that cannot run


def _ctx() -> Context:
    return Context(obs=Observation(url="https://example.org/", final_url="https://example.org/", load_ok=True, status=200))


def test_a_predicate_that_raises_is_recorded_on_the_context(monkeypatch):
    def boom(ctx, subject, arg):
        raise ValueError("defect in the engine")

    monkeypatch.setitem(predicates.REGISTRY, "always_boom", boom)
    ctx = _ctx()
    subject = type("S", (), {"slug": "x", "kind": "site"})()
    assert predicates.evaluate_condition(ctx, subject, {"always_boom": True}) is False
    assert ctx.rule_errors == ["always_boom: ValueError"]


def test_an_unknown_predicate_is_recorded_too():
    ctx = _ctx()
    subject = type("S", (), {"slug": "x", "kind": "site"})()
    predicates.evaluate_condition(ctx, subject, {"no_such_predicate": True})
    assert ctx.rule_errors == ["no_such_predicate: unknown predicate"]


def test_rule_errors_make_the_verdict_inconclusive_not_clean():
    from scanprivacy.scanner import _grade_evaluated

    clean = _ctx()
    assert _grade_evaluated([], True, clean).grade != Grade.INCONCLUSIVE

    broken = _ctx()
    broken.rule_errors.append("x: ValueError")
    verdict = _grade_evaluated([], True, broken)
    assert verdict.grade == Grade.INCONCLUSIVE
    assert verdict.conformant is False
    assert verdict.blocking == ("verdict.rule_error_blocking",)


def test_the_rule_error_messages_exist_in_every_locale():
    from scanprivacy.i18n.translator import Translator, available_locales

    for lang in available_locales():
        t = Translator.for_locale(lang, strict=True)
        for key in ("verdict.rule_error_note", "verdict.rule_error_blocking"):
            assert t.t(key), f"{lang} has no text for {key}"


# ------------------------------------------------------------ rate limiting


class _Boom(Exception):
    pass


class _SpyLimiter(PerHostLimiter):
    def __init__(self, events: list[str]) -> None:
        super().__init__(1.0)
        self.events = events

    async def wait(self, host: str) -> None:
        self.events.append(f"wait:{host}")


class _Page:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def goto(self, url, **_):
        self.events.append(f"goto:{url}")
        raise _Boom

    async def content(self):
        return ""

    async def wait_for_timeout(self, _):
        return None

    async def close(self):
        return None


class _Context:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def new_page(self):
        return _Page(self.events)

    async def close(self):
        return None


class _Browser:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def new_context(self, **_):
        return _Context(self.events)


def test_the_document_fetch_waits_for_the_host_budget_before_it_loads():
    from scanprivacy.observe import docs

    events: list[str] = []
    evidence = asyncio.run(
        docs.fetch_document(
            _Browser(events), "https://example.org/privacy", "privacy", limiter=_SpyLimiter(events)
        )
    )
    assert events == ["wait:example.org", "goto:https://example.org/privacy"]
    assert evidence.ok is False  # the goto was made to fail; only the order is under test


def test_the_refusal_pass_waits_before_each_of_its_page_loads(monkeypatch):
    from scanprivacy.observe import consent

    events: list[str] = []

    async def fake_observe(context, url, settings):
        events.append(f"observe:{url}")
        return Observation(url=url, final_url=url, load_ok=True, status=200, cmp_detected=["X"])

    async def fake_new_context(browser, user_agent, settings=None):
        return _Context(events)

    monkeypatch.setattr(consent, "observe_in_context", fake_observe)
    monkeypatch.setattr(consent, "new_context", fake_new_context)
    monkeypatch.setattr(consent, "load_catalogue", lambda: [])
    with pytest.raises(_Boom):
        asyncio.run(
            consent.run_refusal_pass(_Browser(events), "https://example.org/", limiter=_SpyLimiter(events))
        )
    assert events[:3] == ["wait:example.org", "observe:https://example.org/", "wait:example.org"]
