"""Behaviour that the first public audit found missing, each held by a test
that fails when the fix is taken out.

The scenarios are the ones from the audit: a scan id that stopped existing when
it left memory, a failed target reported as cached, a rule that raised and left
the grade looking clean, and a rate limit that did not cover every request.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scanprivacy import api, batch
from scanprivacy.analyze import predicates
from scanprivacy.analyze.context import Context
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


# ------------------------------------------------- limits, limiter, rules cache


def test_a_limit_below_its_minimum_is_refused_by_name(monkeypatch):
    from scanprivacy.config import ConfigError, env_int

    monkeypatch.setenv("SCANPRIVACY_MAX_CONCURRENT_SCANS", "0")
    with pytest.raises(ConfigError, match="SCANPRIVACY_MAX_CONCURRENT_SCANS=0"):
        env_int("SCANPRIVACY_MAX_CONCURRENT_SCANS", 3)
    monkeypatch.setenv("SCANPRIVACY_MAX_CONCURRENT_SCANS", "many")
    with pytest.raises(ConfigError, match="not an integer"):
        env_int("SCANPRIVACY_MAX_CONCURRENT_SCANS", 3)
    monkeypatch.delenv("SCANPRIVACY_MAX_CONCURRENT_SCANS")
    assert env_int("SCANPRIVACY_MAX_CONCURRENT_SCANS", 3) == 3


def test_serve_reports_a_bad_limit_by_name_and_exits(monkeypatch, capsys):
    import sys

    import scanprivacy
    from scanprivacy import cli

    # Importing the app is what reads the limits, so it has to be imported afresh;
    # monkeypatch puts the original module back, and a second copy left in
    # sys.modules would make later tests talk to a different `api`.
    monkeypatch.setattr(scanprivacy, "api", api)
    monkeypatch.delitem(sys.modules, "scanprivacy.api")
    monkeypatch.setenv("SCANPRIVACY_MAX_SCANS_IN_FLIGHT", "0")
    args = type("A", (), {"host": "127.0.0.1", "port": 1})()
    assert cli._cmd_serve(args) == 2
    assert "SCANPRIVACY_MAX_SCANS_IN_FLIGHT=0" in capsys.readouterr().err


def test_a_wait_on_one_host_does_not_hold_up_another():
    async def go():
        limiter = PerHostLimiter(2.0)  # 0.5 s between requests to one host
        await limiter.wait("slow.example")
        started = asyncio.get_running_loop().time()
        slow = asyncio.create_task(limiter.wait("slow.example"))  # must wait ~0.5 s
        await asyncio.sleep(0)
        await limiter.wait("other.example")  # a different host: immediate
        elapsed_other = asyncio.get_running_loop().time() - started
        await slow
        return elapsed_other

    assert asyncio.run(go()) < 0.2


def test_the_same_host_is_still_spaced():
    async def go():
        limiter = PerHostLimiter(10.0)
        loop = asyncio.get_running_loop()
        times = []
        for _ in range(3):
            await limiter.wait("a.example")
            times.append(loop.time())
        return times

    t = asyncio.run(go())
    assert t[1] - t[0] >= 0.09 and t[2] - t[1] >= 0.09


def test_the_rules_are_parsed_once_and_an_edit_is_still_seen(tmp_path):
    from scanprivacy.analyze import engine

    body = "id: PM-X-01\nseverity: low\nsubject: site\ncondition: {a: 1}\n"
    (tmp_path / "PM-X-01.yml").write_text(body, encoding="utf-8")
    first = engine.load_rules(tmp_path)
    assert engine.load_rules(tmp_path)[0] is first[0], "parsed again instead of cached"
    (tmp_path / "PM-X-01.yml").write_text(body.replace("low", "high"), encoding="utf-8")
    assert engine.load_rules(tmp_path)[0].severity.value == "high"


def test_unpersisted_results_stay_but_do_not_block_eviction_of_the_rest(monkeypatch):
    monkeypatch.setattr(api, "SCAN_RETENTION", 2)
    monkeypatch.setattr(api, "_SCANS", api.OrderedDict())
    api._SCANS["a"] = {"status": "done", "persisted": False}
    for name in "bcd":
        api._SCANS[name] = {"status": "done", "persisted": True}
    api._evict_if_needed()
    assert list(api._SCANS) == ["a", "d"]


def test_new_scans_are_refused_while_results_cannot_be_stored(scans_dir, monkeypatch):
    monkeypatch.setattr(api, "_storage_writable", lambda: False)
    monkeypatch.setattr(api, "check_public_target", lambda url: None)
    response = TestClient(api.app).post("/v1/scans", json={"url": "https://example.org/"})
    assert response.status_code == 503


def test_a_budget_timeout_is_logged_and_carries_a_reference(scans_dir, monkeypatch, caplog):
    async def slow_scan(*args, **kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(api, "scan", slow_scan)
    monkeypatch.setattr(api, "API_SETTINGS", api.replace(api.API_SETTINGS, per_scan_budget_s=0.05))
    monkeypatch.setattr(api, "DEFAULTS", api.replace(api.DEFAULTS, per_scan_budget_s=0.05))
    api._SCANS["abcdef000001"] = {"status": "running", "url": "https://example.org/"}
    with caplog.at_level("WARNING", logger="scanprivacy.api"):
        asyncio.run(api._observe("abcdef000001", api.ScanRequest(url="https://example.org/")))
    entry = api._SCANS["abcdef000001"]
    assert entry["status"] == "error" and entry["error_ref"] == "abcdef000001"
    assert "exceeded its budget" in caplog.text


# ------------------------------------------------------------ stored scan JSON


def test_stored_scans_carry_a_schema_version_and_old_ones_still_load():
    from scanprivacy.core.models import SCHEMA_VERSION, scan_from_dict

    result = ScanResult(
        scan_id="abcdef012345", url="https://e.org/", final_url="https://e.org/",
        started_at="t0", finished_at="t1", status=ScanStatus.OK, verdict=grade([], observed_ok=True),
    )
    data = result.to_dict()
    assert data["schema_version"] == SCHEMA_VERSION
    legacy = {k: v for k, v in data.items() if k != "schema_version"}
    assert scan_from_dict(legacy).scan_id == "abcdef012345"


def test_a_file_from_a_newer_version_is_refused_not_misread():
    from scanprivacy.core.models import scan_from_dict

    result = ScanResult(
        scan_id="abcdef012345", url="https://e.org/", final_url="https://e.org/",
        started_at="t0", finished_at="t1", status=ScanStatus.OK, verdict=grade([], observed_ok=True),
    )
    data = {**result.to_dict(), "schema_version": 999}
    with pytest.raises(ValueError, match="schema_version"):
        scan_from_dict(data)


def test_an_unknown_severity_is_not_read_as_info():
    from scanprivacy.core.models import finding_from_dict

    with pytest.raises(ValueError, match="unknown severity"):
        finding_from_dict({"id": "x", "rule_id": "PM-X-01", "severity": "catastrophic"})


def test_a_scan_that_outlives_its_budget_stops_the_command(monkeypatch, capsys):
    from dataclasses import replace

    from scanprivacy import cli

    async def never(*args, **kwargs):
        await asyncio.sleep(30)

    settings = replace(cli.DEFAULTS, per_scan_budget_s=0.05, max_pages=1)
    with pytest.raises(TimeoutError):
        cli._within_budget(never(), settings)
    monkeypatch.setattr(cli, "_cmd_scan", lambda args: cli._within_budget(never(), settings))
    assert cli._run(cli._cmd_scan, object()) == 4
    assert "budget" in capsys.readouterr().err


def test_shutdown_marks_scans_that_were_still_running(scans_dir):
    api._SCANS["abcdef000002"] = {"status": "running", "url": "https://example.org/"}
    with TestClient(api.app):
        pass  # entering and leaving runs the lifespan
    assert api._SCANS["abcdef000002"]["status"] == "error"
    assert api._SCANS["abcdef000002"]["error_ref"] == "abcdef000002"


def test_the_data_directory_can_be_named(tmp_path):
    from scanprivacy.config import data_dir_from

    assert data_dir_from({"SCANPRIVACY_DATA_DIR": str(tmp_path / "results")}) == tmp_path / "results"
    assert data_dir_from({"SCANPRIVACY_DATA_DIR": "  "}) == Path.cwd() / "data"
    assert data_dir_from({}) == Path.cwd() / "data"


def test_every_api_scan_shares_one_host_limiter(scans_dir, monkeypatch):
    seen: list = []

    async def fake_scan(url, settings, **kwargs):
        seen.append(kwargs.get("limiter"))
        raise RuntimeError("stop here")

    monkeypatch.setattr(api, "scan", fake_scan)
    for n in ("abcdef000010", "abcdef000011"):
        api._SCANS[n] = {"status": "running", "url": "https://example.org/"}
        asyncio.run(api._observe(n, api.ScanRequest(url="https://example.org/")))
    assert seen == [api._HOST_LIMITER, api._HOST_LIMITER]


def test_serve_refuses_an_unknown_log_level(monkeypatch, capsys):
    from scanprivacy import cli

    monkeypatch.setenv("SCANPRIVACY_LOG_LEVEL", "LOUD")
    args = type("A", (), {"host": "127.0.0.1", "port": 1})()
    assert cli._cmd_serve(args) == 2
    assert "SCANPRIVACY_LOG_LEVEL" in capsys.readouterr().err


# --------------------------------------- persistence, pending scans, no-key guard


def test_a_write_that_fails_midway_leaves_no_truncated_result(scans_dir, monkeypatch):
    scan_id = _stored(scans_dir)
    before = (scans_dir / f"{scan_id}.json").read_text(encoding="utf-8")

    def broken_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(api.os, "replace", broken_replace)
    newer = ScanResult(
        scan_id=scan_id, url="https://example.org/changed", final_url="https://example.org/changed",
        started_at="t0", finished_at="t1", status=ScanStatus.OK, verdict=grade([], observed_ok=True),
    )
    assert api._persist(newer) is False
    assert (scans_dir / f"{scan_id}.json").read_text(encoding="utf-8") == before
    assert [p.name for p in scans_dir.iterdir()] == [f"{scan_id}.json"], "a temporary file was left behind"


def test_an_accepted_scan_that_never_finished_reads_as_an_error_after_a_restart(scans_dir, monkeypatch):
    monkeypatch.setattr(api, "check_public_target", lambda url: None)
    monkeypatch.setattr(api, "_run", lambda scan_id, request: asyncio.sleep(0))
    client = TestClient(api.app)
    response = client.post("/v1/scans", json={"url": "https://example.org/"})
    scan_id = response.json()["scan_id"]
    api._SCANS.clear()  # a new process: nothing in memory
    body = client.get(f"/v1/scans/{scan_id}").json()
    assert body["status"] == "error"
    assert body["error_ref"] == scan_id


def test_a_stored_result_whose_evidence_was_altered_is_refused(scans_dir):
    from scanprivacy.report.record import build_record

    result = ScanResult(
        scan_id="abcdef012345", url="https://e.org/", final_url="https://e.org/",
        started_at="t0", finished_at="t1", status=ScanStatus.OK, verdict=grade([], observed_ok=True),
        observation={"browser": {"requests": []}},
    )
    result.record = build_record(url=result.url, observation=result.observation, findings=[])
    assert api._persist(result)
    client = TestClient(api.app)
    assert client.get("/v1/scans/abcdef012345").status_code == 200

    path = scans_dir / "abcdef012345.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["observation"]["browser"]["requests"] = [{"url": "https://tampered.example/"}]
    path.write_text(json.dumps(data), encoding="utf-8")
    assert client.get("/v1/scans/abcdef012345").status_code == 500


def test_without_a_key_only_a_local_caller_is_accepted(monkeypatch):
    monkeypatch.delenv("SCANPRIVACY_API_KEY", raising=False)
    remote = TestClient(api.app, client=("203.0.113.9", 4000))
    assert remote.get("/v1/rules").status_code == 403
    local = TestClient(api.app, client=("127.0.0.1", 4000))
    assert local.get("/v1/rules").status_code == 200
    assert remote.get("/healthz").status_code in (200, 503)  # liveness stays open


def test_oversized_request_fields_are_refused(scans_dir, monkeypatch):
    monkeypatch.setattr(api, "check_public_target", lambda url: None)
    client = TestClient(api.app)
    assert client.post("/v1/scans", json={"url": "https://example.org/" + "a" * 3000}).status_code == 422
    big = {"note": "x" * 9000}
    assert client.post("/v1/scans", json={"url": "https://example.org/", "context": big}).status_code == 422


def test_targets_that_differ_only_by_query_do_not_share_a_result_file():
    assert batch._slug("https://example.org/page?a=1") != batch._slug("https://example.org/page?a=2")
    assert batch._slug("https://example.org/a/b") != batch._slug("https://example.org/a-b")
    assert batch._slug("https://example.org/a") == batch._slug("https://example.org/a")


def test_the_runtime_lock_is_a_subset_of_the_development_lock():
    import re

    root = Path(__file__).resolve().parents[1]

    def pins(name: str) -> dict[str, str]:
        text = (root / name).read_text(encoding="utf-8")
        return dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", text, re.M))

    full, runtime = pins("requirements.lock"), pins("requirements.runtime.lock")
    assert runtime and set(runtime) <= set(full)
    assert {k: v for k, v in runtime.items() if full[k] != v} == {}, "the two locks disagree"
    for development_only in ("pytest", "ruff", "coverage", "markdown"):
        assert development_only not in runtime


def test_the_image_and_the_action_install_from_the_runtime_lock():
    root = Path(__file__).resolve().parents[1]
    assert "requirements.runtime.lock" in (root / "Dockerfile").read_text(encoding="utf-8")
    action = (root / "action.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in action and "requirements.runtime.lock" in action


# ------------------------------------------------------------ report rendering


def test_a_report_loads_no_remote_resource():
    from scanprivacy.report.pdf import check_resource

    for url in ("http://127.0.0.1:9/x.png", "https://example.org/a.css", "ftp://example.org/x", "file:///etc/passwd"):
        with pytest.raises(ValueError, match="no remote resources"):
            check_resource(url)


def test_the_report_stylesheet_and_inline_data_are_still_allowed():
    from scanprivacy.report.pdf import TEMPLATES, check_resource

    check_resource((TEMPLATES / "base.css").as_uri())
    check_resource("data:image/png;base64,AAAA")


def test_the_fetcher_refuses_a_remote_url_before_any_connection(tmp_path):
    from scanprivacy.report.pdf import local_only_fetcher

    try:
        fetcher = local_only_fetcher()
    except OSError:
        pytest.skip("WeasyPrint's system libraries are not installed here")
    with pytest.raises(ValueError):
        fetcher.fetch("http://127.0.0.1:9/never")


def test_the_declared_weasyprint_floor_excludes_the_advisory_range():
    import re

    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"weasyprint>=(\d+)', text)
    assert match and int(match.group(1)) >= 70, "versions below 70 have a published SSRF advisory"
