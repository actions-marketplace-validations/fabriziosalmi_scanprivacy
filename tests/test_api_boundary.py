"""Request values that reach a filesystem path or the network.

`Translator.for_locale` falls back to the default for anything it does not
recognise and raises nothing. That is right for rendering — a reader asking
for a language this build cannot produce should still get a report — and wrong
for a value that is also used to build a filename, because then an unknown
locale is not a fallback but a destination.
"""

from __future__ import annotations


import pytest
from fastapi.testclient import TestClient

from scanprivacy.api import _SCANS, app
from scanprivacy.config import SCANS_DIR


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def finished_scan():
    """A completed scan in the store, so the report endpoints are reachable."""
    from tests.test_integrations import _result

    result = _result()
    _SCANS[result.scan_id] = {
        "status": "done",
        "url": result.url,
        "created_at": "2026-01-01T00:00:00Z",
        "result": result,
        "error": None,
    }
    yield result.scan_id
    _SCANS.pop(result.scan_id, None)


# ------------------------------------------------------- locale as a path


@pytest.mark.parametrize(
    "lang",
    [
        "../PWNED",
        "../../../PWNED",
        "../../../../../../tmp/pwned",
        "..%2f..%2fpwned",
        "/etc/passwd",
        "en/../../x",
    ],
)
def test_a_traversing_locale_is_refused_before_anything_is_written(client, finished_scan, lang):
    """Proven against the running service before this guard existed: a GET with
    lang=../../../PWNED returned 200 and left a 230KB PDF outside SCANS_DIR."""
    before = set(SCANS_DIR.glob("**/*")) if SCANS_DIR.exists() else set()

    response = client.get(f"/v1/scans/{finished_scan}/report.pdf", params={"lang": lang})
    assert response.status_code == 400
    assert "unknown locale" in response.json()["detail"] or "invalid" in response.json()["detail"]

    after = set(SCANS_DIR.glob("**/*")) if SCANS_DIR.exists() else set()
    assert after == before, "the request created files despite being refused"


def test_the_same_guard_applies_to_markdown_and_to_the_rule_catalogue(client, finished_scan):
    """Not only the endpoint that writes a file. A locale that does not exist
    is a client error everywhere, or the API answers differently depending on
    which endpoint you ask."""
    assert client.get(f"/v1/scans/{finished_scan}/report", params={"lang": "../x"}).status_code == 400
    assert client.get("/v1/rules", params={"lang": "../x"}).status_code == 400


def test_a_known_locale_still_works(client, finished_scan):
    response = client.get(f"/v1/scans/{finished_scan}/report", params={"lang": "it"})
    assert response.status_code == 200
    assert response.text.strip()


# ------------------------------------------------------------ target guard


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:9/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/"],
)
def test_the_api_refuses_a_target_it_should_not_fetch(client, url):
    response = client.post("/v1/scans", json={"url": url, "read_documents": False})
    assert response.status_code == 403
    assert "target refused" in response.json()["detail"]


def test_a_malformed_url_is_a_client_error_not_a_scan(client):
    response = client.post("/v1/scans", json={"url": "not-a-url"})
    assert response.status_code == 400


# --------------------------------------------------------- error exposure


def test_a_failed_scan_does_not_hand_its_cause_to_the_client(client):
    """An exception's text carries filesystem paths and module layout. The
    client gets a reference; the cause goes to the log."""
    api = __import__("scanprivacy.api", fromlist=["_SCANS"])
    api._SCANS["boom"] = {
        "status": "error",
        "url": "https://x.it/",
        "created_at": "",
        "result": None,
        "error": "the scan did not complete",
        "error_ref": "boom",
        "error_detail": "FileNotFoundError: /Users/fab/secret/path/config.yml",
    }
    try:
        body = client.get("/v1/scans/boom").json()
        assert body["error"] == "the scan did not complete"
        assert body["error_ref"] == "boom"
        assert "error_detail" not in body
        assert "/Users/fab" not in str(body)
    finally:
        api._SCANS.pop("boom", None)
