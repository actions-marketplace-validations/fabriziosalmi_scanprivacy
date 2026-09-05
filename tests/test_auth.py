"""Who may ask this service to observe something.

An open instance is not merely a resource a stranger can consume. The engine
identifies itself with a User-Agent naming the operator and their contact
address, so requests it makes arrive at third-party sites *in the operator's
name*, and the recipient has no way to tell the operator did not send them.

The rule is therefore mechanical: no key means loopback only, enforced at
startup. A warning would be read once and then not read again.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

import pmate.api as api
from pmate.auth import ENV_VAR, UnsafeBind, assert_bind_is_safe

GOOD_KEY = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def no_key(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    api._SCANS.clear()
    yield
    api._SCANS.clear()


# ------------------------------------------------------------ startup rule


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_without_a_key_is_allowed(host):
    assert_bind_is_safe(host)  # does not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "", "192.168.1.10", "10.0.0.4", "example.org"])
def test_any_other_bind_without_a_key_is_refused(host):
    """0.0.0.0 and the empty host both mean every interface — the case this
    exists to catch."""
    with pytest.raises(UnsafeBind) as unsafe:
        assert_bind_is_safe(host)
    assert ENV_VAR in str(unsafe.value)


def test_a_key_permits_any_bind(monkeypatch):
    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    assert_bind_is_safe("0.0.0.0")


def test_a_short_key_is_refused_rather_than_accepted(monkeypatch):
    """A four-character key is worse than none: it looks like protection."""
    monkeypatch.setenv(ENV_VAR, "abc")
    with pytest.raises(UnsafeBind) as unsafe:
        assert_bind_is_safe("0.0.0.0")
    assert "characters" in str(unsafe.value)


def test_whitespace_is_not_a_key(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "   ")
    with pytest.raises(UnsafeBind):
        assert_bind_is_safe("0.0.0.0")


# --------------------------------------------------------- request handling


def test_without_a_key_configured_the_routes_are_open(monkeypatch):
    """Only reachable on loopback, because the bind check refused otherwise."""
    with TestClient(api.app) as client:
        assert client.get("/v1/locales").status_code == 200


def test_with_a_key_configured_an_unauthenticated_call_is_refused(monkeypatch):
    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    with TestClient(api.app) as client:
        response = client.get("/v1/locales")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize(
    "headers",
    [
        {"X-API-Key": GOOD_KEY},
        {"Authorization": f"Bearer {GOOD_KEY}"},
    ],
)
def test_either_accepted_form_of_the_credential_works(monkeypatch, headers):
    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    with TestClient(api.app) as client:
        assert client.get("/v1/locales", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {"X-API-Key": GOOD_KEY + "x"},          # too long
        {"X-API-Key": GOOD_KEY[:-1]},           # too short
        {"X-API-Key": "0" * len(GOOD_KEY)},     # right length, wrong value
        {"Authorization": f"Basic {GOOD_KEY}"},  # wrong scheme
        {"Authorization": GOOD_KEY},             # no scheme
    ],
)
def test_a_wrong_credential_is_refused_in_every_shape(monkeypatch, headers):
    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    with TestClient(api.app) as client:
        assert client.get("/v1/locales", headers=headers).status_code == 401


def test_every_v1_route_is_covered_not_only_the_obvious_ones(monkeypatch):
    """A route added later without the dependency is the way this regresses,
    so the test enumerates the app rather than a hand-written list."""
    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    # `route.dependencies` holds what was declared; `route.dependant` holds what
    # will actually run. The second is the one that answers the question.
    unprotected = []
    checked = 0
    for route in api.app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/v1"):
            continue
        checked += 1
        dependant = getattr(route, "dependant", None)
        names = {
            getattr(d.call, "__name__", "") for d in (dependant.dependencies if dependant else [])
        }
        if "require_api_key" not in names:
            unprotected.append(path)
    assert checked >= 9, "the enumeration found no routes — it would pass vacuously"
    assert unprotected == [], f"/v1 routes without authentication: {unprotected}"


def test_healthz_stays_open_and_says_which_posture_is_in_force(monkeypatch):
    with TestClient(api.app) as client:
        assert client.get("/healthz").json()["authentication"] == "none"

    monkeypatch.setenv(ENV_VAR, GOOD_KEY)
    with TestClient(api.app) as client:
        body = client.get("/healthz").json()
    assert body["ok"] is True
    assert body["authentication"] == "api-key"
    assert GOOD_KEY not in str(body)


def test_healthz_carries_the_agpl_source_offer(monkeypatch):
    """Section 13. Whoever reaches this instance over a network is owed its
    source, and the only endpoint every such caller can already read is this
    one. An operator running a modified build owes their users *their* source."""
    from pmate import config

    with TestClient(api.app) as client:
        body = client.get("/healthz").json()
    assert body["licence"] == "AGPL-3.0-only"
    assert body["source"] == config.SOURCE_URL_DEFAULT
    assert body["source"].startswith("https://")

    monkeypatch.setenv("PMATE_SOURCE_URL", "https://git.example.org/fork")
    importlib.reload(config)
    importlib.reload(api)
    try:
        with TestClient(api.app) as client:
            assert client.get("/healthz").json()["source"] == "https://git.example.org/fork"
    finally:
        monkeypatch.delenv("PMATE_SOURCE_URL")
        importlib.reload(config)
        importlib.reload(api)
