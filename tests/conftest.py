"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _test_client_is_a_local_caller(monkeypatch):
    """Starlette's test client reports the caller as `testclient`, which is not a
    loopback address. With no API key configured the API accepts only local
    callers, so tests that exercise the open (loopback) posture connect as
    127.0.0.1, as a real local caller would. Tests that want another caller
    pass `client=` themselves."""
    from starlette import testclient

    original = testclient.TestClient.__init__

    def init(self, *args, **kwargs):
        kwargs.setdefault("client", ("127.0.0.1", 50000))
        original(self, *args, **kwargs)

    monkeypatch.setattr(testclient.TestClient, "__init__", init)
