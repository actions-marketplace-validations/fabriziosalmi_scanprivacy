"""What the service will fetch when a stranger asks.

The engine's job is to fetch a URL, so the dangerous version of it is an
endpoint that fetches *any* URL on request: cloud metadata, an internal
dashboard, a service bound to loopback. The report then carries the answer
back out. These tests pin the boundary — and pin that the boundary exists at
the API only, because refusing localhost on the command line would break the
ordinary act of checking a site before deploying it.
"""

from __future__ import annotations

import socket

import pytest

from scanprivacy.core.target import PORTS_NOT_OBSERVED, TargetRefused, check_public_target


def _resolver(*addresses: str):
    """A stand-in for getaddrinfo, so the tests do not depend on DNS."""

    def resolve(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]

    return resolve


# ------------------------------------------------------------------ refused


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/",
        "http://localhost:8000/",  # resolves to loopback
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://10.0.0.5/admin",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://0.0.0.0/",
    ],
)
def test_private_and_loopback_targets_are_refused(url):
    with pytest.raises(TargetRefused):
        check_public_target(url)


def test_a_public_name_resolving_to_metadata_is_refused():
    """The whole technique: the name looks fine, the address does not.
    Checking the string instead of the resolution would let this through."""
    with pytest.raises(TargetRefused) as refused:
        check_public_target("https://totally-normal.example/", resolver=_resolver("169.254.169.254"))
    assert refused.value.reason == "not_a_public_address"


def test_one_private_address_among_several_refuses_the_whole_name():
    """Which address the browser picks is not ours to predict, so a name that
    can land on a private range is refused even when it can also land on a
    public one."""
    with pytest.raises(TargetRefused):
        check_public_target("https://mixed.example/", resolver=_resolver("93.184.216.34", "10.0.0.7"))


@pytest.mark.parametrize("port", sorted(PORTS_NOT_OBSERVED)[:5])
def test_ports_that_never_serve_a_web_page_are_refused(port):
    """Observing them would be a port scan wearing a report as a disguise."""
    with pytest.raises(TargetRefused) as refused:
        check_public_target(f"http://93.184.216.34:{port}/", resolver=_resolver("93.184.216.34"))
    assert refused.value.reason == "port_not_observed"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/", "ftp://x/", "//x/"])
def test_only_http_and_https_are_accepted(url):
    with pytest.raises(TargetRefused):
        check_public_target(url)


def test_a_name_that_does_not_resolve_is_refused_rather_than_attempted():
    def fail(*a, **kw):
        raise socket.gaierror("nodename nor servname provided")

    with pytest.raises(TargetRefused) as refused:
        check_public_target("https://nothing.invalid/", resolver=fail)
    assert refused.value.reason == "does_not_resolve"


# ------------------------------------------------------------------ allowed


def test_a_public_target_passes_and_reports_what_it_resolved_to():
    check = check_public_target("https://example.org/", resolver=_resolver("93.184.216.34"))
    assert check.host == "example.org"
    assert check.addresses == ("93.184.216.34",)


def test_a_public_literal_address_needs_no_resolution():
    check = check_public_target("https://93.184.216.34/")
    assert check.addresses == ("93.184.216.34",)


def test_an_ordinary_port_is_not_refused():
    check = check_public_target("https://example.org:8443/", resolver=_resolver("93.184.216.34"))
    assert check.host == "example.org"


# ------------------------------------------------- what actually happened


def test_a_peer_on_a_private_range_is_refused_after_the_fact():
    """The pre-flight check resolves a name and decides. Between that decision
    and the fetch the record can change, and a redirect moves the destination
    entirely — rebinding to 127.0.0.1 after a passing check is the standard way
    around a guard like this one. So the addresses the browser reports having
    reached are checked too."""
    from scanprivacy.core.target import check_observed_peers

    check_observed_peers(["93.184.216.34", "104.20.26.136"])  # public: fine

    for private in ("127.0.0.1", "10.0.0.7", "169.254.169.254", "192.168.1.1", "::1"):
        with pytest.raises(TargetRefused) as refused:
            check_observed_peers(["93.184.216.34", private])
        assert refused.value.reason == "reached_a_private_address"
        assert refused.value.detail == private


def test_an_unreported_address_is_not_treated_as_private():
    """The browser does not always report a peer — a served-from-cache response
    has none. Absent is not private, and guessing either way would be the same
    mistake this engine keeps having to fix."""
    from scanprivacy.core.target import check_observed_peers

    check_observed_peers([None, "", "93.184.216.34"])


def test_a_value_that_is_not_an_address_is_ignored_rather_than_refused():
    from scanprivacy.core.target import check_observed_peers

    check_observed_peers(["not-an-address", "93.184.216.34"])


def test_peers_are_collected_from_every_page_and_every_request():
    from scanprivacy.core.target import peers_of

    pages = [
        {"requests": [{"peer_ip": "93.184.216.34"}, {"peer_ip": None}]},
        {"requests": [{"peer_ip": "10.0.0.9"}]},
    ]
    assert peers_of(pages) == ["93.184.216.34", "10.0.0.9"]
    assert peers_of(None) == []
    assert peers_of([{"requests": None}]) == []
