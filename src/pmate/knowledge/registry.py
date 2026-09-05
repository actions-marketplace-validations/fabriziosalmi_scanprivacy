"""Host attribution, transfer classification, platform fingerprinting, ownership.

This module answers questions of fact about a network host: who operates it,
where they process, whether they touch the terminal, who has to fix it. Every
answer is a canonical value or a catalogue key — no display strings leave this
module, so the same facts render in any language.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import tldextract
import yaml

from ..core.enums import ConsentClass, DataType, Owner, TransferScope, VendorCategory
from ..i18n.translator import LOCALES_DIR, available_locales

_HERE = Path(__file__).resolve().parent

# ccTLDs of EEA member states (EU plus Iceland, Liechtenstein, Norway) and .eu.
EEA_CCTLDS: frozenset[str] = frozenset(
    {
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr",
        "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk",
        "si", "es", "se", "is", "li", "no", "eu",
    }
)

# Adequacy decisions in force: a transfer here is lawful without further tooling.
ADEQUATE_CCTLDS: frozenset[str] = frozenset({"uk", "ch", "jp", "kr", "ca", "nz", "il", "uy"})

UNKNOWN_VENDOR_KEY = "unknown_third_party"


@dataclass(frozen=True, slots=True)
class VendorRemediation:
    pattern: str
    alternatives: tuple[str, ...] = ()
    extra_steps: tuple[str, ...] = ()


@dataclass(slots=True)
class Vendor:
    id: str
    product: str
    category: VendorCategory
    jurisdiction: str
    transfer: TransferScope
    storage_access: bool
    consent_class: ConsentClass
    data_types: tuple[DataType, ...]
    remediation: VendorRemediation
    vendor: str | None = None
    """Legal entity. `None` for a host we could not attribute — the display name
    then comes from the catalogue key below, because "Unidentified third party"
    is a phrase and phrases are translated."""
    vendor_key: str | None = None
    transfer_basis: str | None = None  # catalogue key: dpf | scc | dpf_scc | adequacy
    hosts: tuple[str, ...] = ()
    host_suffixes: tuple[str, ...] = ()
    known: bool = True
    response_headers_fixed: bool = False
    """The platform serves response headers nobody using it can change.

    A header finding on such a platform is true and permanently unclosable in
    place: telling the reader to "set Strict-Transport-Security" costs them an
    afternoon and leaves the finding open forever. A finding that can never be
    closed teaches people to ignore findings, so the report states the
    constraint and gives a fix that can actually be performed."""

    @property
    def extra_eea(self) -> bool:
        return self.transfer is not TransferScope.EEA

    @property
    def node_id(self) -> str:
        return f"vendor:{self.id}"


@dataclass(frozen=True, slots=True)
class Platform:
    id: str
    name: str


@dataclass(frozen=True, slots=True)
class Mapping:
    """Who closes a finding and which controls it speaks to."""

    owner: Owner
    secondary_owners: tuple[Owner, ...] = ()
    domains: tuple[str, ...] = ()
    controls: dict[str, tuple[str, ...]] = field(default_factory=dict)


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _enum(cls, value, default):
    try:
        return cls(value)
    except ValueError:
        return default


def _vendor_from_dict(v: dict[str, Any]) -> Vendor:
    rem = v.get("remediation", {}) or {}
    return Vendor(
        id=v["id"],
        vendor=v.get("vendor"),
        vendor_key=v.get("vendor_key"),
        product=v.get("product", v["id"]),
        category=_enum(VendorCategory, v.get("category"), VendorCategory.INFRA),
        jurisdiction=v.get("jurisdiction", "unknown"),
        transfer=_enum(TransferScope, v.get("transfer"), TransferScope.NON_EEA),
        transfer_basis=v.get("transfer_basis"),
        storage_access=bool(v.get("storage_access", False)),
        consent_class=_enum(ConsentClass, v.get("consent_class"), ConsentClass.UNCERTAIN),
        data_types=tuple(_enum(DataType, d, DataType.REQUEST_METADATA) for d in v.get("data_types", [])),
        remediation=VendorRemediation(
            pattern=rem.get("pattern", "identify_unknown"),
            alternatives=tuple(rem.get("alternatives", []) or []),
            extra_steps=tuple(rem.get("extra_steps", []) or []),
        ),
        hosts=tuple(h.lower() for h in v.get("hosts", []) or []),
        host_suffixes=tuple(s.lower() for s in v.get("host_suffixes", []) or []),
        response_headers_fixed=bool(v.get("response_headers_fixed", False)),
    )


@lru_cache(maxsize=1)
def _kb() -> tuple[tuple[Vendor, ...], dict[str, Vendor], tuple[tuple[str, Vendor], ...], dict[str, Any]]:
    raw = _load_yaml(_HERE / "vendors.yml")
    vendors: list[Vendor] = []
    by_host: dict[str, Vendor] = {}
    by_suffix: list[tuple[str, Vendor]] = []
    for entry in raw.get("vendors", []):
        vendor = _vendor_from_dict(entry)
        vendors.append(vendor)
        for host in vendor.hosts:
            by_host.setdefault(host, vendor)
        for suffix in vendor.host_suffixes:
            if suffix.startswith("."):
                by_suffix.append((suffix, vendor))
    # longest suffix wins, so ".eu-cdn.clarity.ms" beats ".clarity.ms"
    by_suffix.sort(key=lambda pair: len(pair[0]), reverse=True)
    return tuple(vendors), by_host, tuple(by_suffix), raw.get("defaults", {})


@lru_cache(maxsize=1)
def _aliases() -> dict[str, frozenset[str]]:
    """Union of the aliases declared in every locale.

    The language of a site's privacy notice is unknown when the scan starts, so
    a report requested in English still has to recognise a vendor named the
    Italian way. Locale selection is a rendering concern; matching is not.
    """
    merged: dict[str, set[str]] = {}
    for locale in available_locales():
        path = LOCALES_DIR / locale / "vendors.yml"
        if not path.exists():
            continue
        for vendor_id, body in (_load_yaml(path) or {}).items():
            for alias in (body or {}).get("aliases", []) or []:
                merged.setdefault(vendor_id, set()).add(str(alias).lower())
    return {k: frozenset(v) for k, v in merged.items()}


@lru_cache(maxsize=1)
def _platforms() -> tuple[tuple[Platform, re.Pattern[str] | None, re.Pattern[str] | None], ...]:
    raw = _load_yaml(_HERE / "platforms.yml")
    out = []
    for entry in raw.get("platforms", []):
        generator = entry.get("generator_regex") or ""
        html = entry.get("html_regex") or ""
        out.append(
            (
                Platform(id=entry["id"], name=entry["name"]),
                re.compile(generator, re.I) if generator else None,
                re.compile(html, re.I) if html else None,
            )
        )
    return tuple(out)


@lru_cache(maxsize=1)
def _frameworks() -> dict[str, Mapping]:
    raw = _load_yaml(_HERE / "frameworks.yml")
    defaults = raw.get("defaults", {}) or {}
    out: dict[str, Mapping] = {}
    for rule_id, body in (raw.get("rules", {}) or {}).items():
        out[rule_id] = Mapping(
            owner=_enum(Owner, body.get("owner", defaults.get("owner")), Owner.CTO),
            secondary_owners=tuple(
                _enum(Owner, o, Owner.CTO) for o in body.get("secondary_owners", []) or []
            ),
            domains=tuple(body.get("domains", defaults.get("domains", []))),
            controls={k: tuple(v) for k, v in (body.get("controls", {}) or {}).items()},
        )
    return out


# ------------------------------------------------------------------- public


def all_vendors() -> tuple[Vendor, ...]:
    return _kb()[0]


def aliases_for(vendor_id: str) -> frozenset[str]:
    return _aliases().get(vendor_id, frozenset())


def mapping_for(rule_id: str) -> Mapping:
    return _frameworks().get(rule_id, Mapping(owner=Owner.CTO, domains=("web",)))


def registered_domain(host: str) -> str:
    ext = tldextract.extract(host)
    domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    return (domain or host).lower()


def is_first_party(host: str, site_host: str) -> bool:
    return registered_domain(host) == registered_domain(site_host)


def lookup(host: str) -> Vendor | None:
    host = host.lower().split(":")[0].strip(".")
    _, by_host, by_suffix, _ = _kb()
    if host in by_host:
        return by_host[host]
    for suffix, vendor in by_suffix:
        if host.endswith(suffix):
            return vendor
    return None


def lookup_by_id(vendor_id: str) -> Vendor | None:
    for vendor in _kb()[0]:
        if vendor.id == vendor_id:
            return vendor
    return None


def transfer_scope(host: str) -> TransferScope:
    """Conservative: when in doubt, outside the EEA.

    A false positive costs the site owner one rebuttal with a contract in hand.
    A false negative silently blesses an undocumented transfer.
    """
    host = host.lower().strip(".")
    if not host:
        return TransferScope.EEA
    vendor = lookup(host)
    if vendor is not None:
        return vendor.transfer
    ext = tldextract.extract(host)
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    if tld in EEA_CCTLDS:
        return TransferScope.EEA
    if tld in ADEQUATE_CCTLDS:
        return TransferScope.ADEQUACY
    return TransferScope.NON_EEA


def is_extra_eea(host: str) -> bool:
    return transfer_scope(host) is not TransferScope.EEA


def unknown_vendor(host: str) -> Vendor:
    """A host we cannot attribute is still a third party, and gets a vendor node
    built from its registrable domain with conservative facts."""
    defaults = (_kb()[3] or {}).get(UNKNOWN_VENDOR_KEY, {})
    domain = registered_domain(host)
    rem = defaults.get("remediation", {}) or {}
    return Vendor(
        id=f"host-{domain.replace('.', '-')}",
        vendor=None,
        vendor_key=defaults.get("vendor_key", UNKNOWN_VENDOR_KEY),
        product=domain,
        category=_enum(VendorCategory, defaults.get("category"), VendorCategory.INFRA),
        jurisdiction=_jurisdiction_from_tld(domain) or defaults.get("jurisdiction", "unknown"),
        transfer=transfer_scope(host),
        transfer_basis=None,
        storage_access=bool(defaults.get("storage_access", False)),
        consent_class=_enum(ConsentClass, defaults.get("consent_class"), ConsentClass.UNCERTAIN),
        data_types=tuple(
            _enum(DataType, d, DataType.REQUEST_METADATA) for d in defaults.get("data_types", [])
        ),
        remediation=VendorRemediation(pattern=rem.get("pattern", "identify_unknown")),
        hosts=(host.lower(),),
        known=False,
    )


def vendor_for(host: str) -> Vendor:
    return lookup(host) or unknown_vendor(host)


def _jurisdiction_from_tld(host: str) -> str | None:
    ext = tldextract.extract(host)
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    return tld.upper() if tld in EEA_CCTLDS else None


def identify_platform(generator_meta: str | None, html: str) -> Platform | None:
    for platform, generator_re, html_re in _platforms():
        if generator_meta and generator_re and generator_re.search(generator_meta):
            return platform
        if html_re and html_re.search(html):
            return platform
    return None
