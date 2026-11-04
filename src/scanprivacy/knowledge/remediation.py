"""The remediation knowledge, consultable without observing anything.

Every fix this engine knows already existed: 9 vendor patterns, 27 rule-specific
procedures, 83 concrete steps, 30 alternatives, 26 contextual extra steps, 16
independent verification procedures. None of it could be *asked for*. The only
way to see a fix was to scan a site that happened to trigger the rule that
carried it — so answering "how do I stop sending IP addresses to Google Fonts?"
meant finding a site that used Google Fonts and scanning it.

That makes the knowledge base a lookup table with no lookup. This module is the
lookup: the same catalogue, addressed by rule, by pattern or by vendor, in any
language the build reports in, with no target and no browser involved.

The audience is deliberately three-way. A person wants to read the steps. A
language model wants the whole catalogue at once, to answer from the register
this project actually uses rather than from whatever it remembers about GDPR.
A tool wants one entry by key, with stable field names. All three get the same
structure, because a fix that reads differently depending on who asked is a
fix nobody can check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..analyze.engine import load_rules
from ..i18n.translator import DEFAULT_LOCALE, Translator
from .registry import all_vendors, mapping_for

__all__ = ["RemediationEntry", "catalogue", "entry_for", "patterns"]


@dataclass(slots=True)
class RemediationEntry:
    """One fix, with everything needed to judge and apply it."""

    key: str
    kind: str  # "rule" | "pattern"
    title: str
    summary: str
    steps: list[str] = field(default_factory=list)
    effort: str = ""
    alternatives: list[str] = field(default_factory=list)
    """Things that remove the problem instead of documenting it. The cheapest
    transfer impact assessment is the transfer you do not make."""
    verification: list[str] = field(default_factory=list)
    """How to confirm the fix worked, without this tool — as templates.

    The steps a *finding* carries are filled in from the observation: the real
    URL, the real host, a request that was actually seen. A catalogue has no
    observation, so what it can offer is the shape: "load {url} and watch for a
    request to {host}". Presenting those as if they were specific would be
    worse than presenting them as templates, so the placeholders stay visible."""
    applies_when: str = ""
    """What has to be observed for this fix to be the right one. Without it a
    catalogue is a list of good ideas."""
    severity: str = ""
    owner: str = ""
    references: list[str] = field(default_factory=list)
    controls: dict[str, list[str]] = field(default_factory=dict)
    vendors: list[str] = field(default_factory=list)
    """Which known vendors this pattern is the answer for — empty for a
    rule-specific fix."""

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


def _condition_prose(condition: dict[str, Any]) -> str:
    """The rule's trigger, spelled out.

    Rendered from the predicate names rather than translated: they are the
    engine's own vocabulary, they appear in `rules/README.md`, and a reader
    checking whether a fix applies to them needs the real condition and not a
    paraphrase of it.
    """
    parts = []
    for name, arg in condition.items():
        if isinstance(arg, bool):
            parts.append(name if arg else f"not {name}")
        elif isinstance(arg, (list, tuple)):
            parts.append(f"{name} in [{', '.join(str(a) for a in arg)}]")
        else:
            parts.append(f"{name} = {arg}")
    return " and ".join(parts)


# Which verification templates a rule's subject can produce. Taken from the
# branches in analyze/verify.py: a catalogue that invented its own list would
# drift from what findings actually carry.
_VERIFICATION_BY_SUBJECT = {
    "vendor": ("vendor_request", "vendor_request_cli", "vendor_document"),
    "cookie": ("cookie",),
    "storage": ("storage",),
    "form": ("form",),
    "site": ("headers", "documents_found", "consent"),
}


def _templates(subject: str, t: Translator) -> list[str]:
    out: list[str] = []
    for key in _VERIFICATION_BY_SUBJECT.get(subject, ()):
        value = t.maybe(f"verification.{key}")
        if isinstance(value, list):
            out.extend(str(v) for v in value)
        elif value:
            out.append(str(value))
    return out


def _rule_entry(rule, t: Translator) -> RemediationEntry:
    mapping = mapping_for(rule.id)

    if rule.remediation_source == "vendor":
        # The fix belongs to whichever vendor triggered the rule, so the rule
        # itself has no procedure to state — a finding gets one, this entry
        # cannot. Naming the applicable patterns is the useful answer; a made-up
        # generic procedure would be a worse one.
        applicable = sorted(
            {v.remediation.pattern for v in all_vendors() if v.remediation.pattern}
        )
        summary = t.t("remediation.depends_on_vendor")
        steps = [t.t("remediation.depends_on_vendor_step", patterns=", ".join(applicable))]
    else:
        summary = t.rule(rule.id, "remediation.summary")
        steps = list(t.rule_list(rule.id, "remediation.steps"))

    return RemediationEntry(
        key=rule.id,
        kind="rule",
        title=t.rule(rule.id, "title"),
        summary=summary,
        steps=steps,
        effort=t.label(rule.remediation_effort),
        verification=_templates(rule.subject.value, t),
        applies_when=_condition_prose(rule.condition),
        severity=rule.severity.value,
        owner=t.label(mapping.owner) if mapping.owner else "",
        references=[t.reference(r) for r in rule.references],
        controls={k: list(v) for k, v in mapping.controls.items()},
    )


def _pattern_entry(
    pattern: str, t: Translator, users: list[str], vendor=None
) -> RemediationEntry:
    """A pattern, and — when the question named a vendor — filled in for it.

    The patterns are templates: "serve the asset from your own domain and drop
    the call to {product}". Asked in the abstract, the placeholder is the honest
    answer, because the pattern really does apply to ten vendors. Asked about
    google-fonts, it is half an answer, and the half that is missing is the
    half somebody needed.
    """
    base = f"remediation.pattern.{pattern}"
    params: dict[str, Any] = {}
    if vendor is not None:
        params = {
            "product": vendor.product,
            "vendor": vendor.vendor or vendor.product,
            "hosts": ", ".join(list(vendor.hosts) + list(vendor.host_suffixes)) or vendor.product,
        }
    return RemediationEntry(
        key=pattern,
        kind="pattern",
        title=pattern.replace("_", " "),
        summary=t.t(f"{base}.summary", **params),
        steps=list(t.items(f"{base}.steps", **params)),
        alternatives=[
            t.t(f"remediation.alternative.{a}")
            for a in (vendor.remediation.alternatives if vendor is not None else ())
        ],
        applies_when=(
            f"observed use of {vendor.product}"
            if vendor is not None
            else "a vendor whose knowledge-base entry names this pattern"
        ),
        vendors=sorted(users),
    )


def patterns(locale: str = DEFAULT_LOCALE) -> list[RemediationEntry]:
    """Every vendor remediation pattern, with the vendors it answers for."""
    t = Translator.for_locale(locale)
    users: dict[str, list[str]] = {}
    for vendor in all_vendors():
        pattern = vendor.remediation.pattern
        if pattern:
            users.setdefault(pattern, []).append(vendor.id)
    return [_pattern_entry(p, t, users[p]) for p in sorted(users)]


def catalogue(locale: str = DEFAULT_LOCALE) -> list[RemediationEntry]:
    """Everything this engine knows how to fix, in one list.

    Ordered rules-then-patterns, each group by key, so two calls give the same
    document and a consumer can diff them across versions.
    """
    t = Translator.for_locale(locale)
    rules = sorted(load_rules(), key=lambda r: r.id)
    return [_rule_entry(r, t) for r in rules] + patterns(locale)


def entry_for(key: str, locale: str = DEFAULT_LOCALE) -> RemediationEntry | None:
    """One fix, by rule id, by pattern name, or by vendor id.

    A vendor id resolves to the pattern its knowledge-base entry names, because
    "how do I fix google-fonts" is the question people actually have, and
    knowing that the answer is called `self_host_asset` is the part they were
    hoping not to need.
    """
    for entry in catalogue(locale):
        if entry.key == key:
            return entry
    for vendor in all_vendors():
        if vendor.id == key and vendor.remediation.pattern:
            users = [
                v.id for v in all_vendors() if v.remediation.pattern == vendor.remediation.pattern
            ]
            return _pattern_entry(
                vendor.remediation.pattern, Translator.for_locale(locale), users, vendor
            )
    return None
