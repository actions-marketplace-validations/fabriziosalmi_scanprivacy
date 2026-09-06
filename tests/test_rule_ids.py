"""The rule id prefix, and the version at which it changes.

When the project was renamed from privacymate to scanprivacy, the rule ids kept
their `PM-` prefix. That was deliberate and it was not a decision to leave the
old name lying around: the ids are identifiers rather than branding. Each one
appears in every finding id derived from it, in every SARIF `ruleId`, in the
kept estate baseline, and in any code-scanning alert already raised from one.

Renaming them makes every existing finding a *different* finding. A comparison
against a baseline taken before the change reports the entire estate resolved
and an identical estate discovered — the exact failure `scanprivacy diff` was
taught to warn about. That cost is worth paying once, at a version boundary
where a reader expects identifiers to move, and not on an afternoon.

Agreed 2026-09-06: **`SP-` at the next minor bump.**

The purpose of this file is that the agreement survives the conversation. A note
in a document gets read by whoever goes looking for it; this fails the suite the
moment the version says the boundary has arrived, which is the only moment the
decision is actionable and the likeliest moment to have forgotten it.
"""

from __future__ import annotations

from pathlib import Path

from scanprivacy import __version__
from scanprivacy.config import RULES_DIR

RENAME_AT = (0, 2)
"""The version from which rule ids are `SP-`. Below it they are `PM-`."""


def _rule_ids() -> list[str]:
    return sorted(p.stem for p in Path(RULES_DIR).glob("*.yml"))


def _version() -> tuple[int, int]:
    major, minor, *_ = (int(part) for part in __version__.split(".")[:2])
    return major, minor


def test_the_rule_catalogue_is_not_empty():
    """Every assertion below is over a glob. An empty one passes all of them."""
    assert len(_rule_ids()) >= 25, "the rule catalogue did not load"


def test_the_prefix_matches_the_version():
    expected = "SP-" if _version() >= RENAME_AT else "PM-"
    wrong = [rule for rule in _rule_ids() if not rule.startswith(expected)]
    assert wrong == [], (
        f"version {__version__} expects rule ids prefixed {expected!r}, found: {wrong}.\n"
        "\n"
        "If this fired because the version was just bumped to 0.2.0 or beyond: that is\n"
        "the agreement, not a bug. Renaming the ids also means renaming the files in\n"
        "rules/, the keys in i18n/locales/*/rules.yml, the mappings in\n"
        "knowledge/frameworks.yml, and any rule id written into a test — and it\n"
        "invalidates every kept baseline, because a finding id is derived from the\n"
        "rule id. Take a fresh baseline after, and do not diff across the boundary."
    )


def test_one_prefix_only():
    """A half-finished rename is worse than either end of it: two prefixes in
    one catalogue means two naming schemes a reader has to know, and a finding
    id that tells them nothing about which era it came from."""
    prefixes = {rule.split("-")[0] for rule in _rule_ids()}
    assert len(prefixes) == 1, f"the catalogue mixes prefixes: {sorted(prefixes)}"


def test_every_id_is_shaped_like_an_identifier():
    """`<PREFIX>-<AREA>-<NN>`. The shape is what makes an id sortable, greppable
    and stable in a SARIF file."""
    import re

    shape = re.compile(r"^(PM|SP)-[A-Z]{2,4}-\d{2}$")
    malformed = [rule for rule in _rule_ids() if not shape.match(rule)]
    assert malformed == [], f"rule ids not shaped like identifiers: {malformed}"
