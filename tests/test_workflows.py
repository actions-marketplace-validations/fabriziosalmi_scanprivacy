"""Every action this project runs is either pinned or declared unpinnable.

A `uses: owner/repo@v4` reference is mutable: whoever controls that repository
can move the tag, and the next run executes whatever it points at, holding the
job's token. For a project whose purpose is to sign an attestation over what it
observed, that is a editable link in the chain the signature is supposed to
close.

A reference that cannot be pinned has to be named here with its reason. The test
fails the moment that changes in either direction: a new unpinned reference
appears, or a declared exception stops being one.

The rule covers three places: the action, this project's own CI workflows, and
the examples handed to other people. The first two run with a token.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = [
    ROOT / "action.yml",
    # This project's own CI belongs under the same rule, and more urgently than
    # the example does: these jobs actually run, with a token, on every push.
    *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    *sorted((ROOT / "examples" / "workflows").glob("*.yml")),
]

SHA = re.compile(r"^[^@]+@[0-9a-f]{40}(\s|#|$)")

# References that cannot be pinned, each with the reason. Anything not on this
# list must be a commit. Empty on purpose: the action is published, and the example
# references it by the commit its release tag points at.
UNPINNABLE: dict[str, str] = {}


def _uses(path: Path) -> list[str]:
    """Read the `uses:` values textually rather than through the parsed tree.

    The parse would work, but walking it means knowing every shape a workflow
    can take — composite steps, matrix jobs, reusable workflows — and a shape
    this function did not anticipate would silently contribute nothing.
    """
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip().lstrip("- ").strip()
        if stripped.startswith("uses:"):
            found.append(stripped.split("uses:", 1)[1].split("#")[0].strip())
    return found


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_the_file_parses(path):
    yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_or_declared(path):
    offenders = [
        ref
        for ref in _uses(path)
        if not SHA.match(ref) and ref not in UNPINNABLE and not ref.startswith(("./", "docker://"))
    ]
    assert offenders == [], (
        f"{path.name} references actions by a moving tag: {offenders}. "
        "Pin to a commit, or add the reference to UNPINNABLE with the reason."
    )


def test_the_declared_exceptions_are_all_still_used():
    """The list is an admission, not a permanent allowance. When the action is
    published and the reference becomes a SHA, this fails and the entry — and
    the explanatory block in the workflow — have to go."""
    everything = {ref for path in WORKFLOW_FILES for ref in _uses(path)}
    stale = set(UNPINNABLE) - everything
    assert stale == set(), (
        f"UNPINNABLE lists references nothing uses any more: {stale}. "
        "Remove the entry, and the note in the workflow that explains it."
    )


def test_the_example_does_not_claim_the_action_is_unpublished():
    """The example was written while the repository was private. A reader copying it
    must not be told the action does not exist, and must get a reference that works."""
    text = (ROOT / "examples" / "workflows" / "privacy-gate.yml").read_text(encoding="utf-8")
    assert "NOT YET PUBLISHED" not in text and "unpublished" not in text
    assert re.search(r"uses: fabriziosalmi/scanprivacy@[0-9a-f]{40}\s", text)


def test_the_check_would_notice_an_unpinned_reference(tmp_path):
    """The guard's own guard: a test that only ever sees compliant input
    proves nothing about what it does with the other kind."""
    bad = tmp_path / "bad.yml"
    bad.write_text("jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    refs = _uses(bad)
    assert refs == ["actions/checkout@v4"]
    assert not SHA.match(refs[0])
