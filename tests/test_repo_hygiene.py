"""What this repository is allowed to contain.

The engine is the product. An operator's own measurements are not: a scan
result names a site, grades it, and lists what is wrong with it, and a list of
those is a map of somebody's estate. `data/baseline/<date>/` and `data/fleet/`
are ignored for that reason.

A `.gitignore` pattern is not the same thing as a rule. `mv data/fleet
data/fleet-old` before a rescan moved 46 files out of a narrower pattern, and
the next `git add -A` committed every one of them back in — four commits after
they were deliberately removed, with nothing to notice it. The rule now lives
here, where a filename cannot walk around it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# A scan result, by shape rather than by location. These four keys together
# appear in nothing else the repository legitimately tracks.
SCAN_KEYS = {"findings", "verdict", "observation", "record"}


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return [p for p in out.stdout.split("\0") if p]


@pytest.fixture(scope="module")
def tracked() -> list[str]:
    files = _tracked()
    assert len(files) > 50, "git ls-files found almost nothing — the check would pass vacuously"
    return files


def test_no_scan_result_is_tracked(tracked: list[str]):
    offenders = []
    for path in tracked:
        if not path.endswith(".json"):
            continue
        try:
            payload = json.loads((ROOT / path).read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict) and SCAN_KEYS <= set(payload):
            offenders.append(path)
    assert offenders == [], (
        f"scan results are tracked: {offenders}. They are the estate of whoever "
        "ran the engine, not part of the engine. Keep them on disk and out of "
        "the repository."
    )


def test_no_rendered_report_is_tracked(tracked: list[str]):
    """PDFs and SARIF are output. They belong next to the run that made them."""
    offenders = [p for p in tracked if p.endswith((".pdf", ".sarif"))]
    assert offenders == [], f"rendered output is tracked: {offenders}"


def test_the_target_list_is_not_tracked(tracked: list[str]):
    """`data/fleet-targets.txt` is the list of sites an operator scans. On its
    own, without a single finding attached, it is still a map."""
    assert "data/fleet-targets.txt" not in tracked


def test_the_convention_is_still_documented(tracked: list[str]):
    """The data goes, the explanation stays. Otherwise the next person puts it
    back, reasonably, because nothing said not to."""
    assert "data/baseline/README.md" in tracked


def test_no_credential_shaped_file_is_tracked(tracked: list[str]):
    """`scanprivacy attest --sign cosign-key` takes a private key, and the obvious
    place to leave one is the directory the command ran in."""
    offenders = [
        p for p in tracked if p.endswith((".pem", ".key", ".p12", ".pfx")) or Path(p).name == ".env"
    ]
    assert offenders == [], f"credential-shaped files are tracked: {offenders}"
