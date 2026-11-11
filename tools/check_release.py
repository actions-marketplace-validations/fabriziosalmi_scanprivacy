"""What has to be true before a tag becomes a release.

    python tools/check_release.py v0.2.0            # the tag matches the code and the changelog
    python tools/check_release.py v0.2.0 dist/      # ...and the built files contain what the package needs

Run by .github/workflows/release.yml, and importable so the rules are tested.
"""

from __future__ import annotations

import re
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(r"v(\d+\.\d+\.\d+)")


def check_tag(tag: str, root: Path = ROOT) -> list[str]:
    match = TAG.fullmatch(tag)
    if not match:
        return [f"{tag!r} is not a version tag (vMAJOR.MINOR.PATCH)"]
    version = match.group(1)
    problems = []
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if declared != version:
        problems.append(f"pyproject.toml says {declared}, the tag says {version}")
    init = (root / "src" / "scanprivacy" / "__init__.py").read_text(encoding="utf-8")
    found = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not found or found.group(1) != version:
        problems.append(f"scanprivacy.__version__ is {found.group(1) if found else 'missing'}, the tag says {version}")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\]", changelog, re.M):
        problems.append(f"CHANGELOG.md has no section for {version}")
    return problems


def check_dist(dist: Path) -> list[str]:
    """The wheel carries the data the engine reads at run time, and none of the repository's other files."""
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1 or not list(dist.glob("*.tar.gz")):
        return [f"expected one wheel and one sdist in {dist}, found {[p.name for p in dist.iterdir()]}"]
    names = zipfile.ZipFile(wheels[0]).namelist()
    problems = []
    for needed in ("scanprivacy/rules/PM-SEC-01.yml", "scanprivacy/knowledge/vendors.yml", "scanprivacy/report/templates/fonts/inter-400.woff2"):
        if needed not in names:
            problems.append(f"the wheel does not contain {needed}")
    for name in names:
        if name.startswith(("tests/", "docs/", ".github/")) or re.search(r"(^|/)(\.env|.*\.pem|.*\.key)$", name):
            problems.append(f"the wheel contains {name}")
    return problems


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    problems = check_tag(argv[0])
    if len(argv) > 1:
        problems += check_dist(Path(argv[1]))
    print("\n".join(problems) if problems else f"OK: {argv[0]}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
