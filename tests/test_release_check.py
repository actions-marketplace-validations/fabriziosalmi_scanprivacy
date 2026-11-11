"""The release gate: a tag becomes a release only if it matches the code and the build holds what it must."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_release", ROOT / "tools" / "check_release.py")
check_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_release)


def _tree(tmp_path: Path, pyproject="0.2.0", init="0.2.0", changelog="## [0.2.0]\n") -> Path:
    (tmp_path / "src" / "scanprivacy").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{pyproject}"\n', encoding="utf-8")
    (tmp_path / "src" / "scanprivacy" / "__init__.py").write_text(f'__version__ = "{init}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n" + changelog, encoding="utf-8")
    return tmp_path


def test_the_repository_as_it_is_can_be_tagged_with_its_own_version():
    import tomllib

    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert check_release.check_tag(f"v{version}") == []


def test_a_matching_tag_passes(tmp_path):
    assert check_release.check_tag("v0.2.0", _tree(tmp_path)) == []


@pytest.mark.parametrize(
    "tag,kwargs,fragment",
    [
        ("v0.3.0", {}, "pyproject.toml says 0.2.0"),
        ("v0.2.0", {"init": "0.1.0"}, "__version__ is 0.1.0"),
        ("v0.2.0", {"changelog": "## [0.1.0]\n"}, "no section for 0.2.0"),
        ("v1", {}, "not a version tag"),
        ("0.2.0", {}, "not a version tag"),
    ],
)
def test_a_tag_that_disagrees_with_the_code_is_refused(tmp_path, tag, kwargs, fragment):
    assert any(fragment in p for p in check_release.check_tag(tag, _tree(tmp_path, **kwargs)))


def _dist(tmp_path: Path, extra: tuple[str, ...] = (), drop: tuple[str, ...] = ()) -> Path:
    names = {
        "scanprivacy/rules/PM-SEC-01.yml",
        "scanprivacy/knowledge/vendors.yml",
        "scanprivacy/report/templates/fonts/inter-400.woff2",
        *extra,
    } - set(drop)
    with zipfile.ZipFile(tmp_path / "scanprivacy-0.2.0-py3-none-any.whl", "w") as z:
        for name in names:
            z.writestr(name, "x")
    (tmp_path / "scanprivacy-0.2.0.tar.gz").write_bytes(b"x")
    return tmp_path


def test_a_complete_build_passes(tmp_path):
    assert check_release.check_dist(_dist(tmp_path)) == []


def test_a_wheel_without_its_data_is_refused(tmp_path):
    problems = check_release.check_dist(_dist(tmp_path, drop=("scanprivacy/rules/PM-SEC-01.yml",)))
    assert any("does not contain scanprivacy/rules/PM-SEC-01.yml" in p for p in problems)


@pytest.mark.parametrize("stray", ["tests/test_x.py", "docs/api.md", ".github/workflows/ci.yml", "scanprivacy/.env"])
def test_a_wheel_with_files_that_do_not_belong_is_refused(tmp_path, stray):
    assert any(stray in p for p in check_release.check_dist(_dist(tmp_path, extra=(stray,))))
