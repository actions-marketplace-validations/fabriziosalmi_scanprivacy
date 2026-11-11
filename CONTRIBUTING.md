# Contributing

## Setup

```bash
uv sync --extra dev        # or: pip install -e ".[dev]"
python -m playwright install chromium
python -m pytest -q -rs
```

Read the skip list (`-rs`). A skipped browser or PDF test is a green tick over an unknown quantity.

## What a good change looks like

- A rule or a finding is emitted only from something the engine observed. Never from a failed read or a swallowed exception.
- A new check comes with a test that fails when the check is disabled.
- Wording in reports states what was seen, not what the law requires of the site.
- Never commit a scan result of a real site (`tests/test_repo_hygiene.py` enforces it).
- GitHub Actions are pinned to a commit SHA (enforced by `tests/test_workflows.py`).

## Pull requests

Conventional Commits with a scope (`fix(cookies): ...`), subject stating the resulting behaviour. Open an issue first for a new rule: it needs a legal or technical basis (see the rule template).

Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

By contributing you agree your work is licensed under AGPL-3.0-only, like the rest of the project.

## Releasing

Maintainers only. A version tag publishes to PyPI through `.github/workflows/release.yml`, with no stored credential: PyPI trusts the workflow by identity.

One-time setup:

1. On PyPI, in your account's publishing settings, add a pending trusted publisher for the project name `scanprivacy`: owner `fabriziosalmi`, repository `scanprivacy`, workflow `release.yml`, environment `pypi`.
2. On GitHub, create an environment named `pypi` (Settings, Environments). Adding yourself as a required reviewer makes every release wait for one click.

Each release:

1. Set the new version in `pyproject.toml` and `src/scanprivacy/__init__.py`, and add a `## [X.Y.Z]` section to `CHANGELOG.md`. Merge that through a pull request.
2. Run `python tools/check_release.py vX.Y.Z` on main: it must print `OK`.
3. Tag main and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The workflow refuses a tag that is not on main, that does not match the code and the changelog, or whose wheel lacks the rules, the knowledge files or the fonts. The moving `v1` tag used by the GitHub Action is not a release tag and does not trigger it.
