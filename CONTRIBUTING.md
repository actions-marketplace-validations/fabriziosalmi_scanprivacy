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
