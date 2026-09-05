"""Anchoring a web finding to the line of source that causes it.

A privacy finding is about a running site; a code scanning alert is about a
file and a line. In CI both are present at once, and that is the whole
opportunity: if the page loads `fonts.googleapis.com`, some file in the
repository says so, and pointing the developer at that line is the difference
between an alert they act on and an alert they mute.

The search is deliberately literal — the evidence token as it appears in the
observation, matched verbatim in text files. No parsing, no heuristics about
frameworks: either the token is written in the source, or we say we could not
find it and fall back to the declared anchor. A confident wrong line is worse
than an honest "not found".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..core.models import Finding

# Text files a front end is plausibly built from. Binary and vendored trees are
# skipped: a hit inside node_modules teaches the developer nothing.
SEARCHABLE_SUFFIXES = frozenset(
    {
        ".html", ".htm", ".xhtml", ".jinja", ".j2", ".twig", ".liquid", ".hbs", ".ejs", ".pug",
        ".php", ".erb", ".haml", ".slim", ".astro", ".vue", ".svelte", ".mdx", ".md",
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".css", ".scss", ".sass", ".less",
        ".py", ".rb", ".go", ".rs", ".java", ".cs", ".tmpl", ".tpl",
        ".yml", ".yaml", ".toml", ".json", ".conf", ".config", ".htaccess", ".env.example",
    }
)

SKIP_DIRECTORIES = frozenset(
    {
        ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
        "__pycache__", ".venv", "venv", ".tox", "target", "coverage", ".cache",
        ".pnpm-store",
        # this tool's own output: a report naturally contains every host it
        # reported on, and anchoring a finding to our own PDF summary would be
        # both useless and quietly wrong
        "reports", "artifacts", "scans",
    }
)

# Belt and braces for the same problem: an output file moved somewhere else is
# still recognisable, in any language, by the digest labels it carries.
SELF_REFERENCE = re.compile(
    r"privacymate.{0,400}?(evidence digest|evidenceDigest|impronta dell.evidenza|rulesetDigest)",
    re.I | re.S,
)

# Where a site's markup actually lives, roughly in order of likelihood. Used to
# rank candidates so the anchor lands on the template that includes the third
# party, not on a doc that mentions it.
SOURCE_DIRECTORIES = frozenset(
    {
        "src", "app", "components", "component", "layouts", "layout", "templates", "template",
        "themes", "theme", "partials", "includes", "views", "pages", "public", "static",
        "assets", "web", "wwwroot", "site", "content",
    }
)
DOCUMENTATION_DIRECTORIES = frozenset(
    {"docs", "doc", "examples", "example", "test", "tests", "fixtures", "__tests__", "spec"}
)
MARKUP_SUFFIXES = frozenset(
    {
        ".html", ".htm", ".xhtml", ".astro", ".vue", ".svelte", ".jsx", ".tsx", ".php",
        ".erb", ".twig", ".liquid", ".hbs", ".ejs", ".pug", ".tmpl", ".tpl", ".jinja", ".j2",
    }
)
CODE_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".css", ".scss", ".sass", ".less"})

MAX_FILE_BYTES = 2_000_000


def _rank(path: Path, root: Path) -> int:
    """Higher is searched first. Determinism matters more than cleverness: the
    same repository must always produce the same anchor."""
    parts = {part.lower() for part in path.relative_to(root).parts[:-1]}
    score = 0
    if parts & SOURCE_DIRECTORIES:
        score += 3
    if parts & DOCUMENTATION_DIRECTORIES:
        score -= 3
    suffix = path.suffix.lower()
    if suffix in MARKUP_SUFFIXES:
        score += 2
    elif suffix in CODE_SUFFIXES:
        score += 1
    elif suffix == ".md":
        score -= 2
    return score


# A line that *includes* a third party looks different from a line that merely
# names it: an allowlist, a CSP header, a comment, a knowledge base. Both are
# useful to a developer, but only the first is the cause — and saying which is
# which is the difference between a precise tool and a plausible one.
INCLUSION = re.compile(
    r"<\s*(script|link|iframe|img|source|embed|object)\b|"
    r"\b(src|href|data-src|poster)\s*=|"
    r"\b(import|require|fetch|axios|XMLHttpRequest)\b|"
    r"url\s*\(|@import\b|"
    r"\b(connect-src|script-src|img-src|font-src|frame-src)\b",
    re.I,
)


@dataclass(frozen=True, slots=True)
class SourceAnchor:
    path: str  # repository-relative, POSIX separators — SARIF wants that
    line: int
    snippet: str
    token: str
    kind: str = "inclusion"  # inclusion | mention


def _tokens(finding: Finding) -> list[str]:
    """What to look for, most specific first.

    Hosts come from the evidence rather than the rule, so a rule that fires on
    an unknown vendor still searches for the right string.
    """
    evidence = finding.evidence or {}
    out: list[str] = []

    hosts = evidence.get("hosts") or []
    out.extend(str(h) for h in hosts if h)

    for key in ("name", "key"):  # cookie name, storage key
        value = evidence.get(key)
        if isinstance(value, str) and len(value) >= 3:
            out.append(value)

    action = evidence.get("action")
    if isinstance(action, str) and action:
        out.append(action)

    # deduplicate, longest first: the most specific token wins the anchor
    return sorted(dict.fromkeys(t for t in out if t), key=len, reverse=True)


def _candidate_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if parts & SKIP_DIRECTORIES:
            continue
        if path.suffix.lower() not in SEARCHABLE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


class SourceIndex:
    """One pass over the repository, reused by every finding.

    Built lazily and only when a source root is given: a scan run outside CI
    has nothing to anchor to and must not pay for a filesystem walk.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.skipped_own_output = 0
        collected: list[tuple[int, str, Path, list[str]]] = []
        for path in _candidate_files(self.root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if SELF_REFERENCE.search(text):
                self.skipped_own_output += 1
                continue
            collected.append((_rank(path, self.root), path.as_posix(), path, text.splitlines()))
        collected.sort(key=lambda item: (-item[0], item[1]))
        self._files = [(path, lines) for _, _, path, lines in collected]

    @property
    def file_count(self) -> int:
        return len(self._files)

    def find(self, token: str) -> SourceAnchor | None:
        """Two passes: lines that load the resource, then lines that merely
        name it. Never report the second as if it were the first."""
        needle = token.lower()
        fallback: SourceAnchor | None = None
        for path, lines in self._files:
            for number, line in enumerate(lines, start=1):
                if needle not in line.lower():
                    continue
                anchor = SourceAnchor(
                    path=path.relative_to(self.root).as_posix(),
                    line=number,
                    snippet=line.strip()[:200],
                    token=token,
                    kind="inclusion" if INCLUSION.search(line) else "mention",
                )
                if anchor.kind == "inclusion":
                    return anchor
                if fallback is None:
                    fallback = anchor
        return fallback

    def anchor_for(self, finding: Finding) -> SourceAnchor | None:
        for token in _tokens(finding):
            found = self.find(token)
            if found is not None:
                return found
        return None
