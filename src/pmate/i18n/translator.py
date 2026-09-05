"""Translation runtime.

Design rules, in order of importance:

1. **English is the source language.** `en` is always complete; every other
   locale falls back to it key by key, so a half-translated locale degrades to
   English instead of producing an empty report.
2. **A missing key is loud.** In strict mode (used by the test suite) it
   raises; otherwise it renders as `⟦key⟧`, which is impossible to miss in a
   PDF. Silently empty strings are how translation debt becomes invisible.
3. **The catalogues are data.** Nothing here knows what a finding is. Adding
   German means adding `locales/de/` and nothing else.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml

LOCALES_DIR = Path(__file__).resolve().parent / "locales"
DEFAULT_LOCALE = "en"

CATALOGUES = ("ui", "rules", "vendors", "references")


class MissingTranslation(KeyError):
    """Raised in strict mode when a key has no value in any locale."""


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _clean(value: str) -> str:
    """Folded YAML scalars (`>`) end with a newline. Fragments get concatenated
    into sentences, so that newline would show up as a break mid-sentence.
    Only newlines are stripped: a quoted value like `" and "` needs its spaces.
    """
    return value.rstrip("\n").replace("\n", " ")


def _format(template: str, params: dict[str, Any]) -> str:
    template = _clean(template)
    if not params or "{" not in template:
        return template
    try:
        return string.Formatter().vformat(template, (), _SafeDict(params))
    except (ValueError, IndexError):
        return template


def _deep_get(tree: Any, parts: Iterable[str]) -> Any:
    node = tree
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


@lru_cache(maxsize=32)
def _load_locale(locale: str) -> dict[str, Any]:
    """All catalogues of one locale, merged under their file name."""
    base = LOCALES_DIR / locale
    if not base.is_dir():
        raise FileNotFoundError(f"unknown locale: {locale!r} ({base} does not exist)")
    out: dict[str, Any] = {}
    for name in CATALOGUES:
        path = base / f"{name}.yml"
        out[name] = yaml.safe_load(path.read_text(encoding="utf-8")) or {} if path.exists() else {}
    return out


def available_locales() -> list[str]:
    if not LOCALES_DIR.is_dir():
        return [DEFAULT_LOCALE]
    return sorted(p.name for p in LOCALES_DIR.iterdir() if p.is_dir() and (p / "ui.yml").exists())


@dataclass(frozen=True, slots=True)
class Translator:
    """Renders keys into one locale, falling back to English."""

    locale: str = DEFAULT_LOCALE
    strict: bool = False
    _chain: tuple[dict[str, Any], ...] = field(default_factory=tuple, repr=False)

    @classmethod
    def for_locale(cls, locale: str | None = None, strict: bool = False) -> "Translator":
        locale = (locale or DEFAULT_LOCALE).replace("_", "-").lower()
        # "it-IT" and "it" resolve to the same catalogue; unknown locales fall
        # back to English rather than failing a scan over a display detail.
        candidates = [locale, locale.split("-")[0], DEFAULT_LOCALE]
        chain: list[dict[str, Any]] = []
        resolved = DEFAULT_LOCALE
        for candidate in dict.fromkeys(candidates):
            try:
                chain.append(_load_locale(candidate))
                if len(chain) == 1:
                    resolved = candidate
            except FileNotFoundError:
                continue
        if not chain:
            raise FileNotFoundError("no locale catalogue found, not even English")
        return cls(locale=resolved, strict=strict, _chain=tuple(chain))

    # ------------------------------------------------------------- lookup
    def _lookup(self, catalogue: str, key: str) -> Any:
        # Flat key first: legal reference keys contain dots (`gdpr:13.1.f`)
        # and must not be read as a path. Nested paths are the second try.
        parts = key.split(".")
        for level in self._chain:
            tree = level.get(catalogue, {})
            if isinstance(tree, dict) and key in tree:
                return tree[key]
            value = _deep_get(tree, parts)
            if value is not None:
                return value
        return None

    def _missing(self, catalogue: str, key: str) -> str:
        if self.strict:
            raise MissingTranslation(f"{self.locale}:{catalogue}.{key}")
        return f"⟦{catalogue}.{key}⟧"

    # --------------------------------------------------------------- API
    def t(self, key: str, /, **params: Any) -> str:
        """A user-interface string from `ui.yml`."""
        value = self._lookup("ui", key)
        if value is None:
            return self._missing("ui", key)
        return _format(str(value), params)

    def maybe(self, key: str, /, **params: Any) -> str | None:
        value = self._lookup("ui", key)
        return _format(str(value), params) if value is not None else None

    def items(self, key: str, /, **params: Any) -> list[str]:
        """A list-valued string (remediation steps, verification steps)."""
        value = self._lookup("ui", key)
        if value is None:
            return [self._missing("ui", key)]
        if isinstance(value, str):
            return [_format(value, params)]
        return [_format(str(v), params) for v in value]

    def plural(self, key: str, n: int, /, **params: Any) -> str:
        """Pick `key.one` or `key.other` according to `n`.

        Not a nicety: "1 chiavi di memoria" is wrong Italian and "1 keys" is
        wrong English, and both would appear in the first paragraph a reader
        sees. Languages with richer plural rules (Polish, Russian) will need a
        real CLDR selector; `one`/`other` covers every language on the roadmap.
        """
        form = "one" if abs(n) == 1 else "other"
        value = self._lookup("ui", f"{key}.{form}")
        if value is None:
            value = self._lookup("ui", f"{key}.other")
        if value is None:
            return self._missing("ui", f"{key}.{form}")
        return _format(str(value), {"n": n, **params})

    def label(self, member: StrEnum | str, enum_name: str | None = None) -> str:
        """Display string for a canonical value: `high` -> "High" / "Alta"."""
        if isinstance(member, StrEnum):
            enum_name = enum_name or type(member).__name__
            value = str(member.value)
        else:
            if enum_name is None:
                raise ValueError("enum_name is required when passing a plain string")
            value = str(member)
        key = f"enum.{enum_name}.{value}"
        found = self._lookup("ui", key)
        return _clean(str(found)) if found is not None else self._missing("ui", key)

    def rule(self, rule_id: str, field_: str, /, **params: Any) -> str:
        value = self._lookup("rules", f"{rule_id}.{field_}")
        if value is None:
            return self._missing("rules", f"{rule_id}.{field_}")
        return _format(str(value), params)

    def rule_list(self, rule_id: str, field_: str, /, **params: Any) -> list[str]:
        value = self._lookup("rules", f"{rule_id}.{field_}")
        if value is None:
            return []
        if isinstance(value, str):
            return [_format(value, params)]
        return [_format(str(v), params) for v in value]

    def rule_has(self, rule_id: str, field_: str) -> bool:
        return self._lookup("rules", f"{rule_id}.{field_}") is not None

    def reference(self, key: str) -> str:
        """A legal reference: `gdpr:13.1.f` -> "GDPR Art. 13(1)(f) — …"."""
        value = self._lookup("references", key)
        if value is None:
            # An unknown reference is shown as its key rather than hidden: a
            # citation that vanishes from a report is worse than an ugly one.
            return self._missing("references", key) if self.strict else key
        return _clean(str(value))

    def references(self, keys: Iterable[str]) -> list[str]:
        return [self.reference(k) for k in keys]

