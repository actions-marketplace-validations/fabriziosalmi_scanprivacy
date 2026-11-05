"""Build the static site: the landing page, the docs as HTML, an example report.

    python site/build.py OUT_DIR [--example EXAMPLE_DIR]

`docs/*.md` become `OUT_DIR/docs/*.html`; `site/index.html` is the body of the
landing page; `site/assets/` and the report fonts are copied to `OUT_DIR/assets/`.
When an example directory is given and holds a report, it is published under
`OUT_DIR/example/` and summarised on the landing page. The example report is
never committed (a scan result names a site and grades it; see
tests/test_repo_hygiene.py): the Pages workflow makes it at deploy time.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://github.com/fabriziosalmi/scanprivacy"
SITE = "https://scanprivacy.org"
FONTS = ROOT / "src" / "scanprivacy" / "report" / "templates" / "fonts"

DOC_ORDER = ["index", "quickstart", "api", "deploy", "rules", "platforms"]
DOC_LABELS = {"index": "Overview", "quickstart": "Quickstart", "api": "HTTP API", "deploy": "Deployment", "rules": "Rules",
              "platforms": "Hosting platforms"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
DESCRIPTION = (
    "scanprivacy loads a page the way a first-time visitor would, records every request, cookie and storage "
    "write, and reports what it saw against GDPR, ePrivacy and the AI Act. Open source, AGPL-3.0."
)

HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{canonical}">
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="preload" href="/assets/fonts/inter-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/assets/fonts/inter-600.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/assets/site.css">
<meta property="og:type" content="website">
<meta property="og:title" content="{og_title}">
<meta property="og:description" content="{description}">
<meta property="og:url" content="{canonical}">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="frame">
<a class="wordmark" href="/">scanprivacy</a>
<nav class="site-nav" aria-label="Primary">{nav}</nav>
</div></header>
<main id="main">
"""

FOOT = """
</main>
<footer class="site-footer"><div class="frame">
<p>scanprivacy {version} &middot; AGPL-3.0-only &middot; {rules}</p>
<ul>
<li><a href="{source}">Source</a></li>
<li><a href="{source}/blob/main/CHANGELOG.md">Changelog</a></li>
<li><a href="{source}/blob/main/SECURITY.md">Security policy</a></li>
<li><a href="{source}/blob/main/CONTRIBUTING.md">Contributing</a></li>
</ul>
</div></footer>
<script src="/assets/site.js" defer></script>
</body>
</html>
"""

_LINK = re.compile(r'href="([^"#:]+?)(\.md)?(#[^"]*)?"')
_TABLE = re.compile(r"<table>.*?</table>", re.S)
_EMOJI_LEAD = re.compile(r"^(#{1,6})[ \t]+[^\w\s#`*\[(<\"'-]+️?[ \t]+", re.M)


# ------------------------------------------------------------------ facts

def _version() -> str:
    text = (ROOT / "src" / "scanprivacy" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "unknown"


def _rules_summary() -> str:
    files = list((ROOT / "src" / "scanprivacy" / "rules").glob("PM-*.yml"))
    refusal = sum(1 for p in files if re.search(r"^pass:\s*refusal", p.read_text(encoding="utf-8"), re.M))
    return f"{len(files)} rules ({len(files) - refusal} passive, {refusal} in the refusal pass)"


# ------------------------------------------------------------ rendering

def _rewrite_links(body: str) -> str:
    """Docs link to each other as `foo.md`; on the site those are `foo.html`.
    Anything that points outside docs/ (README, examples/, SECURITY.md) goes to
    the source repository, where it lives."""

    def fix(match: re.Match[str]) -> str:
        target, ext, anchor = match.group(1), match.group(2), match.group(3) or ""
        if target.startswith(("http", "/", "mailto")):
            return match.group(0)
        if target.startswith("../"):
            return f'href="{SOURCE}/blob/main/{target[3:]}{ext or ""}{anchor}"'
        if ext:
            return f'href="{target}.html{anchor}"'
        return match.group(0)

    return _LINK.sub(fix, body)


def _wrap_tables(body: str) -> str:
    """A table wider than its column scrolls inside a focusable region instead
    of pushing the page sideways."""
    return _TABLE.sub(
        lambda m: f'<div class="table-wrap" role="region" aria-label="Table, scrollable" tabindex="0">{m.group(0)}</div>',
        body,
    )


def render_markdown(text: str) -> tuple[str, str, list[dict]]:
    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "md_in_html"],
        extension_configs={"toc": {"permalink": "#", "permalink_title": "Link to this section", "toc_depth": "2-3"}},
    )
    body = _wrap_tables(_rewrite_links(md.convert(text)))
    first = re.search(r"^#\s+(.+)$", text, re.M)
    title = html.unescape(first.group(1)) if first else "scanprivacy"
    return title, body, md.toc_tokens


def _severity_pills(body: str) -> str:
    """Severity as a labelled pill: the word is the information, the colour only helps."""
    for name in SEVERITIES:
        body = body.replace(f"<td>{name}</td>", f'<td><span class="sev sev-{name}">{name.capitalize()}</span></td>')
    return body


def _toc(tokens: list[dict]) -> str:
    def items(nodes: list[dict]) -> str:
        if not nodes:
            return ""
        lis = "".join(
            f'<li><a href="#{n["id"]}">{html.escape(html.unescape(re.sub("<[^>]+>", "", n["name"])))}</a>{items(n["children"])}</li>'
            for n in nodes
            if n["level"] <= 3
        )
        return f"<ul>{lis}</ul>"

    top = [n for n in tokens]
    # the page title is the single h1; its children are the h2s worth listing
    nodes = top[0]["children"] if len(top) == 1 and top[0]["level"] == 1 else top
    return items(nodes)


def _nav(example: bool, current: str) -> str:
    links = [("/docs/", "Docs", "docs"), ("/docs/rules.html", "Rules", "rules")]
    if example:
        links.append(("/example/", "Example report", "example"))
    links.append((SOURCE, "Source", ""))
    here = ' aria-current="page"'
    return "".join(
        f'<a href="{href}"{here if key and key == current else ""}>{label}</a>' for href, label, key in links
    )


def page(
    out: Path, rel: str, title: str, body: str, *, example: bool, current: str = "",
    description: str = DESCRIPTION, version: str = "", rules: str = "",
) -> None:
    path = rel.removesuffix("index.html")
    head = HEAD.format(
        title=html.escape(title if title.startswith("scanprivacy") else f"{title} - scanprivacy"),
        og_title=html.escape(title),
        description=html.escape(description),
        canonical=f"{SITE}/{path}",
        nav=_nav(example, current),
    )
    target = out / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(head + body + FOOT.format(version=version, rules=rules, source=SOURCE), encoding="utf-8")


def _docs_shell(nav_items: list[tuple[str, str, bool]], heading: str, content: str, toc_html: str, extra_nav: str = "", wide: bool = False) -> str:
    current = ' aria-current="page"'
    items = "".join(
        f'<li><a href="{href}"{current if here else ""}>{html.escape(label)}</a></li>'
        for href, label, here in nav_items
    )
    toc = f'<nav class="docs-toc" aria-label="On this page"><h2>On this page</h2>{toc_html}</nav>' if toc_html else ""
    return (
        f'<div class="frame docs{" has-toc" if toc_html else ""}">'
        f'<nav class="docs-nav" aria-label="Documentation"><h2>{html.escape(heading)}</h2><ul>{items}</ul>{extra_nav}</nav>'
        f'<article class="prose{" wide" if wide else ""}">{content}</article>{toc}</div>'
    )


# ---------------------------------------------------------------- example

def _example_summary(example_dir: Path) -> dict | None:
    evidence = example_dir / "evidence.json"
    report = example_dir / "report.md"
    if not (evidence.is_file() and report.is_file()):
        return None
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
        verdict = data["verdict"]
        titles = [
            re.sub(r"^[^\w]+", "", m.group(1)).strip()
            for m in re.finditer(r"^###\s+(.+)$", report.read_text(encoding="utf-8"), re.M)
        ]
        findings = data.get("findings") or []
        return {
            "grade": str(verdict["grade"]),
            "counts": verdict["counts"],
            "site": data.get("site", {}).get("domain") or data.get("url", ""),
            "date": str(data.get("started_at", ""))[:10],
            "top": [
                (f["severity"], titles[i] if i < len(titles) else f["id"]) for i, f in enumerate(findings[:3])
            ],
        }
    except (KeyError, ValueError, TypeError):
        return None


def _specimen(summary: dict) -> str:
    counts = "".join(
        f'<div><dt>{name.capitalize()}</dt><dd>{int(summary["counts"].get(name, 0))}</dd></div>' for name in SEVERITIES
    )
    top = "".join(
        f'<li><span class="sev sev-{html.escape(sev)}">{html.escape(sev.capitalize())}</span><span>{html.escape(title)}</span></li>'
        for sev, title in summary["top"]
    )
    grade = html.escape(summary["grade"])
    return (
        '<aside class="specimen" aria-labelledby="specimen-label">'
        '<p class="specimen-label" id="specimen-label">Example report, made when this site was built</p>'
        f'<div class="specimen-head"><div class="grade grade-{grade}" role="img" aria-label="Grade {grade}">{grade if len(grade) == 1 else "n/a"}</div>'
        f'<div><p class="specimen-site">{html.escape(summary["site"])}</p><p class="specimen-when">observed {html.escape(summary["date"])}</p></div></div>'
        f'<dl class="counts">{counts}</dl>'
        f"<ol>{top}</ol>"
        '<p class="specimen-links"><a href="/example/">Read the report</a><a href="/example/report.pdf">PDF</a>'
        '<a href="/example/evidence.json">Evidence</a></p></aside>'
    )


# ------------------------------------------------------------------ build

def build(out: Path, example_dir: Path | None = None) -> list[str]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    version, rules = _version(), _rules_summary()
    summary = _example_summary(example_dir) if example_dir else None
    have_example = summary is not None
    written: list[str] = []
    common = {"example": have_example, "version": version, "rules": rules}

    # assets: the stylesheet, the script, the icon, and the fonts the report uses
    assets = out / "assets"
    shutil.copytree(ROOT / "site" / "assets", assets)
    (assets / "fonts").mkdir(exist_ok=True)
    for font in sorted(FONTS.glob("*.woff2")) + sorted(FONTS.glob("OFL-*.txt")):
        shutil.copy(font, assets / "fonts" / font.name)
    written += [f"assets/{p.relative_to(assets)}" for p in sorted(assets.rglob("*")) if p.is_file()]

    # docs
    sources = {p.stem: p for p in (ROOT / "docs").glob("*.md")}
    ordered = [s for s in DOC_ORDER if s in sources] + sorted(set(sources) - set(DOC_ORDER))
    for stem in ordered:
        title, body, tokens = render_markdown(sources[stem].read_text(encoding="utf-8"))
        if stem == "rules":
            body = _severity_pills(body)
        nav_items = [(f"/docs/{s}.html" if s != "index" else "/docs/", DOC_LABELS.get(s, s.title()), s == stem) for s in ordered]
        shell = _docs_shell(nav_items, "Documentation", body, _toc(tokens), wide=(stem == "rules"))
        rel = f"docs/{stem}.html" if stem != "index" else "docs/index.html"
        page(out, rel, title, shell, current="rules" if stem == "rules" else "docs", **common)
        written.append(rel)

    # landing
    landing = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    landing = landing.replace("{{HERO_CLASS}}", " has-specimen" if have_example else "")
    landing = landing.replace("{{SPECIMEN}}", _specimen(summary) if summary else "")
    landing = landing.replace("{{EXAMPLE_LINK}}", '<a href="/example/">See an example report</a>' if have_example else "")
    page(out, "index.html", "scanprivacy: what a website does before the visitor says yes", landing, **common)
    written.append("index.html")

    # 404 for GitHub Pages
    page(
        out, "404.html", "Page not found",
        '<div class="frame"><section class="hero"><div><p class="eyebrow">404</p><h1>That page is not here.</h1>'
        '<p class="lede">It may have moved. The <a href="/docs/">documentation</a> and the <a href="/">home page</a> are the places to start.</p></div></section></div>',
        **common,
    )
    written.append("404.html")
    shutil.copy(ROOT / "site" / "robots.txt", out / "robots.txt")
    written.append("robots.txt")

    # example report
    if have_example:
        md_text = (example_dir / "report.md").read_text(encoding="utf-8")
        md_text = _EMOJI_LEAD.sub(r"\1 ", md_text).replace("<details>", '<details markdown="1">')
        title, body, tokens = render_markdown(md_text)
        side = (
            '<h2>Files</h2><ul>'
            '<li><a href="/example/report.pdf">Report, PDF</a></li>'
            '<li><a href="/example/evidence.json">Evidence, JSON</a></li></ul>'
            '<p class="docs-verify">Check the evidence yourself:<br><code>scanprivacy verify evidence.json</code></p>'
        )
        note = (
            '<div class="report-note"><p><strong>This is output of the engine, not a mock-up.</strong></p>'
            "<p>It was made when this site was built, against a site its author runs. The PDF and the evidence file are published beside it.</p></div>"
        )
        shell = _docs_shell([("/example/", "Report", True)], "Example report", note + body, _toc(tokens), extra_nav=side)
        page(out, "example/index.html", title, shell, current="example", **common)
        written.append("example/index.html")
        for name in ("report.pdf", "evidence.json"):
            if (example_dir / name).is_file():
                shutil.copy(example_dir / name, out / "example" / name)
                written.append(f"example/{name}")

    (out / ".nojekyll").write_text("", encoding="utf-8")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    parser.add_argument("--example", type=Path, default=None)
    args = parser.parse_args(argv)
    for name in build(args.out, args.example):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
