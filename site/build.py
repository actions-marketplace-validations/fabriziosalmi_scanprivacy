"""Build the static site: the landing page, the docs as HTML, an example report.

    python site/build.py OUT_DIR [--example EXAMPLE_DIR]

`docs/*.md` become `OUT_DIR/docs/*.html`, `site/index.html` and `robots.txt` are
copied, and, when an example directory is given and holds a report, it is
published under `OUT_DIR/example/`. The example report is never committed (a scan
result names a site and grades it; see tests/test_repo_hygiene.py): the Pages
workflow makes it at deploy time, from the operator's own site.
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://github.com/fabriziosalmi/scanprivacy"

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - scanprivacy</title>
<link rel="canonical" href="https://scanprivacy.org/{path}">
<style>
:root{{--bg:#fbfbf9;--fg:#16181d;--mut:#5b6270;--line:#e3e4e0;--acc:#0b5fff;--code:#f2f3ef}}
@media (prefers-color-scheme:dark){{:root{{--bg:#101215;--fg:#e9ebee;--mut:#9aa1ad;--line:#262a31;--acc:#6ea0ff;--code:#1c2026}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:17px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
.w{{max-width:820px;margin:0 auto;padding:0 16px}}
header{{border-bottom:1px solid var(--line)}}
nav{{display:flex;gap:20px;align-items:center;padding:16px 0;flex-wrap:wrap}}
nav b{{margin-right:auto;font-size:18px}}
a{{color:var(--acc);text-decoration:none}}a:hover{{text-decoration:underline}}
h1{{font-size:32px;line-height:1.2;margin:40px 0 16px}}h2{{margin:40px 0 10px}}
pre{{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:14px 16px;overflow-x:auto;font:14px/1.55 ui-monospace,Menlo,monospace}}
code{{font:.9em ui-monospace,Menlo,monospace}}
table{{border-collapse:collapse;display:block;overflow-x:auto}}th,td{{border:1px solid var(--line);padding:6px 10px;text-align:left}}
footer{{border-top:1px solid var(--line);margin-top:56px;padding:24px 0 40px;color:var(--mut);font-size:15px}}
</style>
</head>
<body>
<header><div class="w"><nav><b><a href="/">scanprivacy</a></b>
<a href="/docs/">Docs</a><a href="/docs/rules.html">Rules</a>{example_nav}<a href="{source}">GitHub</a></nav></div></header>
<main class="w">
{body}
</main>
<footer><div class="w">scanprivacy is free software under the <a href="https://www.gnu.org/licenses/agpl-3.0.html">AGPL-3.0</a>.</div></footer>
</body>
</html>
"""

_LINK = re.compile(r'href="([^"#:]+?)(\.md)?(#[^"]*)?"')


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


def render_markdown(text: str) -> tuple[str, str]:
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
    body = _rewrite_links(md.convert(text))
    first = re.search(r"^#\s+(.+)$", text, re.M)
    return (html.unescape(first.group(1)) if first else "scanprivacy"), body


def write_page(out: Path, rel: str, title: str, body: str, example: bool) -> None:
    target = out / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    nav = '<a href="/example/">Example report</a>' if example else ""
    target.write_text(
        PAGE.format(title=html.escape(title), path=rel.removesuffix("index.html"), body=body, source=SOURCE, example_nav=nav),
        encoding="utf-8",
    )


def build(out: Path, example_dir: Path | None = None) -> list[str]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    have_example = bool(example_dir and (example_dir / "report.md").is_file())
    written: list[str] = []

    for source in sorted((ROOT / "docs").glob("*.md")):
        title, body = render_markdown(source.read_text(encoding="utf-8"))
        rel = f"docs/{source.stem}.html"
        write_page(out, rel, title, body, have_example)
        written.append(rel)

    index = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    section = ""
    if have_example:
        section = (
            '<h2>An example report</h2><p>A real scan of a real site, made by this engine when this page was built: '
            '<a href="/example/">read the report</a>, <a href="/example/report.pdf">PDF</a>, or check the '
            '<a href="/example/evidence.json">evidence</a> yourself with <code>scanprivacy verify evidence.json</code>.</p>'
        )
    (out / "index.html").write_text(index.replace("<!--EXAMPLE-->", section), encoding="utf-8")
    shutil.copy(ROOT / "site" / "robots.txt", out / "robots.txt")
    written += ["index.html", "robots.txt"]

    if have_example:
        title, body = render_markdown((example_dir / "report.md").read_text(encoding="utf-8"))
        note = (
            "<p><em>Example output of this engine against a site its author runs. "
            "The PDF and the evidence file are published next to it.</em></p>"
        )
        write_page(out, "example/index.html", title, note + body, True)
        written.append("example/index.html")
        for name in ("report.pdf", "evidence.json"):
            if (example_dir / name).is_file():
                (out / "example").mkdir(exist_ok=True)
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
