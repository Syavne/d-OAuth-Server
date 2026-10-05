#!/usr/bin/env python3
"""Local documentation link checker for d-OAuth.

This is the "markdown-link-check" equivalent named by task 48. It validates
every relative Markdown link in the root README.md, root AGENTS.md, and the
docs/*.md guides, so CI fails when a doc points at a file or heading that no
longer exists. External http(s), mailto:, and tel: targets are ignored: CI has
no network dependency and the RFC references are stable public URLs.

Usage:
  python3 scripts/check_doc_links.py            # scan the default set
  python3 scripts/check_doc_links.py README.md  # scan explicit files

Exit code 0 when every relative link resolves, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Inline Markdown links only: [text](target). The docs use no reference-style
# links, so a simpler parser is enough and avoids a Markdown dependency.
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILES = [REPO_ROOT / "README.md", REPO_ROOT / "AGENTS.md"]
DEFAULT_FILES += sorted((REPO_ROOT / "docs").glob("*.md"))


def slugify(text: str) -> str:
    """GitHub-style heading slug: lowercase, drop punctuation, spaces to '-'.

    Fenced code blocks are stripped by the caller, so inline code backticks
    may still appear; they are removed here. Trailing duplicate-numbering
    suffixes are not modeled because the docs use unique headings.
    """
    text = text.replace("`", "")
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text).strip("-")


def headings_of(path: Path) -> set[str]:
    """Every heading slug in a Markdown file, ignoring fenced code blocks."""
    slugs: set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            slugs.add(slugify(match.group(2)))
    return slugs


def check_file(path: Path, problems: list[str]) -> None:
    if not path.exists():
        problems.append(f"missing doc: {path.relative_to(REPO_ROOT)}")
        return
    text = path.read_text(encoding="utf-8")
    for target in LINK_RE.findall(text):
        if target.startswith(EXTERNAL_PREFIXES):
            continue
        if target.startswith("#"):
            anchor = target[1:]
            if anchor and slugify(anchor) not in headings_of(path):
                problems.append(f"{path.relative_to(REPO_ROOT)}: missing anchor #{anchor}")
            continue
        file_part, _, anchor = target.partition("#")
        resolved = (path.parent / file_part).resolve()
        if not resolved.exists():
            problems.append(f"{path.relative_to(REPO_ROOT)}: broken link -> {target}")
            continue
        if anchor and resolved.suffix == ".md":
            if slugify(anchor) not in headings_of(resolved):
                problems.append(
                    f"{path.relative_to(REPO_ROOT)}: missing anchor #{anchor} in {file_part}"
                )


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv[1:]] if len(argv) > 1 else DEFAULT_FILES
    problems: list[str] = []
    for path in files:
        check_file(path if path.is_absolute() else REPO_ROOT / path, problems)
    if problems:
        print("doc link check FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"doc link check passed: {len(files)} file(s) scanned")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
