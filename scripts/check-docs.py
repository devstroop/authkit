#!/usr/bin/env python3
"""Check local Markdown links and heading anchors.

External links are not fetched. This keeps the check deterministic and usable offline;
link rot in external documentation is reviewed separately.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
FENCE_RE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)


def slugify(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def headings(path: Path) -> set[str]:
    text = FENCE_RE.sub("", path.read_text(encoding="utf-8", errors="ignore"))
    return {slugify(match) for match in HEADING_RE.findall(text)}


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    text = FENCE_RE.sub("", path.read_text(encoding="utf-8", errors="ignore"))
    text = INLINE_CODE_RE.sub("", text)

    for match in LINK_RE.finditer(text):
        raw = match.group(1).strip()
        if raw.startswith(("http://", "https://", "mailto:", "#")):
            continue

        target_part, _, anchor = raw.partition("#")
        target_part = unquote(target_part)
        target = (path.parent / target_part).resolve() if target_part else path

        try:
            target.relative_to(ROOT)
        except ValueError:
            problems.append(f"{path.relative_to(ROOT)}: link escapes the repository: {raw}")
            continue

        if not target.exists():
            problems.append(f"{path.relative_to(ROOT)}: missing target: {raw}")
            continue

        if anchor and target.is_file() and target.suffix == ".md":
            if slugify(anchor) not in headings(target):
                problems.append(f"{path.relative_to(ROOT)}: missing anchor: {raw}")

    return problems


def main() -> int:
    problems: list[str] = []
    for path in sorted(ROOT.rglob("*.md")):
        if ".git" in path.parts:
            continue
        problems.extend(check_file(path))

    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(f"\n{len(problems)} documentation problem(s) found.", file=sys.stderr)
        return 1

    count = sum(1 for path in ROOT.rglob("*.md") if ".git" not in path.parts)
    print(f"documentation checks passed ({count} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
