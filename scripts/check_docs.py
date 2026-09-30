#!/usr/bin/env python3
"""Offline documentation gate: local links, SVGs, recordings and release surfaces."""
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs/operations.md", "docs/threat-model.md", "docs/research.md", "docs/launch.md", "docs/demo.svg", "docs/demo.cast", ".github/workflows/ci.yml", ".github/workflows/release.yml"]


def validate(root):
    errors = []
    for relative in REQUIRED:
        if not (root / relative).is_file():
            errors.append(f"missing: {relative}")
    documents = [root / "README.md", *sorted((root / "docs").glob("*.md")), *sorted(root.glob("*.md"))]
    for path in set(documents):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for link in re.findall(r"\]\(([^)\s]+)(?:\s+[^)]*)?\)", text):
            if link.startswith(("https://", "http://", "mailto:", "#")):
                continue
            target = link.split("#", 1)[0]
            if target and not (path.parent / target).exists():
                errors.append(f"{path.relative_to(root)}: broken link {link}")
    for path in (root / "docs").glob("*.svg"):
        try:
            tree = ET.parse(path)
            if tree.getroot().tag != "{http://www.w3.org/2000/svg}svg":
                errors.append(f"not SVG: {path.name}")
        except ET.ParseError as error:
            errors.append(f"invalid SVG {path.name}: {error}")
    cast = root / "docs/demo.cast"
    if cast.exists():
        try:
            records = [json.loads(line) for line in cast.read_text().splitlines()]
            assert records[0]["version"] == 2
            assert len(records) >= 4
            previous = 0
            for frame in records[1:]:
                assert len(frame) == 3 and frame[1] == "o" and isinstance(frame[2], str)
                assert frame[0] >= previous
                previous = frame[0]
            assert "CRITICAL" in "".join(frame[2] for frame in records[1:])
        except (ValueError, KeyError, IndexError, AssertionError, TypeError) as error:
            errors.append(f"invalid demo recording: {error}")
    return errors


def main():
    errors = validate(ROOT)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("PASS: required release docs, relative links, SVG syntax and actual demo recording.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
