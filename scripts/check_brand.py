#!/usr/bin/env python3
"""Dependency-free contract for GitHub banner assets and reduced-motion markup."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]


def png_size(path):
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError(f"{path.name}: invalid PNG header")
    return struct.unpack(">II", data[16:24])


def gif_metadata(path):
    data = path.read_bytes()
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        raise ValueError("invalid GIF header")
    width, height = struct.unpack("<HH", data[6:10])
    packed = data[10]
    cursor = 13 + (3 * 2 ** ((packed & 7) + 1) if packed & 128 else 0)
    durations = []
    frames = 0
    delay = 0

    def subblocks(position):
        while True:
            if position >= len(data):
                raise ValueError("truncated GIF block")
            size = data[position]
            position += 1
            if not size:
                return position
            position += size
            if position > len(data):
                raise ValueError("truncated GIF payload")

    while cursor < len(data):
        marker = data[cursor]
        cursor += 1
        if marker == 0x3B:
            return width, height, frames, durations
        if marker == 0x21:
            if cursor >= len(data):
                raise ValueError("truncated extension")
            label = data[cursor]
            cursor += 1
            if label == 0xF9:
                if cursor + 6 > len(data) or data[cursor] != 4:
                    raise ValueError("invalid graphic control block")
                delay = struct.unpack("<H", data[cursor + 2:cursor + 4])[0] * 10
            cursor = subblocks(cursor)
        elif marker == 0x2C:
            if cursor + 9 > len(data):
                raise ValueError("truncated frame")
            x, y, fw, fh = struct.unpack("<HHHH", data[cursor:cursor + 8])
            if not fw or not fh or x + fw > width or y + fh > height:
                raise ValueError("frame outside logical canvas")
            packed = data[cursor + 8]
            cursor += 9 + (3 * 2 ** ((packed & 7) + 1) if packed & 128 else 0)
            cursor = subblocks(cursor + 1)  # skip LZW minimum code size
            frames += 1
            durations.append(delay)
        else:
            raise ValueError(f"unexpected GIF marker: {marker}")
    raise ValueError("missing GIF trailer")


def validate(root):
    errors = []
    try:
        assert png_size(root / "docs/banner.png") == (1200, 400), "static banner dimensions"
        assert png_size(root / "docs/social-preview.png") == (1280, 640), "social preview dimensions"
        gif = root / "docs/banner.gif"
        width, height, frames, durations = gif_metadata(gif)
        assert (width, height) == (1200, 400), "GIF canvas"
        assert frames >= 24, "animation requires distinct frames"
        assert all(delay >= 80 for delay in durations), "avoid rapid frame changes"
        assert 4000 <= sum(durations) <= 10000, "animation cycle must be restrained"
        assert gif.stat().st_size <= 2 * 1024 * 1024, "GIF exceeds 2 MiB budget"
        text = (root / "README.md").read_text(encoding="utf-8")
        assert 'media="(prefers-reduced-motion: reduce)"' in text, "reduced-motion fallback missing"
        assert 'srcset="docs/banner.png"' in text and 'src="docs/banner.gif"' in text, "hero assets not wired"
        assert 'alt="Wraith' in text, "hero needs meaningful alt text"
        assert (root / "docs/brand.md").is_file(), "art provenance/regeneration guide missing"
    except (OSError, AssertionError, ValueError, struct.error) as error:
        errors.append(str(error))
    return errors


def main():
    errors = validate(ROOT)
    if errors:
        print("FAIL: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("PASS: PNG sizes, valid multi-frame GIF, timing/size budget, alt and reduced-motion fallback.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
