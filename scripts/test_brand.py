#!/usr/bin/env python3
"""Unit and bundle regressions for the dependency-free brand contract."""
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from check_brand import ROOT, gif_metadata, png_size, validate


class BrandContractTests(unittest.TestCase):
    def test_actual_bundle_passes(self):
        self.assertEqual(validate(ROOT), [])

    def test_non_png_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.png"
            path.write_bytes(b"not a png")
            with self.assertRaisesRegex(ValueError, "invalid PNG"):
                png_size(path)

    def test_missing_gif_trailer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.gif"
            path.write_bytes((ROOT / "docs/banner.gif").read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "missing GIF trailer"):
                gif_metadata(path)

    def test_truncated_control_extension_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.gif"
            path.write_bytes(b"GIF89a" + struct.pack("<HH", 1200, 400) + b"\0\0\0" + b"\x21\xf9\x04\0")
            with self.assertRaisesRegex(ValueError, "invalid graphic control"):
                gif_metadata(path)

    def test_reduced_motion_markup_cannot_be_removed_silently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            for name in ("banner.png", "banner.gif", "social-preview.png", "brand.md"):
                shutil.copyfile(ROOT / "docs" / name, root / "docs" / name)
            text = (ROOT / "README.md").read_text(encoding="utf-8")
            (root / "README.md").write_text(text.replace('media="(prefers-reduced-motion: reduce)"', ''), encoding="utf-8")
            self.assertIn("reduced-motion fallback missing", validate(root))


if __name__ == "__main__":
    unittest.main()
