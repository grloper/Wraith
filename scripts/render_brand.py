#!/usr/bin/env python3
"""Optional Pillow renderer: generated source art -> static/GIF/social identity.

No generation API or network call is made here. Install Pillow separately to
regenerate; the sensor and CI asset checker have no Pillow dependency.
"""
from pathlib import Path
import math
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SIZE = (1200, 400)
INK = (11, 12, 10)
IVORY = (240, 237, 223)
MUTED = (164, 165, 151)
ACID = (211, 239, 133)


def font(size, mono=False, heading=False):
    windows = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    candidates = ([windows / "bahnschrift.ttf"] if heading else [])
    candidates += [windows / ("consola.ttf" if mono else "segoeui.ttf")]
    candidates += [Path("/usr/share/fonts/truetype/dejavu") / ("DejaVuSansMono.ttf" if mono else "DejaVuSans.ttf")]
    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise RuntimeError("Install DejaVu fonts or use Windows system fonts to render the identity.")


def tracked(draw, position, text, face, fill, spacing=2):
    x, y = position
    for char in text:
        draw.text((x, y), char, font=face, fill=fill)
        x += draw.textlength(char, font=face) + spacing


def compose(source):
    base = source.convert("RGB").resize(SIZE, Image.Resampling.LANCZOS)
    # A dark editorial scrim gives small typography a predictable contrast floor.
    scrim = Image.new("RGBA", SIZE)
    sd = ImageDraw.Draw(scrim)
    for x in range(720):
        sd.line((x, 0, x, 399), fill=(*INK, int(112 * (1 - x / 720))))
    base = Image.alpha_composite(base.convert("RGBA"), scrim).convert("RGB")
    draw = ImageDraw.Draw(base)
    draw.line((68, 51, 92, 51), fill=ACID, width=2)
    tracked(draw, (105, 41), "EXECUTION LEAVES A TRACE", font(13, mono=True), ACID, 2)
    tracked(draw, (62, 120), "WRAITH", font(122, heading=True), IVORY, 3)
    draw.text((69, 273), "Not the bytes. The place they execute.", font=font(21), fill=IVORY)
    tracked(draw, (70, 310), "SYSCALL PROVENANCE / RUNTIME SENSOR", font(11, mono=True), MUTED, 1.4)
    draw.line((68, 353, 1132, 353), fill=(67, 69, 60), width=1)
    tracked(draw, (70, 368), "OBSERVE   /   CLASSIFY   /   CORRELATE", font(10, mono=True), MUTED, 1.1)
    tracked(draw, (942, 368), "LINUX x86-64  /  RUST", font(10, mono=True), IVORY, .3)
    return base


def animate(base):
    # Only the small trace/marker moves: no flashing title, zoom or heavy photo
    # changes. A shared palette permits efficient GIF delta-frame encoding.
    sample = base.copy()
    ImageDraw.Draw(sample).rectangle((0, 0, 16, 16), fill=ACID)
    palette = sample.quantize(colors=255, method=Image.Quantize.MEDIANCUT)
    frames = []
    for index in range(48):
        phase = index / 48
        layer = Image.new("RGBA", SIZE)
        draw = ImageDraw.Draw(layer)
        opacity = int(145 * math.sin(math.pi * phase) ** 2)
        x = int(696 + 430 * phase)
        y = int(184 + 4 * math.sin(phase * math.tau))
        for offset in range(64):
            alpha = int(opacity * (1 - offset / 64) * .55)
            draw.line((x - offset, y, x - offset, y + 1), fill=(*ACID, alpha))
        draw.ellipse((x - 9, y - 9, x + 9, y + 9), fill=(*ACID, opacity // 7))
        draw.ellipse((x - 3, y - 3, x + 3, y + 3), fill=(*ACID, opacity))
        frame = Image.alpha_composite(base.convert("RGBA"), layer).convert("RGB")
        frames.append(frame.quantize(palette=palette, dither=Image.Dither.NONE))
    frames[0].save(DOCS / "banner.gif", save_all=True, append_images=frames[1:],
                   duration=125, loop=0, optimize=True, disposal=1)


def main():
    with Image.open(DOCS / "wraith-art.png") as source:
        banner = compose(source)
    banner.save(DOCS / "banner.png", optimize=True)
    animate(banner)
    card = Image.new("RGB", (1280, 640), INK)
    card.paste(banner, (40, 96))
    draw = ImageDraw.Draw(card)
    tracked(draw, (110, 540), "GRLOPER / WRAITH", font(13, mono=True), ACID, 2)
    draw.text((110, 571), "A small Rust sensor. A different question about execution.", font=font(18), fill=MUTED)
    card.save(DOCS / "social-preview.png", optimize=True)
    print("Rendered banner.png, banner.gif, social-preview.png from wraith-art.png")


if __name__ == "__main__":
    main()
