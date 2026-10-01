# Wraith visual identity

## A specter, not another security shield

The identity starts with a faceless, layered spectral form: a metaphor for code
whose origin matters more than its bytes. Graphite, warm ivory and one chartreuse
trace replace the familiar blue-circuit/lock aesthetic. Large quiet typography
and a thin technical footer make the hero readable before it is decorative.

The artwork is **concept art, not a live sensor visualization**. It makes no
claim about detection accuracy, performance or adoption.

## Assets

- [Generated source artwork](wraith-art.png): 2172 × 724 PNG.
- [Static banner](banner.png): 1200 × 400 PNG; first-class reduced-motion fallback.
- [Animated banner](banner.gif): same canvas, a restrained approximately six-second
  provenance trace; static typography, no flashing/glitching or camera zoom.
- [Social preview](social-preview.png): 1280 × 640 PNG for a repository/social card.

The GIF is a real multi-frame image compatible with GitHub README image rendering;
no JavaScript, external animation service or SVG animation is required. The README
uses `<picture>` with `prefers-reduced-motion: reduce` and a permanent still-image
link. Readers can use the still version if their GitHub client ignores that media
preference. Essential project information remains ordinary text, not image-only.

## Provenance

The source artwork was generated for this project using the Codex image-generation
function. Art direction: an asymmetrical graphite panorama, dark negative space on
the left, a faceless ivory gauze/filament specter on the right, and one restrained
chartreuse thread; explicitly exclude text, shields, padlocks, hoodie hackers,
blue circuitry and watermarks. Typography and motion were composed locally in
`scripts/render_brand.py`; the image model did not generate project claims or labels.

No font files are redistributed. Raster typography uses available Windows system
fonts, with a DejaVu fallback on Linux; regeneration on another platform may have
small typographic differences. Keep generated-art provenance disclosed rather
than presenting it as a hand-painted illustration or exclusive trademark.

## Regeneration and checks

With Pillow already installed in your artwork environment:

```bash
python3 scripts/render_brand.py
python3 scripts/check_brand.py
```

`render_preview.py` is a compatibility entry point for the same renderer, not the
old SVG-to-PNG pipeline. No generation API is called on regeneration. The original
`hero.svg` remains a legacy illustration, not the current hero.

The dependency-free checker enforces canvas dimensions, actual GIF frame structure,
frame duration, a 2 MiB GIF budget, alt text and reduced-motion markup. It runs in
release verification without adding Pillow to the sensor or CI dependencies.
The captured exploitation demo remains separate and unchanged in [demo.svg](demo.svg).
