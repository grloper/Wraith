#!/usr/bin/env python3
"""Record actual local fixture output as portable SVG and asciicast v2."""
import html
import json
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [("benign", 0, []), ("shellcode-sim", 3, []), ("shellcode-sim", 3, ["--block"])]


def main():
    subprocess.run(["cargo", "build", "--release", "--locked", "--quiet"], cwd=ROOT, check=True)
    rows = []
    frames = []
    start = time.monotonic()
    for target, expected, flags in CASES:
        display = f"$ wraith run {' '.join(flags)} -- {target}".replace("  ", " ")
        command = [str(ROOT / "target/release/wraith"), "run", *flags, "--", str(ROOT / f"target/release/{target}")]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        if result.returncode != expected:
            raise SystemExit(f"{target}: expected {expected}, got {result.returncode}: {result.stdout}")
        # Preserve evidence, abbreviating long machine-specific paths only for the visual.
        output = result.stdout.replace(str(ROOT / "target/release") + "/", "")
        text = display + "\n" + output + f"sensor exit: {result.returncode}\n\n"
        frames.append([round(time.monotonic() - start, 3), "o", text.replace("\n", "\r\n")])
        for line in text.splitlines():
            # SVG uses a fixed-width terminal grid; wrap rather than hide evidence.
            rows.extend(line[i:i + 106] for i in range(0, len(line), 106)) if line else rows.append("")
    width, height = 1120, 106 + 20 * len(rows)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">', '<title id="title">Wraith: recorded local provenance demo</title>', '<desc id="desc">Actual Linux fixture output: benign control, injected syscall detection, and block enforcement. Paths abbreviated; PIDs, addresses and counts vary by run.</desc>', f'<rect width="{width}" height="{height}" rx="18" fill="#0c1220"/>', '<circle cx="28" cy="28" r="5" fill="#fb7185"/><circle cx="48" cy="28" r="5" fill="#fbbf24"/><circle cx="68" cy="28" r="5" fill="#34d399"/>', '<text x="92" y="34" fill="#94a3b8" font-family="monospace" font-size="14">WRAITH / recorded fixture session / Linux x86-64</text>']
    for index, line in enumerate(rows):
        color = "#5eead4" if line.startswith("$") else "#fda4af" if "CRITICAL" in line else "#cbd5e1"
        svg.append(f'<text x="24" y="{76 + index * 20}" fill="{color}" font-family="monospace" font-size="14">{html.escape(line)}</text>')
    svg.append('</svg>')
    (ROOT / "docs/demo.svg").write_text("\n".join(svg) + "\n", encoding="utf-8")
    header = {"version": 2, "width": 106, "height": 36, "title": "Wraith local fixture demo", "env": {"TERM": "xterm-256color"}}
    (ROOT / "docs/demo.cast").write_text("\n".join(json.dumps(item) for item in [header, *frames]) + "\n", encoding="utf-8")
    print("Recorded docs/demo.svg and docs/demo.cast from successful real fixture runs.")


if __name__ == "__main__":
    main()
