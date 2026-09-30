#!/usr/bin/env python3
"""Optional: render the authored SVG as a PNG using installed Playwright/Chromium."""
from pathlib import Path
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1200, "height": 360}, device_scale_factor=1)
    page.goto((root / "docs/hero.svg").as_uri())
    page.screenshot(path=str(root / "docs/social-preview.png"))
    browser.close()
print("Rendered docs/social-preview.png from docs/hero.svg")
