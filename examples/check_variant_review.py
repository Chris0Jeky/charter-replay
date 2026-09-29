"""Optional offline browser checks; requires development-only Playwright."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def check_review(html_path: Path, evidence: Path, executable: str | None = None) -> dict:
    if not __debug__:
        raise RuntimeError("browser checks require assertions enabled")
    from playwright.sync_api import sync_playwright

    content = html_path.read_bytes()
    evidence.mkdir(parents=True, exist_ok=False)
    observations = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=executable)
        try:
            for label, width, javascript in (
                ("desktop", 1440, True),
                ("mobile", 390, True),
                ("no-script", 390, False),
            ):
                context = browser.new_context(
                    viewport={"width": width, "height": 1000},
                    java_script_enabled=javascript,
                )
                requests, errors = [], []
                context.route("**/*", lambda route: route.abort())
                page = context.new_page()
                page.on("request", lambda request: requests.append(request.url))
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.set_content(content.decode("utf-8"), wait_until="load")
                assert page.locator("#variant-review").is_visible()
                assert page.locator("#variant-review table").count() == 5
                total = page.locator("[data-case]").count()
                assert total > 0
                matrices = page.locator("#variant-review details")
                matrices.locator("summary").click()
                assert matrices.locator("table:visible").count() == 3
                matrices.locator("summary").click()
                if javascript:
                    assert page.locator("#filters").is_visible()
                    derived = page.locator('[data-case][data-origin="generated-variant"]').count()
                    page.locator("#filter-origin").select_option("generated-variant")
                    assert page.locator("[data-case]:visible").count() == derived
                    page.locator("#search").fill("__no_matching_charter_case__")
                    assert page.locator("[data-case]:visible").count() == 0
                    page.locator("#reset").focus()
                    page.keyboard.press("Enter")
                    assert page.locator("[data-case]:visible").count() == total
                    assert not page.evaluate("Boolean(window.injected || window.__injected)")
                else:
                    assert not page.locator("#filters").is_visible()
                    assert page.locator("[data-case]:visible").count() == total
                assert page.locator("img").count() == 0
                assert page.evaluate("document.body.scrollWidth <= innerWidth + 1")
                assert not requests, requests
                assert not errors, errors
                page.screenshot(path=str(evidence / f"{label}.png"), full_page=True)
                observations.append({
                    "view": label, "width": width, "javascript": javascript,
                    "cases": total, "requests": len(requests), "script_errors": len(errors),
                    "body_overflow": False,
                })
                context.close()
            result = {
                "schema_version": "variant-browser-check.v1",
                "html_sha256": hashlib.sha256(content).hexdigest(),
                "browser": browser.version,
                "checks": observations,
                "limitations": [
                    "HTML is loaded in memory with its own CSP; local-file URL opening is not tested.",
                    "This checks one Chromium engine, not other engines or screen-reader behavior.",
                    "Screenshots contain full corpus content and are not anonymized.",
                ],
            }
            (evidence / "browser-check.json").write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            return result
        finally:
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("html", type=Path)
    parser.add_argument("--evidence", type=Path, required=True, help="new evidence directory")
    parser.add_argument("--executable", help="optional installed Chromium executable")
    args = parser.parse_args()
    print(json.dumps(check_review(args.html, args.evidence, args.executable), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
