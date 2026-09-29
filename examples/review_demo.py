"""Reproduce the synthetic variant review and optionally check it in Chromium."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys

from charter_replay import app
from charter_replay.reports import report_json_bytes

ROOT = Path(__file__).resolve().parents[1]


def _run(arguments: list[str], expected: int) -> None:
    with redirect_stdout(io.StringIO()):
        actual = app.main(arguments)
    if actual != expected:
        raise RuntimeError(f"{arguments[0]} returned {actual}, expected {expected}")


def run_demo(output: Path, *, browser: bool = False, executable: str | None = None) -> dict:
    """Use only the checked synthetic corpus and repository toy hook programs."""
    if not __debug__:
        raise RuntimeError("demonstration checks require assertions enabled")
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "charter_replay" / "corpora" / "charter"
    pack, replay, review = (output / name for name in ("pack", "replay", "review"))
    previous_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "1767225600"
    try:
        _run(
            [
                "variants", "generate", "--source", str(source),
                "--output", str(pack), "--domain", "posix-external.v1",
                "--recipe", str(ROOT / "examples/packs/charter-posix-v1.json"),
            ],
            0,
        )
        _run(
            [
                "hooks", "--baseline",
                json.dumps([sys.executable, str(ROOT / "examples/toy-guard/guard_v1.py")]),
                "--candidate",
                json.dumps([sys.executable, str(ROOT / "examples/toy-guard/guard_v2.py")]),
                "--corpus", str(pack), "--output", str(replay), "--jobs", "4",
            ],
            1,
        )
    finally:
        if previous_epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous_epoch
    report = replay / "report" / "report.json"
    manifest = report.with_name("run-manifest.json")
    inputs = [
        "--source", str(source), "--pack", str(pack),
        "--report", str(report), "--run-manifest", str(manifest),
    ]
    _run(["variants", "review", *inputs, "--output", str(review)], 1)
    _run(["variants", "verify-review", *inputs, "--review", str(review)], 1)
    coverage = json.loads((review / "variant-coverage.json").read_bytes())
    details = json.loads((review / "variant-review.json").read_bytes())
    assert coverage["counts"] == dict(seeds=50, derived=54, skipped=96)
    assert coverage["by_origin"]["seed"]["newly-allowed"] == 4
    assert coverage["by_origin"]["derived"]["newly-allowed"] == 6
    assert details["shape_disagreements"] == {
        "baseline": {"variants": 6, "seeds": 6},
        "candidate": {"variants": 4, "seeds": 4},
        "shared": {"variants": 3, "seeds": 3},
    }
    result = {
        "schema_version": "variant-review-demo.v1",
        "hooks_exit": 1,
        "review_exit": 1,
        "verify_exit": 1,
        "counts": coverage["counts"],
        "shape_disagreements": details["shape_disagreements"],
    }
    if browser:
        from examples.check_variant_review import check_review

        result["browser"] = check_review(
            review / "report.html", output / "browser", executable
        )
        hostile = json.loads(report.read_bytes())
        for row in hostile["results"]:
            row["candidate"]["reason"] = (
                '\"><img src=x onerror="window.__injected=1">'
                '<script>window.__injected=1</script>|\u202e'
            )
        hostile_report = output / "hostile-report.json"
        hostile_report.write_bytes(report_json_bytes(hostile))
        hostile_review = output / "hostile-review"
        hostile_inputs = [
            "--source", str(source), "--pack", str(pack),
            "--report", str(hostile_report), "--run-manifest", str(manifest),
        ]
        _run(["variants", "review", *hostile_inputs, "--output", str(hostile_review)], 1)
        result["hostile_browser"] = check_review(
            hostile_review / "report.html", output / "hostile-browser", executable
        )
    (output / "demo-result.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--executable", help="optional installed Chromium executable")
    args = parser.parse_args()
    print(json.dumps(run_demo(args.output, browser=args.browser, executable=args.executable), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
