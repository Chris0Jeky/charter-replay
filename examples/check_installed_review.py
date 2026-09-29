"""Exercise the installed wheel without allowing source-checkout imports."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def installed_source(
    module_path: str | Path,
    prefix: str | Path,
    repository: str | Path,
    *,
    isolated: bool,
) -> Path:
    """Fail instead of confusing an editable checkout with a wheel installation."""
    module = Path(module_path).resolve()
    environment = Path(prefix).resolve()
    checkout = Path(repository).resolve()
    corpus = (module.parent / "corpora" / "charter").resolve()
    if (
        not isolated
        or not module.is_file()
        or not module.is_relative_to(environment)
        or module.is_relative_to(checkout)
        or not corpus.is_relative_to(environment)
        or corpus.is_relative_to(checkout)
        or not corpus.is_dir()
    ):
        raise RuntimeError("wheel check requires isolated imports from its environment")
    return corpus


def _run(arguments: list[str], output: Path, expected: int) -> str:
    completed = subprocess.run(
        [sys.executable, "-I", "-m", "charter_replay.app", *arguments],
        cwd=output,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    if completed.returncode != expected:
        raise RuntimeError(
            f"installed {arguments[0]} returned {completed.returncode}, expected {expected}"
        )
    return completed.stdout


def run_check(output: Path) -> dict:
    import charter_replay

    source = installed_source(
        charter_replay.__file__, sys.prefix, ROOT, isolated=bool(sys.flags.isolated)
    )
    output = output.resolve()
    if output.is_relative_to(ROOT):
        raise RuntimeError("wheel check output must be outside the checkout")
    output.mkdir(parents=True, exist_ok=False)
    pack, replay, review = (output / name for name in ("pack", "replay", "review"))
    generated = json.loads(
        _run(
            [
                "variants",
                "generate",
                "--source",
                str(source),
                "--output",
                str(pack),
                "--domain",
                "posix-external.v1",
                "--recipe",
                str(ROOT / "examples/packs/charter-posix-v1.json"),
            ],
            output,
            0,
        )
    )
    _run(
        [
            "hooks",
            "--baseline",
            json.dumps([sys.executable, str(ROOT / "examples/toy-guard/guard_v1.py")]),
            "--candidate",
            json.dumps([sys.executable, str(ROOT / "examples/toy-guard/guard_v2.py")]),
            "--corpus",
            str(pack),
            "--output",
            str(replay),
        ],
        output,
        1,
    )
    report_path = replay / "report" / "report.json"
    inputs = [
        "--source",
        str(source),
        "--pack",
        str(pack),
        "--report",
        str(report_path),
        "--run-manifest",
        str(report_path.with_name("run-manifest.json")),
    ]
    _run(["variants", "review", *inputs, "--output", str(review)], output, 1)
    _run(["variants", "verify-review", *inputs, "--review", str(review)], output, 1)
    report = json.loads(report_path.read_bytes())
    counts = {"seeds": 50, "derived": 54, "skipped": 96}
    if generated["counts"] != counts or report["counts"]["newly-allowed"] != 10:
        raise RuntimeError("installed wheel does not reproduce the checked toy fixture")
    if report["gate"]["status"] != "fail":
        raise RuntimeError("installed wheel did not preserve the regression gate")
    entrypoint = Path(sys.executable).with_name(
        "charter-replay.exe" if os.name == "nt" else "charter-replay"
    )
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    help_result = subprocess.run(
        [str(entrypoint), "--help"],
        cwd=output,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    if "variants" not in help_result.stdout:
        raise RuntimeError("installed console entry point is missing variants")
    result = {
        "schema_version": "installed-review-check.v1",
        "isolated_imports": True,
        "counts": counts,
        "hooks_exit": 1,
        "review_exit": 1,
        "verify_exit": 1,
        "console_entry_point": "checked",
    }
    (output / "installed-check.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run_check(args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
