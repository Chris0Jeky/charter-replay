"""Console entry point: measure a PreToolUse hook against a replay corpus.

`replay` and `validate` are the unchanged replay v0 kernel commands. `record`
runs one hook over a corpus and writes a recorded decision source; `hooks`
records two hooks and compares them through the kernel; `import` builds a
private local corpus from agent transcripts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from charter_replay import cli as kernel
from charter_replay.hooks import ASK_EFFECTS, RUNTIMES, HookSpec, HookSpecError
from charter_replay.hooks import parse_hook_command, record_hook
from charter_replay.policy_sources import SourceFailure
from charter_replay.metrics import render_label_summary, score_labels

from charter_replay.review_reports import markdown_literal

PROG = "charter-replay"
SUMMARY_JSON = "summary.json"
SUMMARY_MD = "summary.md"


def _positive_jobs(value: str) -> int:
    try:
        jobs = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("jobs must be a positive integer") from exc
    if jobs < 1:
        raise argparse.ArgumentTypeError("jobs must be a positive integer")
    return jobs


def _add_hook_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime", choices=RUNTIMES, default="claude")
    parser.add_argument(
        "--ask-as",
        choices=ASK_EFFECTS,
        default="deny",
        help="replay effect for an `ask` decision (default: deny)",
    )
    parser.add_argument(
        "--hook-timeout",
        type=kernel._parse_timeout,
        default=10.0,
        help="seconds per hook invocation (default: 10)",
    )
    parser.add_argument(
        "--jobs", type=_positive_jobs, default=4, help="parallel invocations"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("replay", help="compare two decision sources (kernel)")
    sub.add_parser("validate", help="validate a corpus (kernel)")

    record = sub.add_parser("record", help="record one hook's decisions")
    record.add_argument("--hook", required=True, help="hook command (words or JSON)")
    record.add_argument("--corpus", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--policy-id", default="hook")
    record.add_argument("--workspace", help="template directory for the hook's cwd")
    _add_hook_options(record)

    hooks = sub.add_parser("hooks", help="record and compare two hooks")
    hooks.add_argument("--baseline", required=True, help="baseline hook command")
    hooks.add_argument("--candidate", required=True, help="candidate hook command")
    hooks.add_argument("--corpus", required=True)
    hooks.add_argument("--output", required=True)
    hooks.add_argument("--baseline-workspace")
    hooks.add_argument("--candidate-workspace")
    hooks.add_argument(
        "--workspace", help="template directory for both sides unless overridden"
    )
    hooks.add_argument("--fail-on", default=",".join(kernel.DEFAULT_FAIL_ON))
    _add_hook_options(hooks)

    importer = sub.add_parser("import", help="build a private corpus from transcripts")
    importer.add_argument("--claude-root", help="default: ~/.claude/projects")
    importer.add_argument("--codex-root", help="default: ~/.codex/sessions")
    importer.add_argument("--output", default=".local/private-corpus")
    importer.add_argument("--keep-duplicates", action="store_true")
    importer.add_argument("--limit", type=int, default=0)
    importer.add_argument(
        "--sample", type=int, default=0, help="keep a seeded random sample"
    )
    importer.add_argument("--seed", type=int, default=0)
    importer.add_argument(
        "--redact-terms", help="file with extra words to redact, one per line"
    )
    return parser


def _load_events(corpus: str) -> list[dict[str, Any]]:
    loaded = kernel._load_charter_corpus(corpus)
    return loaded.events


def _spec(args: argparse.Namespace, command: str) -> HookSpec:
    return HookSpec(
        argv=parse_hook_command(command),
        runtime=args.runtime,
        timeout=args.hook_timeout,
        ask_effect=args.ask_as,
    )


def _optional_path(value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    if not path.is_dir():
        raise HookSpecError(f"workspace template is not a directory: {value}")
    return path


def _run_record(args: argparse.Namespace) -> int:
    events = _load_events(args.corpus)
    summary = record_hook(
        _spec(args, args.hook),
        events,
        Path(args.output),
        policy_id=args.policy_id,
        workspace_template=_optional_path(args.workspace),
        jobs=args.jobs,
    )
    print(json.dumps(summary, sort_keys=True))
    return kernel.EXIT_SOURCE_FAILED if summary["failures"] else kernel.EXIT_OK


def breakdown(report: dict[str, Any]) -> dict[str, Any]:
    """Count kernel classifications by case class and case family."""

    by_class: dict[str, dict[str, int]] = {}
    by_family: dict[str, dict[str, int]] = {}
    effects: dict[str, dict[str, int]] = {"baseline": {}, "candidate": {}}
    for result in report["results"]:
        case = result.get("case") or {}
        label = result["classification"]
        for table, key in (
            (by_class, case.get("case_class", "unlabelled")),
            (by_family, case.get("case_family", "unlabelled")),
        ):
            row = table.setdefault(key, {})
            row[label] = row.get(label, 0) + 1
        for side in ("baseline", "candidate"):
            effect = result[side]["effect"]
            effects[side][effect] = effects[side].get(effect, 0) + 1
    return {
        "counts": report["counts"],
        "gate": report["gate"],
        "source_failures": report["source_failures"],
        "label_agreement": score_labels(report),
        "effects": effects,
        "by_case_class": dict(sorted(by_class.items())),
        "by_case_family": dict(sorted(by_family.items())),
    }


def _changed(row: dict[str, int]) -> int:
    return sum(count for label, count in row.items() if label != "unchanged")


def render_summary(summary: dict[str, Any], outcomes: dict[str, Any]) -> str:
    counts = summary["counts"]
    lines = [
        "# Hook decision diff",
        "",
        f"Gate: **{summary['gate']['status']}** "
        f"(fail on: {', '.join(summary['gate']['fail_on'])})",
        "",
        "| class | events |",
        "|---|---:|",
    ]
    lines += [f"| {name} | {count} |" for name, count in counts.items()]
    lines += ["", "## Hook outcomes", "", "| outcome | baseline | candidate |"]
    lines += ["|---|---:|---:|"]
    for name in outcomes["baseline"]["outcomes"]:
        base = outcomes["baseline"]["outcomes"][name]
        cand = outcomes["candidate"]["outcomes"][name]
        if base or cand:
            lines.append(f"| {name} | {base} | {cand} |")
    classes = list(counts)
    lines += ["", "## By case class", ""]
    lines += ["| case class | " + " | ".join(classes) + " |"]
    lines += ["|---|" + "---:|" * len(classes)]
    for key, row in summary["by_case_class"].items():
        cells = " | ".join(str(row.get(name, 0)) for name in classes)
        lines.append(f"| {markdown_literal(key)} | {cells} |")
    changed = {k: v for k, v in summary["by_case_family"].items() if _changed(v)}
    if changed:
        lines += ["", "## Families with changes", "", "| family | changes |"]
        lines += ["|---|---|"]
        for key, row in changed.items():
            detail = ", ".join(
                f"{label} {count}"
                for label, count in sorted(row.items())
                if label != "unchanged"
            )
            lines.append(f"| {markdown_literal(key)} | {detail} |")
    lines += ["", render_label_summary(summary["label_agreement"])]
    lines += [
        "",
        "Recorded hook decisions were compared; no corpus command was executed.",
        "",
    ]
    return "\n".join(lines)


def _run_hooks(args: argparse.Namespace) -> int:
    corpus = kernel._load_charter_corpus(args.corpus)
    events = corpus.events
    output = Path(args.output)
    shared = _optional_path(args.workspace)
    # Admit both sides and the comparison gate before either hook can run.
    sides = [
        (name, _spec(args, command), _optional_path(workspace) or shared)
        for name, command, workspace in (
            ("baseline", args.baseline, args.baseline_workspace),
            ("candidate", args.candidate, args.candidate_workspace),
        )
    ]
    replay_args = kernel._parser().parse_args(
        [
            "replay",
            "--baseline",
            f"recorded:{output / 'baseline' / 'decisions.jsonl'}",
            "--candidate",
            f"recorded:{output / 'candidate' / 'decisions.jsonl'}",
            "--corpus",
            args.corpus,
            "--output",
            str(output / "report"),
            "--fail-on",
            args.fail_on,
        ]
    )
    outcomes: dict[str, Any] = {}
    for name, spec, workspace in sides:
        outcomes[name] = record_hook(
            spec,
            events,
            output / name,
            policy_id=f"{name}-hook",
            workspace_template=workspace,
            jobs=args.jobs,
        )
    # A report left by an earlier run must not be summarised as this one.
    for stale in (output / "report" / "report.json", output / SUMMARY_JSON):
        stale.unlink(missing_ok=True)
    (output / SUMMARY_MD).unlink(missing_ok=True)
    code = kernel._run_replay(
        replay_args,
        captured_corpus=corpus,
        baseline_failures=tuple(
            SourceFailure(**failure) for failure in outcomes["baseline"]["failures"]
        ),
        candidate_failures=tuple(
            SourceFailure(**failure) for failure in outcomes["candidate"]["failures"]
        ),
    )
    report_path = output / "report" / "report.json"
    if not report_path.is_file():
        return code
    summary = breakdown(json.loads(report_path.read_text(encoding="utf-8")))
    summary["outcomes"] = {name: value["outcomes"] for name, value in outcomes.items()}
    (output / SUMMARY_JSON).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    markdown = render_summary(summary, outcomes)
    (output / SUMMARY_MD).write_text(markdown, encoding="utf-8", newline="\n")
    print(markdown)
    return code


def _run_import(args: argparse.Namespace) -> int:
    from charter_replay.importer import run_import

    return run_import(args)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("replay", "validate"):
        return kernel.main(argv)
    args = _parser().parse_args(argv)
    try:
        if args.command == "record":
            return _run_record(args)
        if args.command == "hooks":
            return _run_hooks(args)
        return _run_import(args)
    except (HookSpecError, kernel.ReplayInputError, ValueError) as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return kernel.EXIT_INPUT_INVALID
    except OSError as exc:
        print(f"{PROG}: output failed ({exc.__class__.__name__})", file=sys.stderr)
        return kernel.EXIT_SOURCE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
