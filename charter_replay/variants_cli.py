"""Generate or independently regenerate bounded variant corpus files."""

from __future__ import annotations

import argparse
import json
import sys

from charter_replay.variant_packs import generate_pack, verify_pack
from charter_replay.variants import DOMAIN, MAX_DERIVED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="charter-replay variants")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser(
        "generate", help="derive a new corpus without executing commands"
    )
    generate.add_argument("--source", required=True, help="exact seed corpus directory")
    generate.add_argument(
        "--output", required=True, help="new directory under an existing parent"
    )
    generate.add_argument("--domain", required=True, choices=[DOMAIN])
    generate.add_argument("--max-derived", type=int, default=MAX_DERIVED)
    generate.add_argument(
        "--recipe", help="require exact pack recipe before publication"
    )
    verify = commands.add_parser(
        "verify", help="regenerate and verify every bound output byte"
    )
    verify.add_argument("--source", required=True)
    verify.add_argument("--pack", required=True)
    coverage = commands.add_parser(
        "coverage", help="summarize verified seed and variant replay behavior"
    )
    coverage.add_argument("--source", required=True)
    coverage.add_argument("--pack", required=True)
    coverage.add_argument("--report", required=True)
    for name in ("review", "verify-review"):
        review = commands.add_parser(name, help="build or verify capture-bound review")
        review.add_argument("--source", required=True)
        review.add_argument("--pack", required=True)
        review.add_argument("--report", required=True)
        review.add_argument("--run-manifest", required=True)
        review.add_argument(
            "--output" if name == "review" else "--review", required=True
        )
    args = parser.parse_args(argv)
    if args.command in ("review", "verify-review"):
        from charter_replay.variant_review import publish_review, verify_review

        publishing = args.command == "review"
        operation = publish_review if publishing else verify_review
        target = args.output if publishing else args.review
        try:
            code = operation(
                args.source, args.pack, args.report, args.run_manifest, target
            )
        except (ValueError, RuntimeError):
            print(
                "charter-replay variants: invalid review inputs or destination",
                file=sys.stderr,
            )
            return 2
        except OSError:
            print("charter-replay variants: review publication failed", file=sys.stderr)
            return 3
        print(
            json.dumps(
                {
                    "gate": {0: "pass", 1: "fail", 3: "error"}[code],
                    "status": "review-published" if publishing else "review-verified",
                },
                sort_keys=True,
            )
        )
        return code
    try:
        if args.command == "coverage":
            from charter_replay.variant_coverage import build_coverage

            result = build_coverage(args.source, args.pack, args.report)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "generate":
            lineage = generate_pack(
                args.source,
                args.output,
                domain=args.domain,
                max_derived=args.max_derived,
                recipe=args.recipe,
            )
        else:
            lineage = verify_pack(args.source, args.pack)
    except (OSError, ValueError) as exc:
        print(f"charter-replay variants: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "generated" if args.command == "generate" else "verified",
                "counts": lineage["counts"],
                "source_manifest_sha256": lineage["source_manifest_sha256"],
                "output_manifest_sha256": lineage["output_manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
