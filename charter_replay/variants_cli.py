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
    verify = commands.add_parser(
        "verify", help="regenerate and verify every bound output byte"
    )
    verify.add_argument("--source", required=True)
    verify.add_argument("--pack", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            lineage = generate_pack(
                args.source,
                args.output,
                domain=args.domain,
                max_derived=args.max_derived,
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
