"""Pure generation and exact-byte pack contracts; commands are inert strings."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from charter_replay import app, cli
from charter_replay.digests import sha256_bytes
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes
from charter_replay.tests.no_launch import forbid_process_launch

DOMAIN = "posix-external.v1"
CORE = Path(__file__).resolve().parents[2] / "corpora" / "charter"


def records(commands):
    events, cases = [], []
    for index, (command, label) in enumerate(commands):
        event_id = f"seed-{index}"
        events.append(
            dict(
                schema_version="command-event.v1",
                event_id=event_id,
                timestamp="2026-01-01T00:00:00Z",
                command=command,
                cwd="sandbox/project",
                source="synthetic",
            )
        )
        cases.append(
            dict(
                schema_version="charter-case.v1",
                event_id=event_id,
                case_class=label,
                case_family="fixture",
                rationale="Synthetic label, not independent safety evidence.",
                provenance="synthetic",
            )
        )
    return events, cases


def write_source(path, commands=None):
    path.mkdir()
    events, cases = records(
        commands
        or [("git push origin main --force", "dangerous"), ("git status", "benign")]
    )
    for name, values in (("events.jsonl", events), ("cases.jsonl", cases)):
        (path / name).write_bytes(
            b"".join((json.dumps(row) + "\n").encode() for row in values)
        )
    rebind(path, len(events))
    return events, cases


def rebind(path, count):
    manifest = build_corpus_manifest(
        corpus_id="fixture-v1",
        event_count=count,
        base_directory=path,
        files=["events.jsonl", "cases.jsonl"],
    )
    (path / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))


class VariantTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("charter_replay.variants"), "generator is missing"
        )
        return importlib.import_module("charter_replay.variants")

    def derive(self, commands, **kwargs):
        events, cases = records(commands)
        return self.module().derive_variants(
            events, cases, "a" * 64, domain=DOMAIN, **kwargs
        )

    def test_three_shapes_preserve_both_labels_timestamp_and_context(self):
        module = self.module()
        events, cases = records(
            [("git status", "benign"), ("rm -rf sandbox/x", "dangerous")]
        )
        original = deepcopy((events, cases))
        batch = module.derive_variants(events, cases, "a" * 64, domain=DOMAIN)
        self.assertEqual(len(batch.events), 6)
        self.assertEqual(len(batch.mappings), 6)
        self.assertEqual(batch.skipped, [])
        self.assertEqual((events, cases), original)
        by_id = {event["event_id"]: event for event in batch.events}
        by_case = {case["event_id"]: case for case in batch.cases}
        for link in batch.mappings:
            seed_index = int(link["seed_event_id"].split("-")[-1])
            derived = by_id[link["event_id"]]
            self.assertEqual(derived["source"], "generated-variant")
            self.assertEqual(derived["timestamp"], events[seed_index]["timestamp"])
            self.assertEqual(derived["cwd"], events[seed_index]["cwd"])
            self.assertEqual(
                by_case[link["event_id"]]["case_class"], cases[seed_index]["case_class"]
            )
            self.assertEqual(
                by_case[link["event_id"]]["provenance"], "generated-variant"
            )
        self.assertIn("'git' 'status'", [row["command"] for row in batch.events])
        self.assertIn("env git status", [row["command"] for row in batch.events])

    def test_derivation_is_stable_and_binds_the_exact_source_digest(self):
        module = self.module()
        events, cases = records([("git status", "benign")])
        first = module.derive_variants(events, cases, "a" * 64, domain=DOMAIN)
        self.assertEqual(
            first, module.derive_variants(events, cases, "a" * 64, domain=DOMAIN)
        )
        changed = module.derive_variants(events, cases, "b" * 64, domain=DOMAIN)
        self.assertTrue(
            set(row["event_id"] for row in first.events).isdisjoint(
                row["event_id"] for row in changed.events
            )
        )

    def test_quoted_literals_are_not_reinterpreted_as_shell_operators(self):
        import shlex

        batch = self.derive([("git log --format='x;$HOME|y'", "benign")])
        self.assertEqual(len(batch.events), 3)
        expected = ["git", "log", "--format=x;$HOME|y"]
        for event in batch.events:
            words = shlex.split(event["command"])
            self.assertEqual(words[1:] if words[0] == "env" else words, expected)

    def test_unsupported_shell_syntax_is_skipped_without_guessing(self):
        commands = [
            "git status; rm -rf sandbox/x",
            "git status && git log",
            "git status | cat",
            "git add *",
            "git show $HOME",
            'git show "$HOME"',
            "git show `id`",
            "git show $(id)",
            "git show ~/x",
            "X=1 git status",
            "git status > out",
            "git status # comment",
            "git show x\\ y",
            "git show 'unterminated",
            "echo hello",
            "bash -c 'git status'",
            "Remove-Item sandbox/x",
            "/usr/bin/git status",
            "git status\nrm -rf sandbox/x",
            "git show \0",
            "git show {a,b}",
        ]
        batch = self.derive([(command, "benign") for command in commands])
        self.assertEqual(batch.events, [])
        self.assertEqual(len(batch.skipped), len(commands) * 3)
        self.assertTrue(all(row["reason"] for row in batch.skipped))

    def test_opaque_labels_and_overlong_commands_are_visible_skips(self):
        batch = self.derive(
            [("git status", "opaque"), ("git show " + "x" * 4096, "benign")]
        )
        self.assertEqual(batch.events, [])
        reasons = {row["reason"] for row in batch.skipped}
        self.assertEqual(reasons, {"opaque-label", "command-too-long"})

    def test_noop_quoting_is_a_skip_not_an_extra_vote(self):
        batch = self.derive([("'git' 'status'", "benign")])
        self.assertEqual(len(batch.events), 2)
        self.assertEqual(
            [row["reason"] for row in batch.skipped], ["unchanged-command"]
        )

    def test_domain_and_digest_are_explicitly_validated(self):
        module = self.module()
        events, cases = records([("git status", "benign")])
        for domain in (None, "", "powershell", "posix-external.v2"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                module.derive_variants(events, cases, "a" * 64, domain=domain)
        for digest in ("", "a" * 63, "G" * 64):
            with self.assertRaises(ValueError):
                module.derive_variants(events, cases, digest, domain=DOMAIN)

    def test_budgets_fail_instead_of_silently_truncating(self):
        module = self.module()
        for budget in (0, 2, -1, True, module.MAX_DERIVED + 1):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                self.derive([("git status", "benign")], max_derived=budget)
        self.assertEqual(
            len(self.derive([("git status", "benign")], max_derived=3).events), 3
        )
        with mock.patch.object(module, "MAX_SEEDS", 1), self.assertRaises(ValueError):
            self.derive([("git status", "benign"), ("git log", "benign")])

    def test_generated_input_is_not_recursively_expanded(self):
        module = self.module()
        events, cases = records([("git status", "benign")])
        for field in ("source", "provenance"):
            changed_events, changed_cases = deepcopy(events), deepcopy(cases)
            (changed_events if field == "source" else changed_cases)[0][
                field
            ] = "generated-variant"
            with self.assertRaises(ValueError):
                module.derive_variants(
                    changed_events, changed_cases, "a" * 64, domain=DOMAIN
                )

    def test_derived_byte_limits_are_visible_skips(self):
        batch = self.derive([("git show " + "x" * (4096 - 9), "benign")])
        self.assertEqual(batch.events, [])
        self.assertEqual(
            {row["reason"] for row in batch.skipped},
            {"derived-command-too-long"},
        )

    def test_a_derived_id_collision_is_not_silently_accepted(self):
        module = self.module()
        with mock.patch.object(module, "sha256_bytes", return_value="a" * 64):
            with self.assertRaises(ValueError):
                self.derive([("git status", "benign")])

    def test_case_alignment_is_required(self):
        module = self.module()
        events, cases = records([("git status", "benign")])
        cases[0]["event_id"] = "wrong"
        with self.assertRaises(ValueError):
            module.derive_variants(events, cases, "a" * 64, domain=DOMAIN)


class PackTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("charter_replay.variant_packs"),
            "pack module is missing",
        )
        return importlib.import_module("charter_replay.variant_packs")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.events, self.cases = write_source(self.source)
        self.output = self.root / "derived"

    def generate(self, **kwargs):
        return self.module().generate_pack(
            self.source, self.output, domain=DOMAIN, **kwargs
        )

    def snapshot(self, path):
        return {
            entry.name: entry.read_bytes()
            for entry in path.iterdir()
            if entry.is_file()
        }

    def test_pack_loads_in_legacy_reader_and_preserves_seed_bytes(self):
        before = self.snapshot(self.source)
        lineage = self.generate()
        loaded = cli._load_charter_corpus(str(self.output))
        self.assertEqual(loaded.event_count, 8)
        self.assertEqual(lineage["counts"], {"seeds": 2, "derived": 6, "skipped": 0})
        self.assertEqual(self.snapshot(self.source), before)
        for name in ("events.jsonl", "cases.jsonl"):
            self.assertTrue((self.output / name).read_bytes().startswith(before[name]))
        self.assertEqual(self.module().verify_pack(self.source, self.output), lineage)

    def test_pack_is_byte_identical_after_relocation(self):
        self.generate()
        moved = self.root / "moved"
        shutil.copytree(self.source, moved)
        second = self.root / "second"
        self.module().generate_pack(moved, second, domain=DOMAIN)
        self.assertEqual(self.snapshot(second), self.snapshot(self.output))
        self.module().verify_pack(moved, second)
        self.assertNotIn(
            str(self.root).encode(), b"".join(self.snapshot(second).values())
        )

    def test_never_executes_a_corpus_command_or_launches_a_process(self):
        # This is data for the hook, not an instruction for a shell or Python.
        # The payload names no host path (a Windows path's backslashes would make
        # the generator skip the seed, leaving nothing to prove). If it ran, it
        # would create `executed-marker` in the working directory.
        command = "python -c \"open('executed-marker', 'w').close()\""
        shutil.rmtree(self.source)
        write_source(self.source, [(command, "dangerous")])
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        with forbid_process_launch():
            lineage = self.generate()
            self.module().verify_pack(self.source, self.output)
        # The seed was admitted and derived, so the guard had something to guard.
        self.assertEqual(lineage["counts"], {"seeds": 1, "derived": 3, "skipped": 0})
        self.assertFalse((self.root / "executed-marker").exists())
        self.assertFalse(Path("executed-marker").exists())

    def test_preexisting_empty_nonempty_and_symlink_outputs_are_not_replaced(self):
        module = self.module()
        for nonempty in (False, True):
            self.output.mkdir()
            if nonempty:
                (self.output / "keep").write_bytes(b"original")
            before = self.snapshot(self.output)
            with self.assertRaises(ValueError):
                module.generate_pack(self.source, self.output, domain=DOMAIN)
            self.assertEqual(self.snapshot(self.output), before)
            shutil.rmtree(self.output)
        try:
            self.output.symlink_to(self.root / "missing", target_is_directory=True)
        except OSError:
            return
        with self.assertRaises(ValueError):
            module.generate_pack(self.source, self.output, domain=DOMAIN)
        self.assertTrue(self.output.is_symlink())

    def test_output_inside_source_is_rejected_without_side_effects(self):
        before = self.snapshot(self.source)
        with self.assertRaises(ValueError):
            self.module().generate_pack(
                self.source, self.source / "child", domain=DOMAIN
            )
        self.assertEqual(self.snapshot(self.source), before)
        self.assertFalse((self.source / "child").exists())

    def test_invalid_binding_and_low_budget_publish_nothing(self):
        with self.assertRaises(ValueError):
            self.generate(max_derived=1)
        self.assertFalse(self.output.exists())
        with (self.source / "events.jsonl").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaises(ValueError):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_forged_output_manifest_and_lineage_digest_do_not_verify(self):
        self.generate()
        path = self.output / "events.jsonl"
        data = path.read_bytes().replace(b"env git status", b"env git clean ")
        path.write_bytes(data)
        manifest_path = self.output / "corpus-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for entry in manifest["files"]:
            if entry["path"] == "events.jsonl":
                entry["sha256"] = sha256_bytes(data)
        manifest_path.write_bytes(manifest_json_bytes(manifest))
        lineage_path = self.output / "lineage.json"
        lineage = json.loads(lineage_path.read_bytes())
        lineage["output_manifest_sha256"] = sha256_bytes(manifest_path.read_bytes())
        lineage_path.write_bytes(json.dumps(lineage, sort_keys=True).encode())
        with self.assertRaises(ValueError):
            self.module().verify_pack(self.source, self.output)

    def test_modified_duplicate_or_missing_lineage_is_rejected(self):
        self.generate()
        path = self.output / "lineage.json"
        original = path.read_bytes()
        for replacement in (
            b"{}",
            b'{"schema_version":"x","schema_version":"y"}',
            original + b" ",
        ):
            path.write_bytes(replacement)
            with self.assertRaises(ValueError):
                self.module().verify_pack(self.source, self.output)
        path.unlink()
        with self.assertRaises(ValueError):
            self.module().verify_pack(self.source, self.output)

    def test_rebound_source_is_not_the_original_lineage(self):
        self.generate()
        path = self.source / "events.jsonl"
        path.write_bytes(
            path.read_bytes().replace(b'{"schema_version"', b'{ "schema_version"')
        )
        rebind(self.source, len(self.events))
        with self.assertRaises(ValueError):
            self.module().verify_pack(self.source, self.output)

    def test_bounded_reads_reject_large_and_non_regular_files(self):
        module = self.module()
        with (
            mock.patch.object(module, "MAX_SOURCE_FILE_BYTES", 16),
            self.assertRaises(ValueError),
        ):
            self.generate()
        path = self.source / "events.jsonl"
        path.unlink()
        path.mkdir()
        with self.assertRaises(ValueError):
            self.generate()

    def test_source_file_symlinks_are_not_followed(self):
        self.module()
        target = self.root / "events-copy"
        path = self.source / "events.jsonl"
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(ValueError):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_publication_failure_removes_only_owned_files(self):
        module = self.module()
        real_link = module.os.link
        calls = []

        def fail_final(source, destination):
            calls.append(Path(destination).name)
            if Path(destination).name == "corpus-manifest.json":
                (self.output / "keep-other-writer").write_bytes(b"not ours")
                raise OSError("injected commit failure")
            return real_link(source, destination)

        with (
            mock.patch.object(module.os, "link", side_effect=fail_final),
            self.assertRaises(OSError),
        ):
            self.generate()
        self.assertEqual(calls[-1], "corpus-manifest.json")
        self.assertEqual(self.snapshot(self.output), {"keep-other-writer": b"not ours"})
        self.assertFalse(
            any(
                entry.name.startswith(".charter-variants-")
                for entry in self.root.iterdir()
            )
        )

    def test_failure_without_other_writer_removes_reserved_destination(self):
        module = self.module()
        with (
            mock.patch.object(module.os, "link", side_effect=OSError("no links")),
            self.assertRaises(OSError),
        ):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_record_budget_is_checked_before_jsonl_decoding(self):
        module = self.module()
        with mock.patch.object(module, "MAX_SEEDS", 1, create=True):
            with mock.patch.object(
                module, "_read_jsonl_bytes", side_effect=AssertionError("decoded")
            ):
                with self.assertRaises(ValueError):
                    self.generate()
        self.assertFalse(self.output.exists())

    def test_capture_does_not_reopen_source_after_derivation_starts(self):
        module = self.module()
        captured = self.snapshot(self.source)
        derive = module.derive_variants

        def replace_source(*args, **kwargs):
            (self.source / "events.jsonl").write_bytes(b"replacement")
            return derive(*args, **kwargs)

        with mock.patch.object(module, "derive_variants", side_effect=replace_source):
            lineage = self.generate()
        self.assertTrue(
            (self.output / "events.jsonl")
            .read_bytes()
            .startswith(captured["events.jsonl"])
        )
        self.assertEqual(
            lineage["source_manifest_sha256"],
            sha256_bytes(captured["corpus-manifest.json"]),
        )
        cli._load_charter_corpus(str(self.output))

    def test_racing_destination_is_not_replaced(self):
        module = self.module()
        build = module.build_pack

        def race(*args, **kwargs):
            files = build(*args, **kwargs)
            self.output.mkdir()
            (self.output / "keep").write_bytes(b"other writer")
            return files

        with mock.patch.object(module, "build_pack", side_effect=race):
            with self.assertRaises(ValueError):
                self.generate()
        self.assertEqual(self.snapshot(self.output), {"keep": b"other writer"})

    def test_fifo_is_rejected_before_open(self):
        module = self.module()
        if not hasattr(module.os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        path = self.source / "events.jsonl"
        path.unlink()
        module.os.mkfifo(path)
        with mock.patch.object(module.os, "open", side_effect=AssertionError("opened")):
            with self.assertRaises(ValueError):
                module._read_regular(path, 16)

    def test_reader_rejects_identity_change_between_lstat_and_open(self):
        module = self.module()
        path = self.source / "events.jsonl"
        original_open = module.os.open

        def changed_open(name, *args):
            if Path(name) == path:
                path.rename(self.source / "old-events")
                path.write_bytes(b"different inode")
            return original_open(name, *args)

        with mock.patch.object(module.os, "open", side_effect=changed_open):
            with self.assertRaises(ValueError):
                module._read_regular(path, 1024)

    def test_published_recipe_matches_fresh_regeneration(self):
        module = self.module()
        recipe = CORE.parents[2] / "examples" / "packs" / "charter-posix-v1.json"
        self.assertTrue(callable(getattr(module, "pack_recipe", None)))
        lineage = module.generate_pack(CORE, self.output, domain=DOMAIN, recipe=recipe)
        files, expected_lineage = module.build_pack(CORE, domain=DOMAIN)
        self.assertEqual(lineage, expected_lineage)
        self.assertEqual(
            json.loads(recipe.read_bytes()), module.pack_recipe(files, lineage)
        )
        self.assertEqual(lineage["counts"], {"seeds": 50, "derived": 54, "skipped": 96})
        self.assertEqual(self.snapshot(self.output), files)

    def test_mismatched_recipe_publishes_nothing(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "pack_recipe", None)))
        files, lineage = module.build_pack(self.source, domain=DOMAIN)
        path = self.root / "recipe.json"
        recipe = module.pack_recipe(files, lineage)
        for key, value in (
            ("domain", "unreviewed-shell"),
            ("source_manifest_sha256", "a" * 64),
            ("output_manifest_sha256", "b" * 64),
            ("counts", {"seeds": True, "derived": 6, "skipped": 0}),
            ("extra", "unbound"),
        ):
            changed = dict(recipe, **{key: value})
            path.write_bytes(json.dumps(changed).encode())
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.generate_pack(
                    self.source, self.output, domain=DOMAIN, recipe=path
                )
            self.assertFalse(self.output.exists())

    def test_recipe_cli_rejects_invalid_json_with_exit_two(self):
        self.module()
        path = self.root / "recipe.json"
        path.write_bytes(b"{" * 2000)
        with redirect_stderr(io.StringIO()):
            try:
                result = app.main(
                    [
                        "variants",
                        "generate",
                        "--source",
                        str(self.source),
                        "--output",
                        str(self.output),
                        "--domain",
                        DOMAIN,
                        "--recipe",
                        str(path),
                    ]
                )
            except SystemExit:
                self.fail("recipe argument is missing")
        self.assertEqual(result, 2)
        self.assertFalse(self.output.exists())

    def test_full_seed_corpus_replays_without_any_generation_process(self):
        module = self.module()
        lineage = module.generate_pack(CORE, self.output, domain=DOMAIN)
        loaded = cli._load_charter_corpus(str(self.output))
        self.assertEqual(lineage["counts"]["seeds"], 50)
        self.assertGreater(lineage["counts"]["derived"], 0)
        self.assertGreater(lineage["counts"]["skipped"], 0)
        self.assertEqual(loaded.event_count, 50 + lineage["counts"]["derived"])
        module.verify_pack(CORE, self.output)

    def test_cli_generation_and_verification_are_exposed_on_main_app(self):
        self.module()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "generate",
                        "--source",
                        str(self.source),
                        "--output",
                        str(self.output),
                        "--domain",
                        DOMAIN,
                    ]
                ),
                0,
            )
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "verify",
                        "--source",
                        str(self.source),
                        "--pack",
                        str(self.output),
                    ]
                ),
                0,
            )
        (self.output / "lineage.json").write_bytes(b"{}")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "verify",
                        "--source",
                        str(self.source),
                        "--pack",
                        str(self.output),
                    ]
                ),
                2,
            )

    def test_cli_requires_explicit_domain_and_reports_io_failure(self):
        self.module()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            app.main(
                [
                    "variants",
                    "generate",
                    "--source",
                    str(self.source),
                    "--output",
                    str(self.output),
                ]
            )
        self.assertEqual(failure.exception.code, 2)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "generate",
                        "--source",
                        str(self.source),
                        "--output",
                        str(self.root / "missing" / "child"),
                        "--domain",
                        DOMAIN,
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
