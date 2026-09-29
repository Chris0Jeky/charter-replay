from __future__ import annotations

from contextlib import redirect_stderr
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import charter_replay.cli as cli

from charter_replay.digests import sha256_bytes
from charter_replay.manifests import (
    ManifestError,
    build_corpus_manifest,
    build_run_manifest,
    derive_run_id,
    load_corpus_manifest,
    manifest_json_bytes,
    validate_corpus_manifest,
    validate_run_manifest,
)

BASELINE = {
    "kind": "recorded",
    "id": "floor-v1-final",
    "sha256": "1" * 64,
}
CANDIDATE = {
    "kind": "process",
    "id": "candidate-policy",
    "sha256": "2" * 64,
}
CORPUS = {
    "id": "charter-v0.1",
    "manifest_sha256": "3" * 64,
    "event_count": 50,
}
FAIL_ON = ["newly-allowed", "newly-indeterminate"]


class CorpusManifestTests(unittest.TestCase):
    def test_corpus_event_count_must_be_positive(self) -> None:
        manifest = {
            "schema_version": "corpus-manifest.v1",
            "corpus_id": "empty-v0",
            "event_count": 0,
            "files": [{"path": "events.jsonl", "sha256": "a" * 64}],
        }
        with self.assertRaisesRegex(ManifestError, "expected a positive integer"):
            validate_corpus_manifest(manifest)

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "events.jsonl").write_bytes(b"")
            with self.assertRaisesRegex(ManifestError, "expected a positive integer"):
                build_corpus_manifest(
                    corpus_id="empty-v0",
                    event_count=0,
                    base_directory=directory,
                    files=["events.jsonl"],
                )

    def test_build_and_load_validate_every_exact_file_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "events.jsonl").write_bytes(b'{"event_id":"one"}\n')
            (directory / "cases.jsonl").write_bytes(b'{"event_id":"one"}\n')
            manifest = build_corpus_manifest(
                corpus_id="charter-v0.1",
                event_count=1,
                base_directory=directory,
                files=["events.jsonl", "cases.jsonl"],
            )
            manifest_bytes = manifest_json_bytes(manifest)
            manifest_path = directory / "corpus-manifest.json"
            manifest_path.write_bytes(manifest_bytes)

            loaded = load_corpus_manifest(manifest_path)
            self.assertEqual(manifest, loaded.value)
            self.assertEqual(sha256_bytes(manifest_bytes), loaded.manifest_sha256)
            self.assertEqual(
                {
                    "events.jsonl": b'{"event_id":"one"}\n',
                    "cases.jsonl": b'{"event_id":"one"}\n',
                },
                dict(loaded.file_bytes),
            )

            (directory / "events.jsonl").write_bytes(b'{"event_id":"changed"}\n')
            self.assertEqual(
                b'{"event_id":"one"}\n', dict(loaded.file_bytes)["events.jsonl"]
            )
            with self.assertRaisesRegex(ManifestError, "does not match"):
                load_corpus_manifest(manifest_path)

    def test_manifest_digest_covers_exact_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "events.jsonl").write_bytes(b"{}\n")
            manifest = build_corpus_manifest(
                corpus_id="tiny-v0",
                event_count=1,
                base_directory=directory,
                files=["events.jsonl"],
            )
            compact = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
            pretty = manifest_json_bytes(manifest)
            manifest_path = directory / "corpus-manifest.json"
            manifest_path.write_bytes(compact)
            compact_loaded = load_corpus_manifest(manifest_path)
            manifest_path.write_bytes(pretty)
            pretty_loaded = load_corpus_manifest(manifest_path)
        self.assertEqual(compact_loaded.value, pretty_loaded.value)
        self.assertNotEqual(
            compact_loaded.manifest_sha256, pretty_loaded.manifest_sha256
        )

    def test_absolute_parent_duplicate_and_windows_paths_are_rejected(self) -> None:
        base = {
            "schema_version": "corpus-manifest.v1",
            "corpus_id": "charter-v0.1",
            "event_count": 1,
            "files": [{"path": "events.jsonl", "sha256": "a" * 64}],
        }
        for invalid_path in (
            "/private/events.jsonl",
            "../events.jsonl",
            "events\0.jsonl",
            "C:\\events.jsonl",
            ".",
        ):
            value = copy.deepcopy(base)
            value["files"][0]["path"] = invalid_path
            with self.subTest(path=invalid_path):
                with self.assertRaises(ManifestError):
                    validate_corpus_manifest(value)

        duplicate = copy.deepcopy(base)
        duplicate["files"].append(dict(duplicate["files"][0]))
        with self.assertRaisesRegex(ManifestError, "duplicate path"):
            validate_corpus_manifest(duplicate)

    def make_link(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"host cannot create the required symlink: {exc}")

    def write_manifest(self, root: Path, relative: str, data: bytes) -> Path:
        manifest = {
            "schema_version": "corpus-manifest.v1",
            "corpus_id": "boundary-v0",
            "event_count": 1,
            "files": [{"path": relative, "sha256": sha256_bytes(data)}],
        }
        path = root / "corpus-manifest.json"
        path.write_bytes(json.dumps(manifest).encode("utf-8"))
        return path

    def test_external_file_and_directory_links_are_rejected_before_read(self) -> None:
        for directory_link in (False, True):
            with self.subTest(directory_link=directory_link):
                with tempfile.TemporaryDirectory() as raw_directory:
                    outer = Path(raw_directory)
                    root = outer / "corpus"
                    # A sibling prefix is not containment.
                    external = outer / "corpus-sibling"
                    root.mkdir()
                    external.mkdir()
                    data = b"external bytes must not be read\n"
                    target = external / "events.jsonl"
                    target.write_bytes(data)
                    relative = (
                        "alias/events.jsonl" if directory_link else "events.jsonl"
                    )
                    self.make_link(
                        root / ("alias" if directory_link else "events.jsonl"),
                        external if directory_link else target,
                    )
                    manifest = self.write_manifest(root, relative, data)
                    with mock.patch(
                        "charter_replay.manifests.sha256_file", return_value="a" * 64
                    ) as digest:
                        with self.assertRaisesRegex(ManifestError, "outside corpus"):
                            build_corpus_manifest(
                                corpus_id="boundary-v0",
                                event_count=1,
                                base_directory=root,
                                files=[relative],
                            )
                        digest.assert_not_called()
                    read_bytes = Path.read_bytes
                    with mock.patch.object(
                        Path, "read_bytes", autospec=True, side_effect=read_bytes
                    ) as read:
                        with self.assertRaisesRegex(ManifestError, "outside corpus"):
                            load_corpus_manifest(manifest)
                        self.assertEqual([mock.call(manifest)], read.call_args_list)

    def test_resolved_escape_is_rejected_without_host_symlink_support(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            outer = Path(raw_directory)
            root, outside = outer / "corpus", outer / "corpus-sibling/events.jsonl"
            with (
                mock.patch.object(Path, "resolve", side_effect=[root, outside]),
                mock.patch(
                    "charter_replay.manifests.sha256_file", return_value="a" * 64
                ) as digest,
            ):
                with self.assertRaisesRegex(ManifestError, "outside corpus"):
                    build_corpus_manifest(
                        corpus_id="boundary-v0",
                        event_count=1,
                        base_directory=root,
                        files=["events.jsonl"],
                    )
                digest.assert_not_called()

    def test_in_tree_aliases_and_aliased_base_keep_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            outer = Path(raw_directory)
            root = outer / "corpus"
            nested = root / "data"
            nested.mkdir(parents=True)
            data = b'{"event_id":"one"}\n'
            target = nested / "events.jsonl"
            target.write_bytes(data)
            self.make_link(root / "events.jsonl", target)
            self.make_link(root / "alias", nested)
            alias_base = outer / "base-alias"
            self.make_link(alias_base, root)
            paths = ["events.jsonl", "alias/events.jsonl", "data/events.jsonl"]
            manifest = build_corpus_manifest(
                corpus_id="boundary-v0",
                event_count=1,
                base_directory=alias_base,
                files=paths,
            )
            manifest_path = alias_base / "corpus-manifest.json"
            manifest_path.write_bytes(manifest_json_bytes(manifest))
            loaded = load_corpus_manifest(manifest_path)
            self.assertEqual({name: data for name in paths}, dict(loaded.file_bytes))

    def test_non_file_corpus_entry_fails_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            (root / "directory").mkdir()
            manifest = self.write_manifest(root, "directory", b"")
            with self.assertRaisesRegex(ManifestError, "regular file"):
                load_corpus_manifest(manifest)
            with mock.patch(
                "charter_replay.manifests.sha256_file", return_value="a" * 64
            ) as digest:
                with self.assertRaisesRegex(ManifestError, "regular file"):
                    build_corpus_manifest(
                        corpus_id="boundary-v0",
                        event_count=1,
                        base_directory=root,
                        files=["directory"],
                    )
                digest.assert_not_called()

    def assert_cli_rejects_path(self, nul_path: bool) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            outer = Path(raw_directory)
            root = outer / "corpus"
            root.mkdir()
            target = outer / "outside.jsonl"
            target.write_bytes(b"{}\n")
            relative = "events\0.jsonl" if nul_path else "events.jsonl"
            if not nul_path:
                self.make_link(root / relative, target)
            self.write_manifest(root, relative, b"{}\n")
            output = outer / "output"
            stderr = io.StringIO()
            with (
                mock.patch.object(cli, "_load_policy_source") as load_policy,
                redirect_stderr(stderr),
            ):
                code = cli.main(
                    [
                        "replay",
                        "--corpus",
                        str(root),
                        "--baseline",
                        "process:unused-baseline",
                        "--candidate",
                        "process:unused-candidate",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(2, code)
            self.assertTrue(stderr.getvalue().startswith("replay input invalid:"))
            expected = "relative POSIX path" if nul_path else "outside corpus"
            self.assertIn(expected, stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertNotIn(str(target), stderr.getvalue())
            load_policy.assert_not_called()
            self.assertFalse(output.exists())

    def test_nul_path_exits_two_without_policy_or_reports(self) -> None:
        self.assert_cli_rejects_path(True)

    def test_external_path_exits_two_without_policy_or_reports(self) -> None:
        self.assert_cli_rejects_path(False)


class RunManifestTests(unittest.TestCase):
    def build(self, generated_at: str = "2026-07-30T12:00:00Z"):
        return build_run_manifest(
            generated_at=generated_at,
            baseline=BASELINE,
            candidate=CANDIDATE,
            corpus=CORPUS,
            fail_on=FAIL_ON,
        )

    def test_run_id_is_stable_and_excludes_generated_at(self) -> None:
        first = self.build("2026-07-30T12:00:00Z")
        second = self.build("2030-01-01T00:00:00Z")
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(first["generated_at"], second["generated_at"])

    def test_run_manifest_corpus_event_count_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ManifestError, "expected a positive integer"):
            build_run_manifest(
                generated_at="2026-07-30T12:00:00Z",
                baseline=BASELINE,
                candidate=CANDIDATE,
                corpus={**CORPUS, "event_count": 0},
                fail_on=FAIL_ON,
            )

    def test_all_gate_classes_are_accepted_by_build_derive_and_validation(self) -> None:
        for gate_class in (
            "newly-allowed",
            "newly-denied",
            "newly-indeterminate",
        ):
            with self.subTest(gate_class=gate_class):
                derived_run_id = derive_run_id(
                    runner_version="0.1.0",
                    baseline_sha256=BASELINE["sha256"],
                    candidate_sha256=CANDIDATE["sha256"],
                    corpus_manifest_sha256=CORPUS["manifest_sha256"],
                    fail_on=[gate_class],
                )
                manifest = build_run_manifest(
                    generated_at="2026-07-30T12:00:00Z",
                    baseline=BASELINE,
                    candidate=CANDIDATE,
                    corpus=CORPUS,
                    fail_on=[gate_class],
                    runner_version="0.1.0",
                )
                self.assertEqual(derived_run_id, manifest["run_id"])
                self.assertEqual(manifest, validate_run_manifest(manifest))

    def test_report_only_classes_are_rejected_by_build_derive_and_validation(
        self,
    ) -> None:
        for report_only_class in ("unchanged", "resolved-indeterminate"):
            with self.subTest(operation="derive", gate_class=report_only_class):
                with self.assertRaisesRegex(ManifestError, "replay gate class"):
                    derive_run_id(
                        runner_version="0.1.0",
                        baseline_sha256=BASELINE["sha256"],
                        candidate_sha256=CANDIDATE["sha256"],
                        corpus_manifest_sha256=CORPUS["manifest_sha256"],
                        fail_on=[report_only_class],
                    )

            with self.subTest(operation="build", gate_class=report_only_class):
                with self.assertRaisesRegex(ManifestError, "replay gate class"):
                    build_run_manifest(
                        generated_at="2026-07-30T12:00:00Z",
                        baseline=BASELINE,
                        candidate=CANDIDATE,
                        corpus=CORPUS,
                        fail_on=[report_only_class],
                    )

            invalid_manifest = self.build()
            invalid_manifest["fail_on"] = [report_only_class]
            with self.subTest(operation="validate", gate_class=report_only_class):
                with self.assertRaisesRegex(ManifestError, "replay gate class"):
                    validate_run_manifest(invalid_manifest)

    def test_run_id_changes_with_each_semantic_input_class(self) -> None:
        original = self.build()
        changes = [
            {"baseline": {**BASELINE, "sha256": "4" * 64}},
            {"candidate": {**CANDIDATE, "sha256": "4" * 64}},
            {
                "corpus": {
                    **CORPUS,
                    "manifest_sha256": "4" * 64,
                }
            },
            {"fail_on": ["newly-allowed"]},
            {"runner_version": "0.1.1"},
        ]
        for change in changes:
            arguments = {
                "generated_at": "2026-07-30T12:00:00Z",
                "baseline": BASELINE,
                "candidate": CANDIDATE,
                "corpus": CORPUS,
                "fail_on": FAIL_ON,
                **change,
            }
            with self.subTest(change=next(iter(change))):
                changed = build_run_manifest(**arguments)
                self.assertNotEqual(original["run_id"], changed["run_id"])

    def test_output_has_only_portable_declared_fields(self) -> None:
        manifest = self.build()
        self.assertEqual(
            {
                "schema_version",
                "run_id",
                "generated_at",
                "runner_version",
                "baseline",
                "candidate",
                "corpus",
                "fail_on",
            },
            set(manifest),
        )
        serialized = manifest_json_bytes(manifest).decode("utf-8")
        self.assertNotIn("absolute_path", serialized)
        self.assertNotIn("hostname", serialized)
        self.assertNotIn("username", serialized)
        self.assertNotIn("environment", serialized)

        invalid = {**BASELINE, "id": "C:\\private\\policy.py"}
        with self.assertRaises(ManifestError):
            build_run_manifest(
                generated_at="2026-07-30T12:00:00Z",
                baseline=invalid,
                candidate=CANDIDATE,
                corpus=CORPUS,
                fail_on=FAIL_ON,
            )

    def test_validation_rejects_a_run_id_not_bound_to_inputs(self) -> None:
        manifest = self.build()
        manifest["candidate"]["sha256"] = "9" * 64
        with self.assertRaisesRegex(ManifestError, "run_id"):
            validate_run_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
