"""Private imports never replace an existing destination or follow its links."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
import unittest
from unittest import mock

from charter_replay.app import main
from charter_replay.importer import output_is_private, write_corpus


class ImportPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        source = self.root / "transcripts"
        source.mkdir()
        (source / "session.jsonl").write_text(
            json.dumps(
                {
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "name": "Bash",
                                "input": {"command": "git status"},
                            }
                        ]
                    }
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.arguments = [
            "import",
            "--claude-root",
            str(source),
            "--codex-root",
            "none",
            "--output",
        ]
        self.output = self.root / ".local" / "private-corpus"

    def run_import(self):
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return main([*self.arguments, str(self.output)])

    def test_existing_corpus_is_refused_without_changing_any_artifact(self):
        self.output.mkdir(parents=True, mode=0o700)
        names = ("events.jsonl", "cases.jsonl", "corpus-manifest.json")
        for name in names:
            (self.output / name).write_bytes(b"keep existing bytes")
        self.assertNotEqual(self.run_import(), 0)
        for name in names:
            self.assertEqual((self.output / name).read_bytes(), b"keep existing bytes")

    def test_ignored_output_links_cannot_overwrite_repo_or_external_files(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".gitignore").write_text("/.local/\n", encoding="utf-8")
        self.output = repo / ".local" / "private-corpus"
        self.output.mkdir(parents=True, mode=0o700)
        for target in (repo / "README.md", self.root / "outside.txt"):
            target.write_bytes(b"protected target")
            for name in ("events.jsonl", "cases.jsonl", "corpus-manifest.json"):
                link = self.output / name
                try:
                    link.symlink_to(target)
                except OSError as exc:
                    self.skipTest(f"symlinks unavailable: {exc}")
                with (
                    self.subTest(target=target.name, artifact=name),
                    mock.patch(
                        "charter_replay.importer.subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, stdout=""),
                    ),
                ):
                    # Model Git ignoring every lexical output name, without Git writes.
                    self.assertTrue(output_is_private(self.output))
                    self.assertNotEqual(self.run_import(), 0)
                    self.assertEqual(target.read_bytes(), b"protected target")
                    self.assertTrue(link.is_symlink())
                link.unlink()

    def test_output_directory_symlinks_are_refused(self):
        for existing in (True, False):
            target = self.root / ("existing" if existing else "missing")
            if existing:
                target.mkdir()
                (target / "keep").write_bytes(b"protected target")
            link = self.root / "linked-corpus"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with (
                self.subTest(existing=existing),
                self.assertRaises((ValueError, OSError)),
            ):
                write_corpus(link, [], [])
            self.assertTrue(link.is_symlink())
            if existing:
                self.assertEqual(list(target.iterdir()), [target / "keep"])
                self.assertEqual((target / "keep").read_bytes(), b"protected target")
            else:
                self.assertFalse(target.exists())
            link.unlink()

    @unittest.skipUnless(os.name == "nt", "Windows directory junction required")
    def test_output_directory_junction_is_refused_without_changing_target(self):
        import _winapi

        target = self.root / "junction-target"
        target.mkdir()
        (target / "keep.txt").write_bytes(b"protected target")
        self.output.parent.mkdir()
        _winapi.CreateJunction(str(target), str(self.output))
        self.assertTrue(
            self.output.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        self.assertNotEqual(self.run_import(), 0)
        self.assertTrue(
            self.output.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        self.assertEqual(list(target.iterdir()), [target / "keep.txt"])
        self.assertEqual((target / "keep.txt").read_bytes(), b"protected target")


if __name__ == "__main__":
    unittest.main()
