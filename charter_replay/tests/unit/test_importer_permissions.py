"""Private creation modes and permission failures, using temporary corpora only."""

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from charter_replay.importer import write_corpus
from charter_replay.publication import PublicationError


def _with_mode(metadata, mode):
    fields = list(metadata)
    fields[stat.ST_MODE] = stat.S_IFMT(metadata.st_mode) | mode
    return os.stat_result(fields)


class ImportPermissionsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "new-parent" / "nested" / "corpus"

    def test_private_creation_modes_are_requested_on_every_platform(self):
        with (
            mock.patch("os.mkdir", wraps=os.mkdir) as mkdir,
            mock.patch("os.open", wraps=os.open) as opened,
        ):
            write_corpus(self.output, [], [])
        self.assertTrue(mkdir.call_args_list)
        for call in mkdir.call_args_list:
            self.assertEqual(call.args[1], 0o700)
        creations = [
            call for call in opened.call_args_list if call.args[1] & os.O_CREAT
        ]
        self.assertEqual(len(creations), 3)
        for call in creations:
            self.assertEqual(call.args[2], 0o600)
            self.assertTrue(call.args[1] & os.O_EXCL)
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {"events.jsonl", "cases.jsonl", "corpus-manifest.json"},
        )

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits and umask required")
    def test_umask_022_still_creates_private_directories_and_files(self):
        previous = os.umask(0o022)
        try:
            write_corpus(self.output, [], [])
        finally:
            os.umask(previous)
        for directory in (self.output, self.output.parent, self.output.parent.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_insecure_modes_refuse_before_publication_and_preserve_existing_bytes(self):
        sentinel = self.root / "keep.txt"
        sentinel.write_bytes(b"keep existing bytes")
        original_stat = Path.stat

        for failure in ("staging", "file", "destination"):

            def metadata(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path.name.startswith(".charter-publish-"):
                    return _with_mode(result, 0o755 if failure == "staging" else 0o700)
                if path == self.output:
                    return _with_mode(
                        result, 0o755 if failure == "destination" else 0o700
                    )
                return result

            with (
                self.subTest(failure=failure),
                mock.patch("charter_replay.publication.os", wraps=os) as system,
                mock.patch.object(Path, "stat", autospec=True, side_effect=metadata),
            ):
                # Exercise POSIX refusal even on Windows; native mode proof is above.
                system.name = "posix"
                system.O_WRONLY = os.O_WRONLY
                system.O_CREAT = os.O_CREAT
                system.O_EXCL = os.O_EXCL
                system.O_BINARY = getattr(os, "O_BINARY", 0)
                system.fstat.side_effect = lambda fd: _with_mode(
                    os.fstat(fd), 0o644 if failure == "file" else 0o600
                )
                with self.assertRaises(PublicationError):
                    write_corpus(self.output, [], [])
                system.link.assert_not_called()
            self.assertFalse(self.output.exists())
            self.assertEqual(list(self.output.parent.glob(".charter-publish-*")), [])
            self.assertEqual(sentinel.read_bytes(), b"keep existing bytes")


if __name__ == "__main__":
    unittest.main()
