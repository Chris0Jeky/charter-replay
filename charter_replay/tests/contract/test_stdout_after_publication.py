"""Printing the Markdown summary happens after publication and never decides the exit code."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import app

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "charter_replay" / "corpora" / "charter"
GUARDS = REPO / "examples" / "toy-guard"
NON_ASCII = "événement 日本"


class LegacyStream(io.StringIO):
    """A text stream with no binary layer that only accepts cp1252."""

    encoding = "cp1252"

    def write(self, text):
        text.encode(self.encoding)  # UnicodeEncodeError, as a real pipe raises
        return super().write(text)


class EmitTests(unittest.TestCase):
    def test_binary_layer_gets_utf8_whatever_the_text_encoding(self):
        raw = io.BytesIO()
        legacy = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        with mock.patch.object(sys, "stdout", legacy):
            app._emit(NON_ASCII)
        self.assertEqual(raw.getvalue(), (NON_ASCII + "\n").encode("utf-8"))

    def test_text_only_stream_gets_replacements_not_an_exception(self):
        stream = LegacyStream()
        with mock.patch.object(sys, "stdout", stream):
            app._emit(NON_ASCII)
        # cp1252 keeps the accented letters and replaces the two it cannot hold.
        self.assertEqual(stream.getvalue(), "événement ??\n")

    def test_a_failing_stream_is_not_fatal(self):
        class Broken:
            def write(self, _text):
                raise BrokenPipeError

            def flush(self):
                raise BrokenPipeError

        for stream in (Broken(), None):
            with self.subTest(stream=stream), mock.patch.object(sys, "stdout", stream):
                app._emit(NON_ASCII)


class HooksExitCodeTests(unittest.TestCase):
    def test_hooks_exit_code_survives_a_legacy_code_page_stdout(self):
        def hook(name):
            return json.dumps([sys.executable, str(GUARDS / name)])

        raw = io.BytesIO()
        legacy = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            argv = ["hooks", "--baseline", hook("guard_v1.py")]
            argv += ["--candidate", hook("guard_v2.py"), "--corpus", str(CORPUS)]
            argv += ["--output", str(output), "--jobs", "4"]
            with (
                mock.patch.object(sys, "stdout", legacy),
                mock.patch.object(app, "render_summary", return_value=NON_ASCII),
                redirect_stderr(io.StringIO()) as stderr,
            ):
                code = app.main(argv)
            self.assertEqual(code, 1, stderr.getvalue())
            self.assertEqual(stderr.getvalue(), "")
            self.assertTrue((output / "summary.md").is_file())
        self.assertIn(NON_ASCII.encode("utf-8"), raw.getvalue())


if __name__ == "__main__":
    unittest.main()
