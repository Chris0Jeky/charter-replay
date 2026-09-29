"""Publication is exclusive, bounded and portable, including failure cleanup."""

import importlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module("charter_replay.publication")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "new"
        self.files = {"data.json": b"data", "commit.json": b"manifest"}

    def publish(self):
        self.module.publish_new_directory(self.output, self.files, marker="commit.json")

    def test_windows_reserved_and_aliasing_names_are_rejected_on_every_platform(self):
        for name in (
            "con",
            "con.json",
            "nul.txt",
            "aux",
            "com1.json",
            "lpt9.txt",
            "data.",
        ):
            self.files = {name: b"payload", "commit.json": b"manifest"}
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.publish()
            if self.output.exists():
                import shutil

                shutil.rmtree(self.output)

    def test_bad_paths_types_missing_marker_and_budget_fail_before_output(self):
        for name in ("../outside", "/absolute", "sub/child", "sub\\child", "", "CAPS"):
            self.files = {name: b"payload", "commit.json": b"manifest"}
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.publish()
            self.assertFalse(self.output.exists())
        self.files = {"data.json": b"payload"}
        with self.assertRaises(ValueError):
            self.publish()
        self.files = {"data.json": "not bytes", "commit.json": b"manifest"}
        with self.assertRaises(ValueError):
            self.publish()
        self.files = {"data.json": b"data", "commit.json": b"manifest"}
        with mock.patch.object(self.module, "MAX_PUBLICATION_BYTES", 1):
            with self.assertRaises(ValueError):
                self.publish()
        self.assertFalse(self.output.exists())

    def test_destination_racing_with_staging_is_preserved(self):
        original = self.module.os.open

        def reserve(*args, **kwargs):
            if not self.output.exists():
                self.output.mkdir()
                (self.output / "other").write_bytes(b"keep")
            return original(*args, **kwargs)

        with mock.patch.object(self.module.os, "open", side_effect=reserve):
            with self.assertRaises(ValueError):
                self.publish()
        self.assertEqual((self.output / "other").read_bytes(), b"keep")
        self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_empty_existing_directory_and_dangling_link_are_not_replaced(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):
            self.publish()
        self.output.rmdir()
        try:
            self.output.symlink_to(self.root / "missing", target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertTrue(self.output.is_symlink())

    def test_first_link_failure_removes_only_our_empty_reservation(self):
        with mock.patch.object(
            self.module.os, "link", side_effect=OSError("no hard links")
        ):
            with self.assertRaises(OSError):
                self.publish()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_changed_owned_inode_is_preserved_instead_of_deleted(self):
        original = self.module.os.link

        def modify_then_fail(source, target):
            if Path(target).name == "commit.json":
                (self.output / "data.json").write_bytes(b"other writer's changes")
                raise OSError("injected failure")
            return original(source, target)

        with mock.patch.object(self.module.os, "link", side_effect=modify_then_fail):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(
            (self.output / "data.json").read_bytes(), b"other writer's changes"
        )
        self.assertFalse((self.output / "commit.json").exists())

    def test_rollback_bounds_reads_even_after_an_owned_file_is_enlarged(self):
        original = self.module.os.link

        def modify_then_fail(source, target):
            if Path(target).name == "commit.json":
                (self.output / "data.json").write_bytes(b"x" * 10000)
                raise OSError("injected failure")
            return original(source, target)

        with (
            mock.patch.object(self.module.os, "link", side_effect=modify_then_fail),
            mock.patch.object(
                Path, "read_bytes", side_effect=AssertionError("unbounded read")
            ),
        ):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual((self.output / "data.json").stat().st_size, 10000)

    def test_completion_marker_is_last_and_bytes_are_unchanged(self):
        original = self.module.os.link
        order = []

        def observe(source, target):
            order.append(Path(target).name)
            return original(source, target)

        with mock.patch.object(self.module.os, "link", side_effect=observe):
            self.publish()
        self.assertEqual(order[-1], "commit.json")
        self.assertEqual(
            {p.name: p.read_bytes() for p in self.output.iterdir()}, self.files
        )


if __name__ == "__main__":
    unittest.main()
