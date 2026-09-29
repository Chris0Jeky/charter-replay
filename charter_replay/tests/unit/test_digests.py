from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from charter_replay.digests import (
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    sha256_tree,
)


class DigestTests(unittest.TestCase):
    def test_file_digest_covers_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "events.jsonl"
            path.write_bytes(b'{"event_id":"one"}\n')
            lf_digest = sha256_file(path)
            path.write_bytes(b'{"event_id":"one"}\r\n')
            crlf_digest = sha256_file(path)
        self.assertNotEqual(lf_digest, crlf_digest)
        self.assertEqual(hashlib.sha256(b'{"event_id":"one"}\n').hexdigest(), lf_digest)

    def test_canonical_json_digest_ignores_mapping_insertion_order(self) -> None:
        left = canonical_json_bytes({"b": 2, "a": [1, "two"]})
        right = canonical_json_bytes({"a": [1, "two"], "b": 2})
        self.assertEqual(left, right)
        self.assertEqual(sha256_bytes(left), sha256_bytes(right))

    def test_tree_digest_binds_relative_names_and_exact_file_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as first_raw_directory:
            with tempfile.TemporaryDirectory() as second_raw_directory:
                first = Path(first_raw_directory)
                second = Path(second_raw_directory)
                for root in (first, second):
                    (root / "empty").mkdir()
                    (root / "policy.py").write_bytes(b"import rules\n")
                    (root / "rules.py").write_bytes(b'EFFECT = "deny"\n')

                original = sha256_tree(first)
                self.assertEqual(original, sha256_tree(second))
                (first / "rules.py").write_bytes(b'EFFECT = "allow"\n')
                self.assertNotEqual(original, sha256_tree(first))

    def test_tree_digest_binds_file_permission_bits(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            helper = root / "helper"
            helper.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(helper, 0o666)
            original = sha256_tree(root)

            os.chmod(helper, 0o444)
            read_only_file = sha256_tree(root)

        self.assertNotEqual(original, read_only_file)

    @unittest.skipIf(os.name == "nt", "Windows has no portable directory modes")
    def test_tree_digest_binds_directory_permission_bits(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            os.chmod(root, 0o755)
            original = sha256_tree(root)
            try:
                os.chmod(root, 0o555)
                read_only = sha256_tree(root)
            finally:
                os.chmod(root, 0o755)

        self.assertNotEqual(original, read_only)

    @unittest.skipIf(os.name == "nt", "Windows symlinks require optional privilege")
    def test_tree_digest_binds_followed_file_symlink_target_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            root = directory / "tree"
            root.mkdir()
            target = directory / "target"
            target.write_bytes(b"same bytes\n")
            link = root / "linked-file"
            link.symlink_to(target)
            os.chmod(target, 0o666)
            writable = sha256_tree(root)

            os.chmod(target, 0o444)
            read_only = sha256_tree(root)

        self.assertNotEqual(writable, read_only)


if __name__ == "__main__":
    unittest.main()
