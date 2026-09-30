"""The wheel smoke check must not silently import a source checkout."""

import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


class InstalledReviewCheckTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("examples.check_installed_review"),
            "isolated installed-review check is missing",
        )
        return importlib.import_module("examples.check_installed_review")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "environment"
        self.repository = self.root / "repository"
        self.package = self.prefix / "lib" / "site-packages" / "charter_replay"
        self.corpus = self.package / "corpora" / "charter"
        self.corpus.mkdir(parents=True)
        self.module_path = self.package / "__init__.py"
        self.module_path.write_text("", encoding="utf-8")
        self.repository.mkdir()

    def source(self, module_path=None, isolated=True):
        return self.module().installed_source(
            module_path or self.module_path,
            self.prefix,
            self.repository,
            isolated=isolated,
        )

    def test_installed_package_and_corpus_are_required_inside_environment(self):
        self.assertEqual(self.source(), self.corpus.resolve())

    def test_checkout_package_is_not_accepted_as_installed_evidence(self):
        shadow = self.repository / "charter_replay" / "__init__.py"
        shadow.parent.mkdir()
        shadow.write_text("", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.source(shadow)

    def test_an_external_package_does_not_count_as_this_environment(self):
        foreign = self.root / "outside" / "__init__.py"
        foreign.parent.mkdir()
        foreign.write_text("", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.source(foreign)

    def test_isolated_interpreter_mode_is_mandatory(self):
        with self.assertRaises(RuntimeError):
            self.source(isolated=False)

    def test_missing_packaged_corpus_is_a_failure(self):
        self.corpus.rmdir()
        with self.assertRaises(RuntimeError):
            self.source()

    def test_a_venv_nested_in_checkout_is_rejected_as_ambiguous(self):
        with self.assertRaises(RuntimeError):
            self.module().installed_source(
                self.module_path,
                self.prefix,
                self.root,
                isolated=True,
            )


if __name__ == "__main__":
    unittest.main()
