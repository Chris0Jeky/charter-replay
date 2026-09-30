"""The hook context descriptor is input-only, portable, private and bounded."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import hook_context as hc
from charter_replay.adapters import RUNTIMES, get_adapter
from charter_replay.hooks import HookSpec


class DescriptorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.script = self.write(self.root / "guard.py", b"import sys\n")
        self.helper = self.write(self.root / "rules.json", b'{"deny": []}\n')
        self.template = self.root / "template"
        self.write(self.template / "a.txt", b"a")
        self.write(self.template / "sub" / "b.txt", b"b")

    @staticmethod
    def write(path: Path, data: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def spec(self, *argv, **options) -> HookSpec:
        return HookSpec(argv or (sys.executable, str(self.script)), **options)

    def describe(self, spec=None, template=None, jobs=1, **kwargs):
        return hc.describe_hook_context(
            spec or self.spec(), workspace_template=template, jobs=jobs, **kwargs
        )

    def identity(self, *args, **kwargs) -> str:
        return hc.context_id(self.describe(*args, **kwargs))

    def test_descriptor_is_deterministic_and_input_only(self):
        first = self.describe(template=self.template)
        self.assertEqual(first, self.describe(template=self.template))
        self.assertEqual(first["schema_version"], hc.HOOK_CONTEXT_VERSION)
        self.assertEqual(first["adapter"]["contract_id"], "claude-pretooluse.v1")
        self.assertEqual(first["execution"], {"timeout_seconds": 10.0, "jobs": 1})
        self.assertEqual(first["workspace_template"]["entries"], 3)
        self.assertEqual(first["workspace_template"]["bytes"], 2)
        self.assertEqual(len(hc.context_id(first)), 64)
        self.assertEqual(first["environment"]["adapter_names"], ["CLAUDE_PROJECT_DIR"])

    def test_each_configuration_input_changes_the_identity(self):
        base = self.identity(template=self.template)
        variants = {
            "timeout": self.identity(self.spec(timeout=5), template=self.template),
            "ask": self.identity(self.spec(ask_effect="allow"), template=self.template),
            "runtime": self.identity(
                self.spec(runtime="codex"), template=self.template
            ),
            "jobs": self.identity(template=self.template, jobs=2),
            "no template": self.identity(),
        }
        for name, value in variants.items():
            with self.subTest(name):
                self.assertNotEqual(value, base)

    def test_argv_file_bytes_and_template_bytes_change_the_identity(self):
        spec = self.spec(sys.executable, str(self.script), str(self.helper))
        base = self.identity(spec, self.template)
        self.helper.write_bytes(b'{"deny": ["x"]}\n')
        self.assertNotEqual(self.identity(spec, self.template), base)
        self.helper.write_bytes(b'{"deny": []}\n')
        self.assertEqual(self.identity(spec, self.template), base)
        (self.template / "sub" / "b.txt").write_bytes(b"changed")
        self.assertNotEqual(self.identity(spec, self.template), base)

    def test_template_structure_is_framed_not_concatenated(self):
        base = self.describe(template=self.template)["workspace_template"]
        # Same bytes, different names and an added empty directory.
        (self.template / "sub" / "b.txt").rename(self.template / "sub" / "c.txt")
        renamed = self.describe(template=self.template)["workspace_template"]
        (self.template / "empty").mkdir()
        added = self.describe(template=self.template)["workspace_template"]
        self.assertEqual(len({base["tree_sha256"], renamed["tree_sha256"]}), 2)
        self.assertNotEqual(renamed["tree_sha256"], added["tree_sha256"])
        self.assertEqual(added["entries"], 4)

    def test_executable_bytes_and_invocation_name_change_the_identity(self):
        one = self.write(self.root / "tools" / "hook.exe", b"binary one")
        other = self.write(self.root / "other" / "hook.exe", b"binary two")
        alias = self.root / "tools" / "alias.exe"
        shutil.copyfile(one, alias)
        first = self.identity(self.spec(str(one)))
        self.assertNotEqual(first, self.identity(self.spec(str(other))))
        self.assertNotEqual(first, self.identity(self.spec(str(alias))))
        one.write_bytes(b"binary one, patched")
        self.assertNotEqual(first, self.identity(self.spec(str(one))))

    def test_relocated_identical_bytes_keep_the_identity(self):
        first = self.write(self.root / "one" / "guard.py", b"same bytes\n")
        second = self.write(self.root / "two" / "deeper" / "guard.py", b"same bytes\n")
        self.assertEqual(
            self.identity(self.spec(sys.executable, str(first))),
            self.identity(self.spec(sys.executable, str(second))),
        )
        copy_of = self.root / "moved-template"
        shutil.copytree(self.template, copy_of)
        self.assertEqual(
            self.identity(template=self.template), self.identity(template=copy_of)
        )

    def test_bare_executable_resolves_against_the_hook_path(self):
        bin_dir = self.root / "bin"
        name = "context-fixture-tool" + (".exe" if os.name == "nt" else "")
        self.write(bin_dir / name, b"tool").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(bin_dir)}):
            entry = self.describe(self.spec("context-fixture-tool"))["hook"]["argv"][0]
        self.assertEqual(entry["status"], "bound")
        self.assertEqual(entry["size"], 4)

    def test_missing_executable_is_unbound_without_raising(self):
        descriptor = self.describe(self.spec("no-such-context-fixture-binary"))
        entry = descriptor["hook"]["argv"][0]
        self.assertEqual(entry["status"], "unbound")
        self.assertEqual(entry["reason"], "unresolved")
        self.assertIn("executable", descriptor["unbound"])
        self.assertEqual(descriptor["unbound"], sorted(descriptor["unbound"]))
        for name in hc.STATIC_UNBOUND:
            self.assertIn(name, descriptor["unbound"])
        hc.validate_hook_context(hc.context_document(descriptor))

    def test_unreadable_argv_file_and_missing_template_are_unbound(self):
        spec = self.spec(sys.executable, str(self.helper))
        with mock.patch.object(hc, "_hash_file", side_effect=PermissionError):
            descriptor = self.describe(spec, self.root / "absent")
        self.assertEqual(descriptor["hook"]["argv"][0]["reason"], "unreadable")
        self.assertEqual(descriptor["hook"]["argv"][1]["reason"], "unreadable")
        self.assertEqual(descriptor["workspace_template"]["reason"], "unreadable")
        for name in ("executable", "argv-file:1", "workspace-template"):
            self.assertIn(name, descriptor["unbound"])

    def test_words_are_hashed_after_path_reduction_and_never_emitted(self):
        marker = "secret-token-marker"
        first = self.describe(
            self.spec(sys.executable, "--flag", marker, "/one/dir/tool.cfg")
        )
        second = self.describe(
            self.spec(sys.executable, "--flag", marker, "/two/else/tool.cfg")
        )
        self.assertEqual(hc.context_id(first), hc.context_id(second))
        self.assertNotIn(marker, json.dumps(first))
        self.assertNotIn("/one/dir", json.dumps(first))
        self.assertEqual({item["kind"] for item in first["hook"]["argv"][1:]}, {"word"})

    def test_pinned_kinds_keep_an_output_path_a_word(self):
        output = self.root / "out.json"
        spec = self.spec(sys.executable, str(self.script), str(output))
        initial = self.describe(spec)
        self.assertEqual(hc.argv_kinds(initial), ["executable", "file", "word"])
        output.write_bytes(b"created by the hook")
        self.assertNotEqual(self.identity(spec), hc.context_id(initial))
        pinned = self.describe(spec, argv_kinds=hc.argv_kinds(initial))
        self.assertEqual(hc.context_id(pinned), hc.context_id(initial))

    def test_pinned_file_that_vanishes_becomes_unbound(self):
        spec = self.spec(sys.executable, str(self.script))
        initial = self.describe(spec)
        self.script.unlink()
        final = self.describe(spec, argv_kinds=hc.argv_kinds(initial))
        self.assertEqual(final["hook"]["argv"][1]["status"], "unbound")
        self.assertNotEqual(hc.context_id(final), hc.context_id(initial))

    def test_byte_limits_apply_before_any_content_is_read(self):
        spec = self.spec(sys.executable, str(self.script))
        with (
            mock.patch.object(hc, "MAX_FILE_BYTES", 1),
            mock.patch.object(hc, "MAX_CONTEXT_BYTES", 1),
        ):
            descriptor = self.describe(spec, self.template)
        self.assertEqual(descriptor["hook"]["argv"][0]["reason"], "limit-exceeded")
        self.assertEqual(descriptor["hook"]["argv"][1]["reason"], "limit-exceeded")
        self.assertEqual(descriptor["workspace_template"]["reason"], "limit-exceeded")

    def test_template_walk_stops_before_reading_when_over_a_limit(self):
        for patched in ("MAX_TEMPLATE_ENTRIES", "MAX_CONTEXT_BYTES"):
            with (
                self.subTest(patched),
                mock.patch.object(hc, patched, 1),
                mock.patch.object(hc, "_hash_file", side_effect=AssertionError),
            ):
                template = hc._template(self.template)
            self.assertEqual(
                template, {"status": "unbound", "reason": "limit-exceeded"}
            )

    def test_file_growing_after_stat_is_refused_while_streaming(self):
        self.helper.write_bytes(b"x" * 100)
        with mock.patch.object(hc, "_CHUNK", 10):
            self.assertEqual(hc._hash_file(self.helper, 100)[1], 100)
            small = mock.Mock(st_size=1)
            with mock.patch.object(Path, "stat", return_value=small):
                with self.assertRaises(hc._LimitExceeded):
                    hc._hash_file(self.helper, 50)

    def test_template_symlinks_are_followed_and_cycles_are_unbound(self):
        target = self.root / "shared"
        self.write(target / "z.txt", b"z")
        try:
            (self.template / "link").symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        followed = self.describe(template=self.template)["workspace_template"]
        self.assertEqual(followed["status"], "bound")
        self.assertEqual(followed["entries"], 5)
        (target / "loop").symlink_to(self.template, target_is_directory=True)
        cycle = self.describe(template=self.template)["workspace_template"]
        self.assertEqual(cycle, {"status": "unbound", "reason": "unreadable"})

    def test_descriptor_holds_no_machine_path_or_user_name(self):
        spec = self.spec(sys.executable, str(self.script), str(self.helper))
        text = json.dumps(self.describe(spec, self.template))
        markers = {str(self.root), self.root.as_posix(), str(Path.home())}
        for variable in ("USERNAME", "USER", "LOGNAME"):
            if os.environ.get(variable):
                markers.add(os.environ[variable])
        try:
            markers.add(os.getlogin())
        except OSError:
            pass
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, text)

    def test_inline_code_differing_before_a_slash_changes_the_identity(self):
        # Only absolute paths are reduced; code, regexes and URLs stay whole.
        pairs = [
            ("process.exit(/rm -rf/.test(x)?2:0)", "process.exit(/curl/.test(x)?2:0)"),
            ("import sys; sys.exit(4/2)", "import sys; sys.exit(0/2)"),
            ("https://a.example/x", "https://b.example/x"),
            ("--rules=v1/deny", "--rules=v2/deny"),
        ]
        for first, second in pairs:
            with self.subTest(first=first):
                self.assertNotEqual(
                    self.identity(self.spec(sys.executable, "-c", first)),
                    self.identity(self.spec(sys.executable, "-c", second)),
                )

    def test_absolute_missing_paths_reduce_on_both_path_flavours(self):
        for first, second in (
            ("/one/dir/out.json", "/two/else/out.json"),
            ("C:\\one\\out.json", "D:\\two\\out.json"),
        ):
            with self.subTest(first=first):
                self.assertEqual(
                    self.identity(self.spec(sys.executable, "--log", first)),
                    self.identity(self.spec(sys.executable, "--log", second)),
                )

    def test_absolute_paths_reduce_by_their_own_flavour_on_any_host(self):
        # Pure-path logic, so a Windows host exercises the POSIX case and back.
        self.assertEqual(hc._reduced("C:\\one\\out.json"), "out.json")
        self.assertEqual(hc._reduced("\\\\server\\share\\dir\\out.json"), "out.json")
        self.assertEqual(hc._reduced("/one/dir/out.json"), "out.json")
        self.assertEqual(hc._reduced("rules/v1/deny"), "rules/v1/deny")

    def test_directory_argument_is_declared_unbound_not_hashed_as_a_word(self):
        rules = self.root / "rules"
        rules.mkdir()
        spec = self.spec(sys.executable, str(self.script), str(rules))
        descriptor = self.describe(spec)
        entry = descriptor["hook"]["argv"][2]
        self.assertEqual(
            entry,
            {
                "kind": "directory",
                "name": "rules",
                "status": "unbound",
                "reason": "not-captured",
            },
        )
        self.assertIn("argv-directory:2", descriptor["unbound"])
        hc.validate_hook_context(hc.context_document(descriptor))
        # The pinned kind survives the directory vanishing: still declared.
        rules.rmdir()
        again = self.describe(spec, argv_kinds=hc.argv_kinds(descriptor))
        self.assertEqual(again["hook"]["argv"][2], entry)

    def test_template_containing_the_output_is_unbound(self):
        output = self.template / "runs" / "x"
        descriptor = self.describe(template=self.template, output=output)
        self.assertEqual(
            descriptor["workspace_template"],
            {"status": "unbound", "reason": "contains-output"},
        )
        self.assertIn("workspace-template", descriptor["unbound"])
        hc.validate_hook_context(hc.context_document(descriptor))
        # Decisions later written there cannot move the identity.
        self.write(output / "decisions.jsonl", b'{"effect":"deny"}\n')
        self.assertEqual(
            hc.context_id(descriptor),
            self.identity(template=self.template, output=output),
        )
        outside = self.root / "elsewhere"
        self.assertEqual(
            self.describe(template=self.template, output=outside)["workspace_template"][
                "status"
            ],
            "bound",
        )

    @unittest.skipUnless(os.name == "nt", "CreateProcess search rules")
    def test_bare_name_on_windows_hashes_the_exe_createprocess_runs(self):
        first, second = self.root / "a", self.root / "b"
        self.write(first / "context-fixture-hook.cmd", b"never run")
        self.write(second / "context-fixture-hook.exe", b"the program")
        path = os.pathsep.join((str(first), str(second)))
        with mock.patch.dict(os.environ, {"PATH": path}):
            entry = self.describe(self.spec("context-fixture-hook"))["hook"]["argv"][0]
        self.assertEqual(entry["size"], len(b"the program"))

    def test_large_directory_stops_listing_at_the_entry_limit(self):
        crowded = self.root / "crowded"
        for index in range(20):
            self.write(crowded / f"f{index:02d}", b"")
        with mock.patch.object(hc, "MAX_TEMPLATE_ENTRIES", 5):
            descriptor = self.describe(template=crowded)
        self.assertEqual(descriptor["workspace_template"]["reason"], "limit-exceeded")


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        script = root / "guard.py"
        script.write_bytes(b"pass\n")
        template = root / "template"
        template.mkdir()
        (template / "f.txt").write_bytes(b"f")
        descriptor = hc.describe_hook_context(
            HookSpec((sys.executable, str(script), "--x", "missing.cfg")),
            workspace_template=template,
            jobs=2,
        )
        self.document = hc.context_document(descriptor)

    def rejected(self, document):
        with self.assertRaises(ValueError) as failure:
            hc.validate_hook_context(document)
        self.assertNotIn("tamper", str(failure.exception))
        return str(failure.exception)

    def test_accepts_any_positive_jobs_the_recorder_accepts(self):
        descriptor = copy.deepcopy(self.document["descriptor"])
        descriptor["execution"]["jobs"] = 2**40
        hc.validate_hook_context(hc.context_document(descriptor))

    def with_adapter(self, runtime, contract_id):
        # Re-derive the id, so only the pair itself can be what is rejected.
        descriptor = copy.deepcopy(self.document["descriptor"])
        descriptor["adapter"] = {"runtime": runtime, "contract_id": contract_id}
        return hc.context_document(descriptor)

    def test_rejects_a_fabricated_runtime_and_contract_pair(self):
        for runtime, contract_id in (
            ("claude", "codex-pretooluse.v1"),
            ("codex", "claude-pretooluse.v1"),
            ("codex-legacy", "codex-pretooluse.v1"),
            ("claude", "made-up.v1"),
        ):
            with self.subTest(runtime=runtime, contract_id=contract_id):
                message = self.rejected(self.with_adapter(runtime, contract_id))
                self.assertIn("descriptor.adapter", message)
                self.assertNotIn(contract_id, message)

    def test_accepts_the_historical_codex_floor_pair(self):
        hc.validate_hook_context(self.with_adapter("codex", "codex-legacy-floor.v1"))

    def test_accepts_every_current_registry_pair(self):
        for name in RUNTIMES:
            with self.subTest(runtime=name):
                hc.validate_hook_context(
                    self.with_adapter(name, get_adapter(name).contract_id)
                )

    def test_a_newly_registered_runtime_needs_no_change_here(self):
        adapter = get_adapter("claude")
        registry = {**{n: get_adapter(n) for n in RUNTIMES}, "extra": adapter}
        with (
            mock.patch.object(hc, "RUNTIMES", tuple(registry)),
            mock.patch.object(hc, "get_adapter", registry.__getitem__),
        ):
            hc.validate_hook_context(self.with_adapter("extra", adapter.contract_id))

    def test_accepts_the_written_file_form(self):
        hc.validate_hook_context(self.document)
        written = json.loads(hc.hook_context_bytes(self.document))
        hc.validate_hook_context(written)
        self.assertTrue(hc.hook_context_bytes(self.document).endswith(b"}\n"))

    def test_rejects_a_tampered_descriptor_and_stale_id(self):
        document = copy.deepcopy(self.document)
        document["descriptor"]["execution"]["jobs"] = 3
        self.assertIn("context_id", self.rejected(document))
        document = copy.deepcopy(self.document)
        document["context_id"] = "0" * 64
        self.assertIn("context_id", self.rejected(document))

    def test_rejects_extra_and_missing_keys_at_every_level(self):
        paths = [
            (),
            ("descriptor",),
            ("descriptor", "adapter"),
            ("descriptor", "execution"),
            ("descriptor", "environment"),
            ("descriptor", "workspace_template"),
            ("descriptor", "hook", "argv", 0),
            ("descriptor", "hook", "argv", 1),
            ("descriptor", "hook", "argv", 2),
        ]
        for path in paths:
            for mutate in ("extra", "missing"):
                with self.subTest(path=path, mutate=mutate):
                    document = copy.deepcopy(self.document)
                    node = document
                    for step in path:
                        node = node[step]
                    if mutate == "extra":
                        node["tamper"] = 1
                    else:
                        del node[sorted(node)[0]]
                    self.rejected(document)

    def test_rejects_bad_hex_types_and_vocabularies(self):
        edits = [
            (("context_id",), "A" * 64),
            (("descriptor", "hook", "argv", 0, "sha256"), "abc"),
            (("descriptor", "hook", "argv", 2, "sha256"), "G" * 64),
            (("descriptor", "workspace_template", "tree_sha256"), "0" * 63),
            (("descriptor", "execution", "jobs"), True),
            (("descriptor", "execution", "timeout_seconds"), 10),
            (("descriptor", "decision_mapping", "ask_effect"), "ask"),
            (("descriptor", "adapter", "runtime"), "other"),
            (("descriptor", "hook", "argv", 1, "kind"), "executable"),
            (("descriptor", "hook", "argv", 0, "size"), -1),
            (("descriptor", "environment", "fixed"), {}),
            (("descriptor", "unbound"), ["network"]),
            (("schema_version",), "hook-context.v2"),
        ]
        for path, value in edits:
            with self.subTest(path=path):
                document = copy.deepcopy(self.document)
                node = document
                for step in path[:-1]:
                    node = node[step]
                node[path[-1]] = value
                self.rejected(document)

    def test_rejects_unbound_that_disagrees_with_the_components(self):
        document = copy.deepcopy(self.document)
        document["descriptor"]["unbound"].append("workspace-template")
        document["descriptor"]["unbound"].sort()
        self.rejected(document)

    def test_rejects_non_mapping_documents_without_echoing_them(self):
        for value in (None, [], "text", 7):
            with self.subTest(value=value):
                self.rejected(value)


if __name__ == "__main__":
    unittest.main()
