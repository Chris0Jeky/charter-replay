"""Private transcript importer: extraction, scrubbing and the Git boundary."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from charter_replay import cli as kernel
from charter_replay.importer import (
    Scrubber,
    build_private_corpus,
    claude_commands,
    codex_commands,
    output_is_private,
    write_corpus,
)

REPO = Path(__file__).resolve().parents[3]
HAS_GIT = shutil.which("git") is not None


def _write_jsonl(path: Path, records: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
    )


class ScrubberTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scrubber = Scrubber(["projectphoenix"])

    def test_credentials_are_replaced(self) -> None:
        # Assembled at runtime so this file holds no credential-shaped literal.
        samples = [
            "gh" + "p_" + "A1b2" * 9,
            "github" + "_pat_" + "Z9" * 20,
            "s" + "k-" + "q" * 30,
            "AK" + "IA" + "Q" * 16,
            "ey" + "J" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
        ]
        for secret in samples:
            with self.subTest(prefix=secret[:4]):
                self.assertNotIn(secret, self.scrubber.scrub(f"use {secret} now"))

    def test_assignments_and_headers_are_redacted(self) -> None:
        text = self.scrubber.scrub(
            'API_TOKEN=abc123 curl -H "Authorization: Bearer abcdefghij" x'
        )
        self.assertIn("API_TOKEN=<redacted>", text)
        self.assertNotIn("abcdefghij", text)
        self.assertNotIn("abc123", text)

    def test_home_paths_emails_hosts_and_repos(self) -> None:
        text = self.scrubber.scrub(
            "cat C:\\Users\\someone\\notes /home/someone/x /Users/someone/y "
            "mail a.person@corp.example.net "
            "curl https://build.internal.corp/api https://example.com/ok "
            "gh pr view 3 --repo someorg/somerepo "
            "git clone git@github.com:someorg/somerepo.git"
        )
        self.assertNotIn("someone", text)
        self.assertNotIn("a.person", text)
        self.assertNotIn("internal.corp", text)
        self.assertIn("https://example.com/ok", text)
        self.assertNotIn("someorg", text)
        self.assertNotIn("somerepo", text)

    def test_flag_and_user_credentials_are_redacted(self) -> None:
        text = self.scrubber.scrub(
            "docker login -u me --password hunter2hunter2; tool --token abc123def; "
            "curl -u admin:S3cretPw https://example.com"
        )
        for secret in ("hunter2hunter2", "abc123def", "S3cretPw"):
            self.assertNotIn(secret, text)

    def test_a_home_name_with_a_space_is_fully_removed(self) -> None:
        scrubber = Scrubber(["Jane Doe", "Jane", "Doe"])
        text = scrubber.scrub(r"cd C:\Users\Jane Doe\repo")
        self.assertNotIn("Doe", text)
        self.assertNotIn("Jane", text)

    def test_identity_terms_do_not_shield_repos_or_emails(self) -> None:
        scrubber = Scrubber(["ownerlogin", "mail.example.net"])
        text = scrubber.scrub(
            "gh pr view 1 --repo ownerlogin/secretproject; "
            "git log --author someone@mail.example.net"
        )
        self.assertNotIn("secretproject", text)
        self.assertNotIn("someone", text)

    def test_private_hosts_lose_their_path_in_any_url_form(self) -> None:
        text = self.scrubber.scrub(
            "git clone ssh://git@code.private.corp/acme/secret.git; "
            "git clone git@code.private.corp:acme/secret.git; "
            "git fetch git://build.internal:9418/team/proj"
        )
        for private in ("private.corp", "acme", "secret", "build.internal", "proj"):
            self.assertNotIn(private, text)

    def test_url_scrub_keeps_the_following_command(self) -> None:
        text = self.scrubber.scrub(
            "curl https://private.corp/a;rm -rf /tmp/x && "
            "git clone git@buildhost:team/secret.git|wc"
        )
        self.assertIn(";rm -rf /tmp/x && ", text)
        self.assertIn("|wc", text)
        for private in ("private.corp", "buildhost", "team", "secret"):
            self.assertNotIn(private, text)

    def test_short_jwts_and_npm_tokens_are_replaced(self) -> None:
        samples = [
            "ey" + "JhbGciOiJIUzI1NiJ9" + ".e30." + "aaIGT-BFLnc0LS81LJnR",
            "np" + "m_" + "abcdefghij" * 3 + "0123456789",
        ]
        for secret in samples:
            with self.subTest(prefix=secret[:4]):
                self.assertNotIn(secret, self.scrubber.scrub(f"echo {secret}"))

    def test_numbered_names_and_quoted_keys_are_redacted(self) -> None:
        value = "Orange" + "Elephant42"
        for text in (
            f"API_KEY2={value} tool",
            f"""curl --data '{{"api_key":"{value}"}}' https://example.com""",
            f"""cfg "token": '{value}'""",
        ):
            with self.subTest(text=text[:12]):
                self.assertNotIn(value, self.scrubber.scrub(text))

    def test_percent_encoded_and_split_values_are_scrubbed(self) -> None:
        body = "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"
        cases = {
            "echo gh'p_'" + body: body,
            "echo ghp%5F" + body: body,
            "curl https://example.com/?user=zoe%40mail.example": "zoe",
            "curl https://example.com/?path=%2Fhome%2Fzoe%2Fnotes": "zoe",
        }
        for text, secret in cases.items():
            with self.subTest(text=text[:16]):
                self.assertNotIn(secret, self.scrubber.scrub(text))

    def test_quoted_home_names_with_spaces_and_unc_homes_are_removed(self) -> None:
        for text in (
            r'cat "C:\Users\Jane Roe\notes"',
            'cat "/Users/Jane Roe/notes"',
            "cat '/home/Jane Roe/notes'",
            r"cat \\server\Users\zoe\notes",
            "cat //server/Users/zoe/notes",
        ):
            with self.subTest(text=text):
                scrubbed = Scrubber().scrub(text)
                self.assertNotIn("Roe", scrubbed)
                self.assertNotIn("zoe", scrubbed)
                self.assertIn("notes", scrubbed)

    def test_escaped_json_keys_and_other_auth_schemes_are_redacted(self) -> None:
        value = "s3cr3t" + "Value9"
        hexish = "9f8e7d6c" + "5b4a3a2b1c0d"
        for text, secret in (
            ('curl -d "{\\"api_key\\":\\"' + value + '\\"}"', value),
            ('curl -H "Authorization: Token ' + hexish + '"', hexish),
            ('curl -H "Authorization: Bot ' + hexish + '"', hexish),
        ):
            with self.subTest(text=text[:24]):
                self.assertNotIn(secret, self.scrubber.scrub(text))

    def test_long_keyword_runs_scrub_in_bounded_time(self) -> None:
        # Unbounded name runs made this ~100 KB line take over a minute.
        started = time.monotonic()
        self.scrubber.scrub("token" * 20000)
        self.assertLess(time.monotonic() - started, 10)

    def test_rescans_keep_already_redacted_words_intact(self) -> None:
        self.assertEqual(
            Scrubber().scrub("""curl --data '{"api_key":"x","b":1}'"""),
            """curl --data '{"api_key":<redacted>,"b":1}'""",
        )

    def test_quoted_private_urls_lose_their_whole_query(self) -> None:
        text = self.scrubber.scrub(
            "curl 'https://build.corp/secrets?x=1&customer=AcmeSecret' && ls"
        )
        self.assertNotIn("AcmeSecret", text)
        self.assertNotIn("build.corp", text)
        self.assertIn("' && ls", text)

    def test_extra_terms_match_inside_joined_paths(self) -> None:
        text = self.scrubber.scrub("cd /src/ProjectPhoenix-app && ls xprojectphoenix")
        self.assertNotIn("phoenix", text.lower())


class ExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_claude_tool_uses(self) -> None:
        _write_jsonl(
            self.root / "claude" / "p" / "s.jsonl",
            [
                {
                    "timestamp": "2026-02-03T04:05:06.789Z",
                    "cwd": "/fictional/app",
                    "message": {
                        "content": [
                            {"type": "text", "text": "hi"},
                            {
                                "type": "tool_use",
                                "name": "Bash",
                                "input": {"command": "git status"},
                            },
                            {
                                "type": "tool_use",
                                "name": "Read",
                                "input": {"file_path": "x"},
                            },
                        ]
                    },
                },
                "not an object",
            ],
        )
        with (self.root / "claude" / "p" / "s.jsonl").open("a") as handle:
            handle.write("{broken\n")
        stats: Counter[str] = Counter()
        found = list(claude_commands(self.root / "claude", stats))
        self.assertEqual(
            found, [("git status", "2026-02-03T04:05:06Z", "/fictional/app")]
        )
        self.assertEqual(stats["unparsed-lines"], 1)

    def test_codex_function_calls(self) -> None:
        call = {"type": "function_call", "name": "shell_command"}
        _write_jsonl(
            self.root / "codex" / "r.jsonl",
            [
                {"payload": {"type": "turn_context", "cwd": "/fictional/svc"}},
                {"payload": {**call, "arguments": json.dumps({"command": "ls -la"})}},
                {
                    "payload": {
                        **call,
                        "name": "shell",
                        "arguments": json.dumps({"command": ["bash", "-lc", "make"]}),
                    }
                },
                {
                    "payload": {
                        **call,
                        "name": "shell",
                        "arguments": json.dumps({"command": ["tool", "a b"]}),
                    }
                },
                {"payload": {**call, "arguments": "{"}},
            ],
        )
        stats: Counter[str] = Counter()
        found = [item[0] for item in codex_commands(self.root / "codex", stats)]
        self.assertEqual(found, ["ls -la", "make"])
        self.assertEqual(stats["codex-unparsed-calls"], 2)

    def test_corpus_is_scrubbed_deduplicated_and_loadable(self) -> None:
        commands = [
            ("ls /home/someone", "2026-01-01T00:00:00Z", None),
            ("ls /home/other", "2026-01-01T00:00:01Z", None),
            ("git status", "2026-01-01T00:00:02Z", None),
        ]
        events, cases, stats = build_private_corpus(
            [("claude", iter(commands))], Scrubber([])
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(stats["duplicates"], 1)
        self.assertEqual({case["case_class"] for case in cases}, {"opaque"})
        output = self.root / "corpus"
        write_corpus(output, events, cases)
        loaded = kernel._load_charter_corpus(str(output))
        self.assertEqual(loaded.event_count, 2)
        self.assertEqual(loaded.events[0]["source"], "historical-redacted")


@unittest.skipUnless(HAS_GIT, "git is not installed")
class GitBoundaryTests(unittest.TestCase):
    def test_output_inside_an_unignored_work_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            self.assertFalse(output_is_private(repo / "corpus"))
            ignore = repo / ".gitignore"
            ignore.write_text("/corpus/events.jsonl\n", encoding="utf-8")
            self.assertFalse(output_is_private(repo / "corpus"))
            ignore.write_text("/corpus/\n", encoding="utf-8")
            self.assertTrue(output_is_private(repo / "corpus"))

    def test_output_outside_any_work_tree_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if any((parent / ".git").exists() for parent in Path(tmp).parents):
                self.skipTest("temporary directory sits inside a Git work tree")
            self.assertTrue(output_is_private(Path(tmp) / "corpus"))

    def test_this_repository_ignores_private_corpora(self) -> None:
        for path in (".local/private-corpus", "examples/private-corpus"):
            with self.subTest(path=path):
                self.assertTrue(output_is_private(REPO / path))

    def test_no_private_corpus_is_tracked(self) -> None:
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "*corpus-manifest.json"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        for name in tracked:
            manifest = json.loads((REPO / name).read_text(encoding="utf-8"))
            self.assertNotEqual(manifest.get("corpus_id"), "private-local", name)
        paths = subprocess.run(
            ["git", "-C", str(REPO), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        self.assertFalse([path for path in paths if "private-corpus/" in path])


if __name__ == "__main__":
    unittest.main()
