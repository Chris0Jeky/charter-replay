"""Private transcript importer: extraction, scrubbing and the Git boundary."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from charter_replay import cli as kernel
from charter_replay import importer
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


def _review_redaction_cases() -> list[tuple[str, str, tuple[str, ...]]]:
    password = "Hun" + "ter2"
    apostrophe = "O'" + "Brien2024!"
    cases = [
        (
            f"# connect with the root password:\nmysql -uroot -p{password} db",
            "# connect with the root password:\nmysql -uroot -p<redacted> db",
            (password,),
        ),
        (
            f"echo \"password: 'see below\nbash -c 'mysql -uroot -p{password}'",
            "echo \"password: <redacted> below\nbash -c 'mysql -uroot -p<redacted>'",
            (password,),
        ),
    ]
    for prefix, suffix in (
        ("--password=", ""),
        ("mysql -p", " db"),
        ("API_TOKEN=", ""),
        ("ConvertTo-SecureString ", " -AsPlainText"),
        ("ConvertTo-SecureString -String ", " -AsPlainText -Force"),
    ):
        cases.append(
            (
                prefix + apostrophe + suffix,
                prefix + "<redacted>" + suffix,
                (apostrophe, "Brien2024!"),
            )
        )
    return cases


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

    def test_bare_credentials_consume_backslash_escaped_characters(self) -> None:
        cases = (
            (r"tool --password foo\"SecretTail", "tool --password <redacted>"),
            (r"tool --password=foo\"SecretTail", "tool --password=<redacted>"),
            (r"PASSWORD=foo\"SecretTail", "PASSWORD=<redacted>"),
            (r"api_key: foo\"SecretTail", "api_key: <redacted>"),
            (r"tool --password foo\'SecretTail", "tool --password <redacted>"),
            (r"tool --password foo\\SecretTail", "tool --password <redacted>"),
            (r"tool --password foo\XSecretTail", "tool --password <redacted>"),
            (r"tool --password foo\ SecretTail", "tool --password <redacted>"),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                clean = self.scrubber.scrub(command)
                self.assertNotIn("SecretTail", clean)
                self.assertEqual(clean, expected)
                self.assertEqual(self.scrubber.scrub(clean), clean)

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

    def test_codex_review_shapes_are_scrubbed(self) -> None:
        body = "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"
        for text, secrets in (
            ("echo gh'p%5F'" + body, (body,)),
            (
                'curl "https://build.corp/search?q=O\'Reilly&customer=AcmeSecret"',
                ("Reilly", "AcmeSecret", "build.corp"),
            ),
            (r"cat \\private-build-17\Users\zoe\notes", ("private-build-17", "zoe")),
        ):
            with self.subTest(text=text[:16]):
                scrubbed = self.scrubber.scrub(text)
                for secret in secrets:
                    self.assertNotIn(secret, scrubbed)

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

    def test_attached_json_fields_are_scrubbed_individually(self) -> None:
        for command in (
            """curl --data '{"api_key":"fictional-one","token":"fictional-two","b":1}' """,
            r"""curl --data "{\"api_key\":\"fictional-one\",\"token\":\"fictional-two\",\"b\":1}" """,
        ):
            with self.subTest(command=command):
                clean = self.scrubber.scrub(command)
                self.assertNotIn("fictional-one", clean)
                self.assertNotIn("fictional-two", clean)
                self.assertEqual(clean.count("<redacted>"), 2)
                self.assertIn("1}", clean)

    def test_quoted_private_urls_lose_their_whole_query(self) -> None:
        text = self.scrubber.scrub(
            "curl 'https://build.corp/secrets?x=1&customer=AcmeSecret' && ls"
        )
        self.assertNotIn("AcmeSecret", text)
        self.assertNotIn("build.corp", text)
        self.assertIn("' && ls", text)

    def test_unc_admin_shares_and_wsl_homes_are_scrubbed(self) -> None:
        for path in (
            r"\\fs01\c$\Users\jdoe\x",
            r"\\fs01\C$\Users\jdoe\x",
            "//fs01/c$/Users/jdoe/x",
            r"\\wsl.localhost\Ubuntu\home\jdoe\x",
            r"\\wsl$\Ubuntu\home\jdoe\x",
        ):
            with self.subTest(path=path):
                clean = self.scrubber.scrub("cat " + path)
                self.assertIn("<host>", clean)
                self.assertIn("<user>", clean)
                for private in ("fs01", "wsl.localhost", "wsl$", "jdoe"):
                    self.assertNotIn(private, clean)
                self.assertTrue(clean.endswith("/x") or clean.endswith("\\x"))

    def test_rescans_preserve_surrounding_quotes(self) -> None:
        body = "abcdefgh" + "1234"
        split = "gh'p_'" + body
        for command, expected in (
            (f'echo "{split} done"', 'echo "<token> done"'),
            (f'echo "{split}"', 'echo "<token>"'),
            (f'echo "before {split}"', 'echo "before <token>"'),
            (f"echo {split} done", "echo <token> done"),
            ("echo 'ghp_'" + body, "echo <token>"),
        ):
            with self.subTest(command=command):
                self.assertEqual(self.scrubber.scrub(command), expected)

    def test_bare_assignment_values_preserve_closing_quotes(self) -> None:
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                self.assertEqual(
                    self.scrubber.scrub(
                        f"git commit -m {quote}rotate token: done{quote}"
                    ),
                    f"git commit -m {quote}rotate token: <redacted>{quote}",
                )

    def test_assignment_quote_fidelity_does_not_expose_joined_values(self) -> None:
        tail = "Synthetic" + "Tail42"
        for value in (
            "head'" + tail + "'",
            'head"' + tail + '"',
            "<redacted>" + tail,
            "<redacted>'" + tail + "'",
        ):
            with self.subTest(value=value):
                clean = self.scrubber.scrub("API_TOKEN=" + value)
                self.assertNotIn(tail, clean)

    def test_quoted_credentials_consume_attached_unquoted_tails(self) -> None:
        tail = "Synthetic" + "Tail42"
        for command in (
            f'API_TOKEN="head"{tail}',
            "--password 'ab'cdef",
            f'--password "head"{tail},more; echo after',
            f'API_TOKEN="head"{tail}&echo after',
        ):
            with self.subTest(command=command):
                clean = self.scrubber.scrub(command)
                for secret in ("head", tail, "cdef", "more"):
                    self.assertNotIn(secret, clean)
                self.assertIn("<redacted>", clean)
                if "echo after" in command:
                    self.assertIn("echo after", clean)

    def test_rescans_choose_the_most_redacted_variant(self) -> None:
        body = "Ab12Cd34" + "Ef56Gh78Ij90"
        for prefix in ("gh'p_'", "gh'p%5F'", "ghp%2'5'5F"):
            with self.subTest(prefix=prefix):
                clean = self.scrubber.scrub(
                    "echo " + prefix + body + "%2Fhome%2Fzoe%2Fnotes"
                )
                self.assertEqual(clean, "echo <token>/home/<user>/notes")
                self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_credential_values_on_the_next_nonempty_line_are_redacted(self) -> None:
        value = "fictional" + "NextValue42"
        for ending in ("\n", "\r\n", "\r", "\u2028"):
            for key in ("password:", "API_TOKEN=", '"api_key":', "--password", "-p"):
                with self.subTest(ending=repr(ending), key=key):
                    text = key + ending + "  " + ending + f"  {value} keep"
                    expected = key + ending + "  " + ending + "  <redacted> keep"
                    clean = self.scrubber.scrub(text)
                    self.assertEqual(clean, expected)
                    self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_cross_line_cuts_preserve_other_credential_rules(self) -> None:
        for index, (command, _, secrets) in enumerate(_review_redaction_cases()[:2]):
            with self.subTest(case=index):
                clean = self.scrubber.scrub(command)
                for secret in secrets:
                    self.assertNotIn(secret, clean)
                self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_internal_unmatched_quotes_do_not_expose_value_suffixes(self) -> None:
        for index, (command, expected, _) in enumerate(_review_redaction_cases()[2:]):
            with self.subTest(case=index):
                self.assertEqual(self.scrubber.scrub(command), expected)

    def test_cross_line_scrub_never_exposes_single_line_redactions(self) -> None:
        password = "fictional" + "SecurePw42"
        body = "Ab12Cd34" + "Ef56Gh78Ij90"
        jwt = "ey" + "JhbGciOiJub25lIn0.eyJzdWIiOiJmaWN0aW9uYWwifQ."
        # Frozen main-era single-line outputs keep this oracle independent of
        # both the cross-line state and changes to the value matcher.
        corpus = _review_redaction_cases() + [
            (f"mysql -p{password} db", "mysql -p<redacted> db", (password,)),
            (
                f'ConvertTo-SecureString "{password}" -AsPlainText',
                "ConvertTo-SecureString <redacted> -AsPlainText",
                (password,),
            ),
            ("echo " + jwt, "echo <token>", (jwt,)),
            ("echo gh'p%5F'" + body, "echo <token>", (body,)),
            ("echo ghp%255F" + body, "echo <token>", (body,)),
            (
                'curl -d "{\\"api_key\\":\\"' + password + '\\"}"',
                'curl -d "{\\"api_key\\":<redacted>}"',
                (password,),
            ),
            (
                'curl --data \'{"api_key":"x","b":1}\'',
                'curl --data \'{"api_key":<redacted>,"b":1}\'',
                ("x",),
            ),
            (
                'git commit -m "rotate token: done"',
                'git commit -m "rotate token: <redacted>"',
                ("done",),
            ),
            (
                'curl "https://build.corp/search?q=O\'Reilly&customer=AcmeSecret"',
                'curl "https://<host>/<path>"',
                ("build.corp", "Reilly", "AcmeSecret"),
            ),
            (
                "curl https://example.com/?next=https://build_node.corp/team/project",
                "curl https://example.com/?next=https://<host>/<path>",
                ("build_node", "team", "project"),
            ),
            (
                "gh pr view 1 --repo ownerlogin/secretproject",
                "gh pr view 1 --repo <owner>/<repo>",
                ("ownerlogin", "secretproject"),
            ),
            (
                "git clone git@buildhost:team/secret.git|wc",
                "git clone <host>:<path>|wc",
                ("buildhost", "team", "secret.git"),
            ),
            (
                r"cat \\fs01\c$\Users\jdoe\x",
                r"cat \\<host>\c$\Users\<user>\x",
                ("jdoe",),
            ),
            (
                r"cat \\wsl.localhost\Ubuntu\home\jdoe\x",
                r"cat \\<host>\Ubuntu\home\<user>\x",
                ("jdoe",),
            ),
            (
                r'echo "prefix C:\Users\Jane Roe\notes"',
                r'echo "prefix C:\Users\<user>\notes"',
                ("Jane Roe",),
            ),
            (
                "curl https://example.com/?user=zoe%40mail.example",
                "curl https://example.com/?user=<email>",
                ("zoe",),
            ),
            (
                "curl https://example.com/?path=%2Fhome%2Fzoe%2Fnotes",
                "curl https://example.com/?path=/home/<user>/notes",
                ("zoe",),
            ),
            ("token" * 20000, "<redacted>", ("token",)),
            ("a." * 50000, "<redacted>", ("a.",)),
        ]
        for index, (command, expected, secrets) in enumerate(corpus):
            for prefix in ("", "password:\n", 'API_TOKEN="see below\n'):
                with self.subTest(case=index, context=bool(prefix)):
                    baseline = "\n".join(
                        self.scrubber.scrub(line) for line in command.split("\n")
                    )
                    clean = self.scrubber.scrub(prefix + command)
                    for secret in secrets:
                        self.assertNotIn(secret, expected)
                        self.assertNotIn(secret, baseline)
                        self.assertNotIn(secret, clean)

    def test_credential_prefixes_inside_a_scanned_value_are_not_rescanned(self) -> None:
        command = '-pass=""' * 512
        with mock.patch.object(
            importer, "_credential_end", wraps=importer._credential_end
        ) as scan:
            self.scrubber._scrub_lines(command)
        self.assertEqual(scan.call_count, 1)

    def test_multiline_quoted_credentials_are_redacted_through_closing_quote(
        self,
    ) -> None:
        first = "fictional" + "First42"
        second = "fictional" + "Second42"
        for prefix in ("export DB_PASSWORD=", "curl --password ", "password:\n  "):
            for quote in ('"', "'"):
                with self.subTest(prefix=prefix, quote=quote):
                    text = f"{prefix}{quote}{first}\n\n{second}{quote}; echo after"
                    clean = self.scrubber.scrub(text)
                    self.assertNotIn(first, clean)
                    self.assertNotIn(second, clean)
                    self.assertTrue(clean.endswith("; echo after"))
                    self.assertEqual(clean.count("\n"), text.count("\n"))
                    self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_multiline_quote_state_stops_at_line_budget_or_size_guard(self) -> None:
        value = "fictional" + "Inside42"
        # The opening line counts towards the 16-line budget.
        text = 'API_TOKEN="' + value + "\n" + (value + "\n") * 15 + "echo after"
        clean = self.scrubber.scrub(text)
        self.assertNotIn(value, clean)
        self.assertTrue(clean.endswith("echo after"))
        self.assertEqual(self.scrubber.scrub(clean), clean)
        for prefix in ('API_TOKEN="' + value, "password:"):
            with self.subTest(prefix=prefix[:10]):
                text = prefix + "\n" + "x" * 4097 + "\necho after"
                clean = self.scrubber.scrub(text)
                self.assertNotIn(value, clean)
                self.assertTrue(clean.endswith("\n<redacted>\necho after"))
                self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_mysql_backslash_continuations_keep_credential_context(self) -> None:
        value = "fictional" + "MysqlNext42"
        for ending in ("\n", "\r\n"):
            for middle in ("", "  --host example.com \\\n"):
                with self.subTest(ending=repr(ending), middle=bool(middle)):
                    text = (
                        "mysql -u root \\"
                        + ending
                        + middle
                        + f"  -p{value} db\necho after"
                    )
                    clean = self.scrubber.scrub(text)
                    self.assertNotIn(value, clean)
                    self.assertIn("-p<redacted> db", clean)
                    self.assertTrue(clean.endswith("\necho after"))
                    self.assertEqual(self.scrubber.scrub(clean), clean)
        for flag in ("--password", "-p"):
            text = f"mysql {flag} \\\n  {value} db"
            clean = self.scrubber.scrub(text)
            self.assertNotIn(value, clean)
            self.assertEqual(self.scrubber.scrub(clean), clean)
        # An escaped backslash or a finished command must not carry mysql scope.
        for head in ("mysql -u root", "mysql -u root " + "\\" * 2, "echo ready \\"):
            text = head + f"\n  -p{value} db"
            self.assertEqual(self.scrubber.scrub(text), text)
        text = f"mysql \\\n  -p{value} db; echo \\\n  -pkeep"
        self.assertTrue(self.scrubber.scrub(text).endswith("\n  -pkeep"))

    def test_credential_quote_concatenation_includes_spaces_in_later_segments(
        self,
    ) -> None:
        first = "fictional" + "Joined42"
        second = "fictional" + "Spaced42"
        for prefix in ("curl --password ", "API_TOKEN=", "mysql -p"):
            for value in (
                f"\"{first}\"'{second} tail'",
                f"'{first}'bare\"{second} tail\"'last part'",
            ):
                with self.subTest(prefix=prefix, quoted=value[0]):
                    clean = self.scrubber.scrub(prefix + value + "; echo after")
                    self.assertEqual(clean, prefix + "<redacted>; echo after")
                    self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_pgp_private_key_blocks_are_redacted_whole(self) -> None:
        material = "fictional" + "PgpBody42"
        checksum = "=" + "Ab42"
        text = (
            "echo before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n"
            + material
            + "\nshort\n"
            + checksum
            + "\n-----END PGP PRIVATE KEY BLOCK-----\necho after\n"
        )
        clean = self.scrubber.scrub(text)
        self.assertEqual(clean, "echo before\n<private-key>\necho after\n")
        self.assertEqual(self.scrubber.scrub(clean), clean)

    def test_quoted_credential_near_matches_scrub_in_bounded_time(self) -> None:
        # Missing -AsPlainText forces the value matcher to reject the input.
        # Escaped quotes must not have exponentially many segmentations.
        sample = "ConvertTo-SecureString " + '\\"x\\"' * 800
        program = (
            "from charter_replay.importer import Scrubber; "
            f"Scrubber().scrub({sample!r})"
        )
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            timeout=10,
            check=True,
        )
        self.assertEqual(result.stdout, b"")
        self.assertLess(time.monotonic() - started, 10)

    def test_escaped_bare_credentials_near_limit_scrub_in_bounded_time(self) -> None:
        prefix = "tool --password foo"
        tail = "SecretTail"
        # Stay below the line guard so the matcher must consume every escape.
        escapes = (r"\\\"" * 1024)[: 4095 - len(prefix) - len(tail)]
        sample = prefix + escapes + tail
        self.assertEqual(len(sample), 4095)
        program = (
            "from charter_replay.importer import Scrubber; "
            "s = Scrubber(); "
            f"clean = s.scrub({sample!r}); "
            "assert 'SecretTail' not in clean; "
            "assert clean == 'tool --password <redacted>'; "
            "assert s.scrub(clean) == clean"
        )
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertLess(time.monotonic() - started, 10)

    def test_cross_line_credential_state_scrubs_many_short_lines_in_bounded_time(
        self,
    ) -> None:
        program = (
            "from charter_replay.importer import Scrubber; "
            "s = Scrubber(); "
            "value = 'fictional' + 'Timing42'; "
            "sample = 'password:\\n\\n' + value + '\\n' "
            "+ 'mysql ' + chr(92) + '\\n  -p' + value + '\\n' "
            "+ 'API_TOKEN=\"' + value + '\\n' + value + '\"\\n'; "
            "text = sample * 10000; "
            "clean = s.scrub(text); "
            "assert value not in clean; "
            "assert s.scrub(clean) == clean"
        )
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            timeout=10,
            check=True,
        )
        self.assertEqual(result.stdout, b"")
        self.assertLess(time.monotonic() - started, 10)

    def test_rescans_keep_the_earlier_variant_on_equal_redaction(self) -> None:
        self.assertEqual(
            self.scrubber.scrub("echo %2Fhome%2Fzoe%2Fnotes%2520after"),
            "echo /home/<user>/notes%20after",
        )

    def test_short_lines_and_near_limit_lines_scrub_in_bounded_time(self) -> None:
        # Each case is isolated so quadratic regressions cannot hang the suite.
        samples = [
            "mysql" + ending
            for ending in (
                "\n",
                "\r",
                "\r\n",
                "\v",
                "\f",
                "\x1c",
                "\x1d",
                "\x1e",
                "\x85",
                "\u2028",
                "\u2029",
            )
        ]
        cases = [(sample, 30000) for sample in samples]
        cases.append(("-----BEGIN PRIVATE KEY-----\n", 30000))
        # These remain below the guard and must actually exercise the regexes.
        cases.extend(
            (sample[:4095], 1)
            for sample in (
                "mysql " * 683,
                "token" * 819,
                "a." * 2048,
                '"' * 4095,
                "-----BEGIN PRIVATE KEY-----" + "x" * 4095,
            )
        )
        for sample, repeats in cases:
            with self.subTest(sample=repr(sample[:28]), repeats=repeats):
                program = (
                    "from charter_replay.importer import Scrubber; "
                    "s = Scrubber(); "
                    f"s.scrub({sample!r} * {repeats})"
                )
                started = time.monotonic()
                result = subprocess.run(
                    [sys.executable, "-c", program],
                    capture_output=True,
                    timeout=10,
                    check=True,
                )
                self.assertEqual(result.stdout, b"")
                self.assertLess(time.monotonic() - started, 10)

    def test_multiline_private_keys_are_scrubbed_before_line_processing(self) -> None:
        for label in ("", "RSA ", "EC ", "ENCRYPTED "):
            with self.subTest(label=label):
                text = (
                    "echo before\n"
                    f"-----BEGIN {label}PRIVATE KEY-----\n"
                    "fictional key material\n" + "x" * 5000 + "\n"
                    f"-----END {label}PRIVATE KEY-----\n"
                    "echo after\n"
                )
                self.assertEqual(
                    self.scrubber.scrub(text),
                    "echo before\n<private-key>\necho after\n",
                )

    def test_percent_encoded_multiline_private_keys_are_scrubbed(self) -> None:
        text = (
            "-----BEGIN PRIVATE KEY-----\n"
            "fictional key material\n"
            "-----END PRIVATE KEY-----"
        )
        encoded = text.replace(" ", "%20").replace("\n", "%0A")
        self.assertEqual(self.scrubber.scrub("echo " + encoded), "echo <private-key>")

    def test_long_dotted_lines_scrub_in_bounded_time(self) -> None:
        # Isolate the timing check so an old quadratic regex cannot hang the suite.
        program = (
            "from charter_replay.importer import Scrubber; "
            "s = Scrubber(); "
            "[s.scrub(line) for line in "
            "('a.' * 50000, 'a-' * 50000, 'a_' * 50000, "
            "'a.' * 50000 + '@example.com', "
            "'https://' + 'a.' * 50000)]"
        )
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            timeout=10,
            check=True,
        )
        self.assertEqual(result.stdout, b"")
        self.assertLess(time.monotonic() - started, 10)

    def test_oversized_lines_are_redacted_without_losing_other_lines(self) -> None:
        text = "echo before\n" + "a." * 50000 + "\necho after\n"
        self.assertEqual(
            self.scrubber.scrub(text),
            "echo before\n<redacted>\necho after\n",
        )
        boundary = "x " * 2048
        self.assertEqual(self.scrubber.scrub(boundary), boundary)
        self.assertEqual(self.scrubber.scrub(boundary + "x"), "<redacted>")
        # Guard Unicode and alternate line separators too; no payload survives.
        for ending in ("\r\n", "\r", "\u2028"):
            self.assertEqual(
                self.scrubber.scrub("a." * 50000 + ending + "echo after"),
                "<redacted>" + ending + "echo after",
            )

    def test_double_percent_encoding_and_unsigned_jwts_are_scrubbed(self) -> None:
        body = "Ab12Cd34" + "Ef56Gh78Ij90"
        unsigned = "ey" + "JhbGciOiJub25lIn0.eyJzdWIiOiJmaWN0aW9uYWwifQ."
        for command, secret in (
            ("echo ghp%255F" + body, body),
            ("echo gh'p%255F'" + body, body),
            ("echo " + unsigned, unsigned),
        ):
            with self.subTest(command=command[:16]):
                self.assertNotIn(secret, self.scrubber.scrub(command))
                self.assertIn("<token>", self.scrubber.scrub(command))

    def test_percent_escapes_split_by_quotes_are_scrubbed(self) -> None:
        body = "Ab12Cd34" + "Ef56Gh78Ij90"
        for prefix in ("ghp%5'F'", "ghp%2'5'5F"):
            with self.subTest(prefix=prefix):
                self.assertNotIn(body, self.scrubber.scrub("echo " + prefix + body))

    def test_mysql_attached_passwords_are_scrubbed(self) -> None:
        secret = "fictional" + "MysqlPw42"
        for command in (
            f"mysql -p{secret} db",
            f'mysql -p"{secret}" db',
            f"mysql.exe --host example.com -p{secret}; echo done",
        ):
            with self.subTest(command=command[:16]):
                clean = self.scrubber.scrub(command)
                self.assertNotIn(secret, clean)
                self.assertIn("-p<redacted>", clean)
        self.assertEqual(self.scrubber.scrub("mysql -p db"), "mysql -p db")

    def test_powershell_plaintext_secure_strings_are_scrubbed(self) -> None:
        secret = "fictional" + "SecurePw42"
        for value in (f'"{secret}"', f"'{secret}'", secret):
            command = f"ConvertTo-SecureString {value} -AsPlainText -Force; echo done"
            clean = self.scrubber.scrub(command)
            self.assertNotIn(secret, clean)
            self.assertIn("; echo done", clean)
        self.assertNotIn(
            secret,
            self.scrubber.scrub(
                f'ConvertTo-SecureString -String "{secret}" -AsPlainText -Force'
            ),
        )

    def test_underscore_hosts_and_nested_private_urls_are_scrubbed(self) -> None:
        for command in (
            "curl https://build_node.corp/team/project",
            "git clone git@build_node.corp:team/project",
            "curl https://example.com/?next=https://build_node.corp/team/project",
            'curl "https://example.com/?next=https://build_node.corp/team/project&ok=1"',
            "curl https://example.com/?next=https%3A%2F%2Fbuild_node.corp%2Fteam%2Fproject",
        ):
            with self.subTest(command=command[:30]):
                clean = self.scrubber.scrub(command)
                self.assertNotIn("build_node", clean)
                self.assertNotIn("team", clean)
                self.assertNotIn("project", clean)
                self.assertIn("<host>", clean)
        self.assertIn("https://example.com/", clean)

    def test_quoted_spaced_home_names_after_a_prefix_are_scrubbed(self) -> None:
        for command in (
            r'echo "prefix C:\Users\Jane Roe\notes"',
            'echo "prefix /home/Jane Roe/notes"',
            "echo 'prefix /Users/Jane Roe/notes'",
        ):
            clean = self.scrubber.scrub(command)
            self.assertNotIn("Jane", clean)
            self.assertNotIn("Roe", clean)
            self.assertIn("prefix", clean)
            self.assertIn("notes", clean)

    def test_scrubbing_is_idempotent_and_known_secrets_never_survive(self) -> None:
        body = "Ab12Cd34" + "Ef56Gh78Ij90"
        jwt = "ey" + "JhbGciOiJub25lIn0.eyJzdWIiOiJmaWN0aW9uYWwifQ."
        password = "fictional" + "SecurePw42"
        # Fixed corpus drawn from the inputs above, including #62's regressions.
        corpus = [
            "echo gh'p%5F'" + body,
            f"echo \"gh'p_'{body} done\"",
            "echo ghp%255F" + body,
            "echo ghp%2'5'5F" + body,
            "echo " + jwt,
            f"mysql -p{password} db",
            f'ConvertTo-SecureString "{password}" -AsPlainText',
            r"cat \\fs01\c$\Users\jdoe\x",
            r"cat \\wsl.localhost\Ubuntu\home\jdoe\x",
            r'echo "prefix C:\Users\Jane Roe\notes"',
            'git commit -m "rotate token: done"',
            "curl https://example.com/?next=https://build_node.corp/team/project",
            'curl "https://build.corp/search?q=O\'Reilly&customer=AcmeSecret"',
            "curl https://example.com/?user=zoe%40mail.example",
            "curl https://example.com/?path=%2Fhome%2Fzoe%2Fnotes",
            'curl --data \'{"api_key":"x","b":1}\'',
            'curl -d "{\\"api_key\\":\\"' + password + '\\"}"',
            "gh pr view 1 --repo ownerlogin/secretproject",
            "git clone git@buildhost:team/secret.git|wc",
            "token" * 20000,
            "a." * 50000,
        ]
        secrets = (
            body,
            jwt,
            password,
            "jdoe",
            "Jane Roe",
            "build_node",
            "AcmeSecret",
            "zoe",
        )
        for index, command in enumerate(corpus):
            with self.subTest(index=index):
                clean = self.scrubber.scrub(command)
                self.assertEqual(self.scrubber.scrub(clean), clean)
                for secret in secrets:
                    self.assertNotIn(secret, clean)

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
            (repo / ".git" / "objects").mkdir(parents=True)
            (repo / ".git" / "refs").mkdir()
            (repo / ".git" / "HEAD").write_text(
                "ref: refs/heads/main\n", encoding="utf-8"
            )
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
