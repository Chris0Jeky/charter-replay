"""Repeat-stability classification, document determinism and exit precedence."""

from __future__ import annotations

import hashlib
import itertools
import json
import unittest

from charter_replay import repeat

CONTEXT = "a" * 64
OTHER_CONTEXT = "b" * 64
EVENTS = ["e1", "e2", "e3"]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def obs(effect="allow", outcome="allow", reason="allow: ok"):
    return (effect, outcome, digest(reason))


def record(index, per_event, *, context=CONTEXT, failures=None):
    return repeat.RepeatRecord(
        index,
        context,
        failures or {},
        dict(zip(EVENTS, per_event)),
    )


def uniform(index, **kwargs):
    return record(index, [obs(), obs(), obs()], **kwargs)


class ClassifyTests(unittest.TestCase):
    def test_each_class_and_precedence(self):
        allow, deny = obs(), obs("deny", "deny", "deny: no")
        cases = {
            "stable": [allow, allow, allow],
            "reason-varies": [allow, obs(reason="allow: other")],
            "outcome-varies": [
                obs("deny", "deny", "deny: x"),
                obs("deny", "stop", "deny: x"),
            ],
            "effect-varies": [allow, deny],
        }
        for expected, observations in cases.items():
            self.assertEqual(repeat.classify_event(observations), expected)
        # The strongest difference names the event.
        mixed = [obs("allow", "allow", "a"), obs("deny", "stop", "b")]
        self.assertEqual(repeat.classify_event(mixed), "effect-varies")
        both = [obs("deny", "deny", "a"), obs("deny", "stop", "b")]
        self.assertEqual(repeat.classify_event(both), "outcome-varies")

    def test_indeterminate_counts_as_an_effect(self):
        flaky = [obs(), obs("indeterminate", "timeout", "timeout: no reply")]
        self.assertEqual(repeat.classify_event(flaky), "effect-varies")

    def test_classification_ignores_observation_order(self):
        items = [
            obs(),
            obs("deny", "deny", "deny: a"),
            obs("deny", "stop", "stop: b"),
        ]
        results = {
            (repeat.classify_event(order), json.dumps(repeat.event_row("e", order)))
            for order in itertools.permutations(items)
        }
        self.assertEqual(len(results), 1)

    def test_empty_observations_are_refused(self):
        with self.assertRaises(ValueError):
            repeat.classify_event([])

    def test_reason_digest_is_sha256_of_the_reason(self):
        self.assertEqual(repeat.reason_digest("deny: x"), digest("deny: x"))
        self.assertEqual(len(repeat.reason_digest("\ud800")), 64)

    def test_row_counts_variants_and_distinct_reason_digests(self):
        row = repeat.event_row(
            "e1",
            [
                obs(reason="allow: t1"),
                obs(reason="allow: t2"),
                obs(reason="allow: t2"),
                obs("deny", "deny", "deny: x"),
            ],
        )
        self.assertEqual(
            row["variants"],
            [
                {"effect": "allow", "outcome": "allow", "count": 3},
                {"effect": "deny", "outcome": "deny", "count": 1},
            ],
        )
        self.assertEqual(sorted(item["count"] for item in row["reasons"]), [1, 1, 2])
        self.assertNotIn("t1", json.dumps(row))


class AdmissionTests(unittest.TestCase):
    def test_repeat_bounds(self):
        self.assertEqual(repeat.parse_repeats("2"), 2)
        self.assertEqual(repeat.parse_repeats(50), 50)
        for bad in ("1", "51", "0", "-3", "--5", "2.5", "", "x", "٣", " ", True):
            with self.subTest(bad=bad), self.assertRaises(repeat.RepeatInputError):
                repeat.parse_repeats(bad)

    def test_fail_on_is_sorted_named_and_unique(self):
        self.assertEqual(
            repeat.parse_fail_on("reason-varies,effect-varies"),
            ("effect-varies", "reason-varies"),
        )
        for bad in ("stable", "", "effect-varies,effect-varies", "nope"):
            with self.subTest(bad=bad), self.assertRaises(repeat.RepeatInputError):
                repeat.parse_fail_on(bad)


class DocumentTests(unittest.TestCase):
    def test_stable_document_shape(self):
        document = repeat.build_document(EVENTS, [uniform(1), uniform(2)])
        self.assertEqual(document["schema_version"], "repeat-stability.v1")
        self.assertEqual(document["context_id"], CONTEXT)
        self.assertEqual(document["repeats"], 2)
        self.assertEqual(document["counts"]["stable"], 3)
        self.assertEqual(
            document["gate"], {"fail_on": ["effect-varies"], "status": "pass"}
        )
        self.assertEqual(repeat.exit_code(document), 0)
        self.assertNotIn("elapsed", json.dumps(document))

    def test_result_is_independent_of_the_order_of_later_repeats(self):
        varied = [
            record(2, [obs("deny", "deny", "deny: a"), obs(), obs()]),
            record(3, [obs(), obs(reason="allow: t"), obs()]),
            record(4, [obs(), obs(), obs("deny", "stop", "stop: z")]),
        ]
        reference = None
        for order in itertools.permutations(varied):
            # Same repeats, re-numbered: only the reference (repeat 1) is fixed.
            records = [uniform(1)] + [
                repeat.RepeatRecord(index, r.context_id, r.failures, r.observations)
                for index, r in enumerate(order, start=2)
            ]
            document = repeat.build_document(EVENTS, records)
            body = {key: document[key] for key in ("counts", "rows", "gate")}
            reference = reference or body
            self.assertEqual(body, reference)
        self.assertEqual(
            [row["class"] for row in reference["rows"]],
            ["effect-varies", "reason-varies", "effect-varies"],
        )

    def test_records_are_ordered_by_index_not_by_arrival(self):
        records = [uniform(2), uniform(1)]
        forward = repeat.stability_bytes(repeat.build_document(EVENTS, records))
        backward = repeat.stability_bytes(repeat.build_document(EVENTS, records[::-1]))
        self.assertEqual(forward, backward)

    def test_identical_observations_give_identical_bytes(self):
        one = repeat.stability_bytes(
            repeat.build_document(EVENTS, [uniform(1), uniform(2)])
        )
        two = repeat.stability_bytes(
            repeat.build_document(EVENTS, [uniform(1), uniform(2)])
        )
        self.assertEqual(one, two)
        self.assertTrue(one.endswith(b"\n"))

    def test_other_context_is_not_merged_and_is_a_source_failure(self):
        differing = record(
            2, [obs("deny", "deny", "deny: a")] * 3, context=OTHER_CONTEXT
        )
        document = repeat.build_document(EVENTS, [uniform(1), differing])
        self.assertEqual(document["comparable_repeats"], 1)
        # The differing recording would have made every event effect-varies.
        self.assertEqual(document["counts"]["stable"], 3)
        self.assertEqual(document["counts"]["effect-varies"], 0)
        run = document["repeat_runs"][1]
        self.assertFalse(run["context_matches"])
        self.assertEqual(run["source_failures"], {"repeat-context-changed": 1})
        self.assertEqual(document["gate"]["status"], "error")
        self.assertEqual(repeat.exit_code(document), 3)

    def test_unreadable_repeat_is_excluded_and_a_failure(self):
        gone = repeat.RepeatRecord(2, CONTEXT, {"repeat-unreadable": 1}, None)
        document = repeat.build_document(EVENTS, [uniform(1), gone])
        self.assertEqual(document["comparable_repeats"], 1)
        self.assertEqual(repeat.exit_code(document), 3)

    def test_exit_precedence(self):
        varying = [
            uniform(1),
            record(2, [obs("deny", "deny", "deny: a"), obs(), obs()]),
        ]
        document = repeat.build_document(EVENTS, varying)
        self.assertEqual(repeat.exit_code(document), 1)
        # A class outside --fail-on does not fail the gate.
        relaxed = repeat.build_document(EVENTS, varying, fail_on=["reason-varies"])
        self.assertEqual(repeat.exit_code(relaxed), 0)
        # A source failure outranks a selected class.
        failing = varying + [record(3, [obs()] * 3, failures={"hook-crash": 1})]
        self.assertEqual(repeat.exit_code(repeat.build_document(EVENTS, failing)), 3)

    def test_reason_variation_only_fails_when_selected(self):
        records = [uniform(1), record(2, [obs(reason="allow: t")] * 3)]
        self.assertEqual(repeat.exit_code(repeat.build_document(EVENTS, records)), 0)
        selected = repeat.build_document(EVENTS, records, fail_on=["reason-varies"])
        self.assertEqual(repeat.exit_code(selected), 1)

    def test_markdown_escapes_event_ids_and_never_shows_reasons(self):
        events = ["<b>@bot|x</b>"]
        records = [
            repeat.RepeatRecord(1, CONTEXT, {}, {events[0]: obs(reason="SECRET-1")}),
            repeat.RepeatRecord(
                2, CONTEXT, {}, {events[0]: obs("deny", "deny", "SECRET-2")}
            ),
        ]
        document = repeat.build_document(events, records)
        text = repeat.render_markdown(document)
        self.assertNotIn("<b>", text)
        self.assertNotIn("SECRET", text)
        self.assertIn("effect-varies", text)
        self.assertNotIn("SECRET", repeat.stability_bytes(document).decode())

    def test_measurements_are_separate_and_marked_observational(self):
        timed = repeat.RepeatRecord(1, CONTEXT, {}, {}, {"schema_version": "m"})
        document = json.loads(repeat.measurements_bytes([timed]))
        self.assertFalse(document["deterministic"])
        self.assertEqual(document["repeats"][0]["repeat"], 1)


if __name__ == "__main__":
    unittest.main()
