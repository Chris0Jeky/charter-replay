"""Counts stay inspectable; intervals do not certify supplied labels."""

from copy import deepcopy
import importlib
import json
import unittest


def result(label, effect, *, generated=False):
    row = {
        "event": {"source": "generated-variant" if generated else "synthetic"},
        "baseline": {"effect": "deny"},
        "candidate": {"effect": effect},
    }
    if label is not None:
        row["case"] = {"case_class": label, "provenance": "synthetic"}
    return row


class LabelMetricTests(unittest.TestCase):
    def metrics(self):
        return importlib.import_module("charter_replay.metrics")

    def test_disagreements_include_explicit_coverage_and_both_denominators(self):
        rows = [
            result(label, effect)
            for label in ("dangerous", "benign")
            for effect in ("allow", "deny", "indeterminate")
        ] + [result("opaque", "allow"), result(None, "deny")]
        scores = self.metrics().score_labels({"results": rows})
        candidate = scores["strata"]["all"]["candidate"]
        self.assertEqual(candidate["excluded"], {"opaque": 1, "unlabelled": 1})
        for label in ("dangerous", "benign"):
            metrics = candidate[label]
            self.assertEqual(metrics["total"], 3)
            self.assertEqual(
                metrics["effects"], {"allow": 1, "deny": 1, "indeterminate": 1}
            )
            self.assertEqual(metrics["disagreement_count"], 1)
            self.assertEqual(metrics["disagreement_rate"], 0.333333)
            self.assertEqual(metrics["determinate_count"], 2)
            self.assertEqual(metrics["determinate_disagreement_rate"], 0.5)
            self.assertEqual(metrics["indeterminate_rate"], 0.333333)
            self.assertEqual(metrics["decision_coverage"], 0.666667)
        baseline = scores["strata"]["all"]["baseline"]
        self.assertEqual(baseline["dangerous"]["disagreement_rate"], 0.0)
        self.assertEqual(baseline["benign"]["disagreement_rate"], 1.0)
        self.assertEqual(scores["label_basis"], "supplied-v1-labels")
        self.assertIn("not independent", scores["limitations"][0])

    def test_empty_denominators_are_null_not_perfect_scores(self):
        scores = self.metrics().score_labels({"results": []})
        for stratum in scores["strata"].values():
            self.assertEqual(stratum["events"], 0)
            for side in ("baseline", "candidate"):
                for label in ("dangerous", "benign"):
                    row = stratum[side][label]
                    self.assertEqual(row["total"], 0)
                    for key in (
                        "disagreement_rate",
                        "determinate_disagreement_rate",
                        "indeterminate_rate",
                        "decision_coverage",
                        "wilson_95",
                    ):
                        self.assertIsNone(row[key])

    def test_generated_cases_get_separate_counts_and_no_pooled_interval(self):
        rows = [result("dangerous", "allow")] + [
            result("dangerous", "deny", generated=True) for _ in range(3)
        ]
        strata = self.metrics().score_labels({"results": rows})["strata"]
        self.assertEqual(strata["all"]["candidate"]["dangerous"]["total"], 4)
        self.assertEqual(strata["seed"]["candidate"]["dangerous"]["total"], 1)
        self.assertEqual(strata["generated-variant"]["events"], 3)
        for name in ("all", "generated-variant"):
            row = strata[name]["candidate"]["dangerous"]
            self.assertIsNone(row["wilson_95"])
            self.assertEqual(row["interval_status"], "suppressed-generated-dependence")
        self.assertIsNotNone(strata["seed"]["candidate"]["dangerous"]["wilson_95"])

    def test_case_provenance_also_marks_derived_observations(self):
        row = result("dangerous", "allow")
        row["case"]["provenance"] = "generated-variant"
        strata = self.metrics().score_labels({"results": [row]})["strata"]
        self.assertEqual(strata["seed"]["events"], 0)
        self.assertEqual(strata["generated-variant"]["events"], 1)

    def test_scoring_does_not_mutate_inputs_or_depend_on_result_order(self):
        rows = [result("dangerous", "allow"), result("benign", "indeterminate")]
        original = deepcopy(rows)
        before = self.metrics().score_labels({"results": rows})
        after = self.metrics().score_labels({"results": list(reversed(rows))})
        self.assertEqual(rows, original)
        self.assertEqual(
            json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True)
        )

    def test_unknown_effect_is_not_silently_scored_as_safe(self):
        with self.assertRaises(ValueError):
            self.metrics().score_labels({"results": [result("dangerous", "unknown")]})

    def test_wilson_interval_small_samples_and_extremes(self):
        wilson = self.metrics().wilson_95
        self.assertEqual(wilson(0, 0), None)
        self.assertEqual(wilson(5, 10), [0.236593, 0.763407])
        self.assertEqual(wilson(0, 10), [0.0, 0.277533])
        self.assertEqual(wilson(10, 10), [0.722467, 1.0])
        for errors, total in ((-1, 10), (11, 10), (1, 0), (True, 2)):
            with self.assertRaises(ValueError):
                wilson(errors, total)


class LatencyMetricTests(unittest.TestCase):
    def metrics(self):
        return importlib.import_module("charter_replay.metrics")

    def test_nearest_rank_counts_timeout_and_excludes_unstarted_events(self):
        observations = [
            {"elapsed_ms": value, "outcome": "timeout" if value == 20 else "allow"}
            for value in range(1, 21)
        ] + [{"elapsed_ms": 999, "outcome": "start-failed"}]
        measured = self.metrics().latency_summary(
            observations, jobs=4, timeout_seconds=10
        )
        self.assertEqual(measured["event_count"], 21)
        self.assertEqual(measured["sample_count"], 20)
        self.assertEqual(measured["timeout_count"], 1)
        self.assertEqual(measured["start_failed_count"], 1)
        self.assertEqual(measured["elapsed_ms"], {"p50": 10, "p95": 19, "max": 20})
        self.assertEqual(measured["jobs"], 4)
        self.assertEqual(measured["timeout_seconds"], 10)
        self.assertFalse(measured["deterministic"])
        self.assertEqual(measured["percentile_method"], "nearest-rank")

    def test_no_started_samples_have_null_percentiles(self):
        for observations in ([], [{"outcome": "start-failed", "elapsed_ms": 0}]):
            measured = self.metrics().latency_summary(
                observations, jobs=1, timeout_seconds=1
            )
            self.assertEqual(measured["sample_count"], 0)
            self.assertEqual(
                measured["elapsed_ms"], {"p50": None, "p95": None, "max": None}
            )

    def test_invalid_observations_are_rejected(self):
        for elapsed in (-1, True, float("nan"), "5"):
            with self.assertRaises(ValueError):
                self.metrics().latency_summary(
                    [{"elapsed_ms": elapsed, "outcome": "allow"}],
                    jobs=1,
                    timeout_seconds=1,
                )


if __name__ == "__main__":
    unittest.main()
