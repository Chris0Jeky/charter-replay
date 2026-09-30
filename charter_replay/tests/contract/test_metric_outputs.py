"""CLI scoring is stable while timing remains an observational sidecar."""

import json
import os
import unittest
from unittest import mock

from charter_replay import hooks
from charter_replay.tests.contract import test_cli as fixtures
from charter_replay.tests.contract.test_hook_failures import arguments, command, invoke


class MetricOutputTests(unittest.TestCase):
    def test_label_scores_and_latency_are_written_to_separate_artifacts(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "output"
            argv = arguments(corpus, output, command("pass"), command("pass"))
            self.assertEqual(invoke(argv), 0)
            summary = json.loads((output / "summary.json").read_bytes())
            scored = summary["label_agreement"]["strata"]["all"]["candidate"]
            self.assertEqual(scored["dangerous"]["disagreement_rate"], 1.0)
            self.assertEqual(scored["benign"]["disagreement_rate"], 0.0)
            self.assertIn(
                "Supplied-label agreement", (output / "summary.md").read_text("utf-8")
            )
            self.assertNotIn("elapsed_ms", json.dumps(summary))
            for side in ("baseline", "candidate"):
                measurement = json.loads(
                    (output / side / "measurements.json").read_bytes()
                )
                self.assertEqual(measurement["sample_count"], 2)
                self.assertFalse(measurement["deterministic"])

    def test_changed_latency_does_not_change_summary_or_run_identity(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            stable = []
            variable = []
            for elapsed in (10, 500):
                output = directory / f"output-{elapsed}"
                reply = hooks.HookOutcome("allow", "fixture", 0, elapsed)
                with mock.patch.object(hooks, "run_hook", return_value=reply):
                    with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
                        argv = arguments(
                            corpus, output, command("pass"), command("pass")
                        )
                        self.assertEqual(invoke(argv), 0)
                stable.append(
                    (
                        (output / "summary.json").read_bytes(),
                        (output / "report" / "report.json").read_bytes(),
                    )
                )
                variable.append(
                    (output / "candidate" / "measurements.json").read_bytes()
                )
            self.assertEqual(stable[0], stable[1])
            self.assertNotEqual(variable[0], variable[1])

    def test_measurement_output_failure_returns_three_instead_of_traceback(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "recording"
            (output / "measurements.json").mkdir(parents=True)
            code = invoke(
                [
                    "record",
                    "--hook",
                    command("pass"),
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
