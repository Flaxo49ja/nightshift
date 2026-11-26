"""Baseline answers a different question than the scorecard: how often does a
rule fire when nobody is injecting anything?"""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from nightshift.baseline import measure, render
from nightshift.cli import main
from nightshift.providers.journald import JournaldProvider
from nightshift.rules import load_rules
from nightshift.store import read_jsonl

ROOT = Path(__file__).resolve().parent.parent


def fixture_events(name="timer_variants.jsonl"):
    provider = JournaldProvider()
    rows = [json.loads(line) for line in
            (ROOT / "fixtures" / name).read_text().splitlines()]
    return [event.to_dict() for event in (provider.normalize(row) for row in rows) if event]


class MeasureTest(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / "rules")
        self.events = fixture_events()

    def test_it_counts_each_rules_alerts_over_the_window(self):
        result = measure(self.events, self.rules, hours=24)
        by_rule = {row["rule_id"]: row for row in result["rows"]}
        self.assertEqual(set(by_rule), {"transient-unit-started", "timer-unit-introduced"})
        self.assertEqual(by_rule["transient-unit-started"]["alerts"], 1)
        self.assertAlmostEqual(by_rule["timer-unit-introduced"]["per_hour"], 1 / 24)
        self.assertEqual(result["total"], 2)

    def test_the_window_ends_at_the_newest_event_not_at_wall_clock(self):
        # The fixture is old; a wall-clock window would find nothing. A tiny
        # window from the newest event drops the earliest of the two detections.
        result = measure(self.events, self.rules, hours=0.001)
        self.assertEqual([row["rule_id"] for row in result["rows"]],
                         ["timer-unit-introduced"])
        self.assertEqual(result["events"], 4)   # events at 3, 4, 5 and 6 s

    def test_empty_store_is_reported_as_empty_not_as_zero_alerts(self):
        text = render(measure([], self.rules))
        self.assertIn("no events collected", text)

    def test_the_report_says_it_used_no_injections_and_needs_a_quiet_day(self):
        text = render(measure(self.events, self.rules, hours=24))
        self.assertIn("no injections were run", text)
        self.assertIn("quiet day", text)
        self.assertIn("timer-unit-introduced", text)


class CliTest(unittest.TestCase):
    def test_baseline_reads_the_store_and_never_touches_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            rows = [event for event in fixture_events()]
            (state / "events.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in rows))
            # A truth file next to it would be a temptation; baseline must not
            # read or need it.
            (state / "truth.jsonl").write_text('{"technique": "T1053.006"}\n')
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["baseline", "--state-dir", str(state), "--hours", "24",
                             "--rules", str(ROOT / "rules")])
            self.assertEqual(code, 0)
            self.assertIn("timer-unit-introduced", out.getvalue())
            self.assertEqual(len(read_jsonl(state / "truth.jsonl")), 1)

    def test_no_events_is_an_error_not_an_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["baseline", "--state-dir", tmp,
                             "--rules", str(ROOT / "rules")])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
