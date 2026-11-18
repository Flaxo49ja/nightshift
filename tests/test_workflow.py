"""The whole shift, end to end, on the reviewed fixtures: scan -> shift -> score.

This is the test that would have caught "each command works but the pipeline
does not": it uses the real CLI entry point, the real rules and the real store.
"""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from nightshift.cli import main

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
FIXTURES = ROOT / "fixtures" / "expected"


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        events = []
        for name in ("auth_failed_su_burst.expected.jsonl", "sudo_commands.expected.jsonl"):
            for line in (FIXTURES / name).read_text().splitlines():
                if line.strip():
                    events.append(json.loads(line))
        (self.state / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def detections(self):
        path = self.state / "detections.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def test_scan_applies_the_shipped_rules_to_real_events(self):
        code, out = run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        self.assertEqual(code, 0)
        self.assertIn("new detection", out)
        rules_fired = {d["rule_id"] for d in self.detections()}
        self.assertIn("auth-brute-force", rules_fired)
        self.assertIn("sudo-enumeration", rules_fired)

    def test_scan_is_idempotent(self):
        run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        first = (self.state / "detections.jsonl").read_text()
        code, out = run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        self.assertEqual(code, 0)
        self.assertEqual((self.state / "detections.jsonl").read_text(), first)
        self.assertIn("0 new detection", out)

    def test_shift_lists_then_confirms_a_detection(self):
        run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        code, out = run(["shift", "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        self.assertIn("auth-brute-force", out)

        target = next(d for d in self.detections() if d["rule_id"] == "auth-brute-force")
        code, out = run(["shift", "--state-dir", str(self.state),
                         "--confirm", target["id"][:8], "--note", "expected burst"])
        self.assertEqual(code, 0)
        self.assertIn("confirmed", out)

        queue = json.loads((self.state / "queue.json").read_text())
        self.assertEqual(queue[target["id"]]["status"], "confirmed")
        self.assertEqual(queue[target["id"]]["note"], "expected burst")

    def test_ambiguous_prefix_is_a_usage_error_not_a_guess(self):
        run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        code, _ = run(["shift", "--state-dir", str(self.state), "--confirm", "a"])
        self.assertEqual(code, 2)

    def test_score_uses_injected_truth_and_reports_the_gap(self):
        run(["scan", "--state-dir", str(self.state), "--rules", str(RULES)])
        target = next(d for d in self.detections() if d["rule_id"] == "auth-brute-force")
        truth = [
            {"technique": "T1110.001", "status": "ran", "started": "2026-10-30T20:04:00.000000Z",
             "ended": "2026-10-30T20:04:20.000000Z", "observed": 5},
            {"technique": "T1105", "status": "ran", "started": "2026-10-30T20:10:00.000000Z",
             "ended": "2026-10-30T20:10:05.000000Z", "visible_expected": False},
        ]
        (self.state / "truth.jsonl").write_text("\n".join(json.dumps(t) for t in truth) + "\n")
        code, out = run(["score", "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        self.assertIn("recall", out)
        self.assertIn("100%", out)
        self.assertIn("not a miss", out)
        self.assertTrue(target["id"])

    def test_score_without_truth_fails_loudly(self):
        code, _ = run(["score", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)

    def test_coverage_report_runs_and_names_the_blind_spots(self):
        code, out = run(["coverage", "--rules", str(RULES)])
        self.assertEqual(code, 0)
        self.assertIn("blind spot", out)

    def test_bad_rules_directory_is_a_rule_error(self):
        broken = self.state / "rules"
        broken.mkdir()
        (broken / "bad.json").write_text('{"id": "x", "title": "t", "severity": "high",'
                                         ' "when": {"nope": 1}}')
        code, _ = run(["scan", "--state-dir", str(self.state), "--rules", str(broken)])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
