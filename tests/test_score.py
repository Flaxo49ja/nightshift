"""The scorecard's job is to be uncomfortable: a blind spot is not a miss, and
an invented alert is not a win."""
import unittest

from nightshift.score import SLACK, score, render


def truth(technique, started="2026-10-30T20:04:00.000000Z",
          ended="2026-10-30T20:05:00.000000Z", status="ran", **extra):
    return {"technique": technique, "status": status, "started": started,
            "ended": ended, "title": technique, **extra}


def detection(technique, ident="d1", ts_first="2026-10-30T20:04:11.000000Z",
              ts_last=None, rule="r1", severity="high", key="k"):
    return {"id": ident, "technique": technique, "rule_id": rule, "severity": severity,
            "key": key, "ts_first": ts_first, "ts_last": ts_last or ts_first,
            "count": 1, "event_ids": ["e1"], "title": "t"}


class RecallTest(unittest.TestCase):
    def test_caught_technique_scores_perfectly(self):
        card = score([truth("T1110.001")], [detection("T1110.001")])
        self.assertEqual(card.recall, 1.0)
        self.assertEqual(card.precision, 1.0)
        self.assertEqual(card.true_positives, 1)

    def test_missed_technique_lowers_recall(self):
        card = score([truth("T1110.001"), truth("T1136.001", started="2026-10-30T21:00:00.000000Z",
                                                ended="2026-10-30T21:01:00.000000Z")],
                     [detection("T1110.001")])
        self.assertEqual(card.recall, 0.5)
        self.assertEqual(card.false_negatives, 1)

    def test_a_detection_of_the_wrong_technique_is_not_a_catch(self):
        card = score([truth("T1110.001")], [detection("T1136.001")])
        self.assertEqual(card.true_positives, 0)
        self.assertEqual(len(card.false_positives), 1)

    def test_detections_outside_the_window_do_not_match(self):
        # Scores as neither a catch nor a false alarm: the experiment did not
        # observe it, so it is not evidence either way. It is still reported.
        late = "2026-10-30T20:30:00.000000Z"
        card = score([truth("T1110.001")], [detection("T1110.001", ts_first=late)])
        self.assertEqual(card.true_positives, 0)
        self.assertEqual(card.false_positives, [])
        self.assertEqual([d["id"] for d in card.out_of_session], ["d1"])
        self.assertIn("out of scope, not counted", render(card))

    def test_probe_before_the_session_is_out_of_session(self):
        early = "2026-10-30T19:40:00.000000Z"
        card = score([truth("T1053.006", observed=1)],
                     [detection("T1053.006", ident="probe", ts_first=early),
                      detection("T1053.006", ident="injected")])
        self.assertEqual(card.true_positives, 1)
        self.assertEqual(card.precision, 1.0)
        self.assertEqual([d["id"] for d in card.out_of_session], ["probe"])

    def test_second_detection_of_a_caught_technique_is_a_repeat(self):
        card = score([truth("T1053.006", observed=2)],
                     [detection("T1053.006", ident="unit-started"),
                      detection("T1053.006", ident="unit-finished",
                                ts_first="2026-10-30T20:04:12.000000Z")])
        self.assertEqual(card.true_positives, 1)
        self.assertEqual(card.precision, 1.0)
        self.assertEqual([d["id"] for d in card.repeats], ["unit-finished"])
        self.assertIn("same technique already caught in the window", render(card))

    def test_detection_of_a_simulation_that_recorded_nothing_is_a_false_positive(self):
        # Nothing was observed, so nothing was caught. Calling this a repeat
        # would excuse an alert on the strength of a catch that never happened.
        card = score([truth("T1548.003", observed=0)], [detection("T1548.003")])
        self.assertEqual(card.repeats, [])
        self.assertEqual([d["id"] for d in card.false_positives], ["d1"])
        self.assertNotIn("already caught", render(card))

    def test_detection_of_a_blind_spot_is_a_false_positive(self):
        # No telemetry exists for T1105, so a detection of it is not a catch
        # and cannot be a duplicate of one.
        card = score([truth("T1105")], [detection("T1105")])
        self.assertEqual(card.repeats, [])
        self.assertEqual([d["id"] for d in card.false_positives], ["d1"])

    def test_journald_lag_within_slack_still_matches(self):
        # SLACK is 5 minutes; journald can be well behind wall clock
        card = score([truth("T1110.001")],
                     [detection("T1110.001", ts_first="2026-10-30T20:09:00.000000Z")])
        self.assertEqual(card.true_positives, 1)
        self.assertGreaterEqual(SLACK.total_seconds(), 60)

    def test_one_detection_cannot_cover_two_injections(self):
        card = score([truth("T1110.001"),
                      truth("T1110.001", started="2026-10-30T20:04:30.000000Z",
                            ended="2026-10-30T20:05:30.000000Z")],
                     [detection("T1110.001")])
        self.assertEqual(card.true_positives, 1)
        self.assertEqual(card.false_negatives, 1)


class HonestyTest(unittest.TestCase):
    def test_no_telemetry_technique_is_unscored_not_missed(self):
        card = score([truth("T1105")], [])
        self.assertEqual(card.rows[0].unscored, 1)
        self.assertEqual(card.rows[0].injected, 0)
        self.assertIsNone(card.recall, "nothing scored means no recall to report")
        self.assertIn("not a miss", render(card))

    def test_unobserved_simulation_is_not_a_detection_failure(self):
        card = score([truth("T1548.003", observed=0)], [])
        row = card.rows[0]
        self.assertEqual(row.unobserved, 1)
        self.assertEqual(row.injected, 0)
        self.assertIn("recorded nothing", render(card))

    def test_observed_simulation_is_scored_normally(self):
        card = score([truth("T1053.006", observed=2)], [detection("T1053.006")])
        self.assertEqual(card.rows[0].injected, 1)
        self.assertEqual(card.rows[0].detected, 1)

    def test_skipped_simulations_are_listed_not_hidden(self):
        card = score([truth("T1548.003", status="skipped", reason="sudo unavailable")], [])
        self.assertEqual(card.rows, [])
        self.assertIn("skipped T1548.003: sudo unavailable", render(card))

    def test_no_ground_truth_says_so(self):
        self.assertIn("run `nightshift inject` first", render(score([], [])))


class PrecisionTest(unittest.TestCase):
    def test_extra_detections_are_false_positives(self):
        card = score([truth("T1110.001")],
                     [detection("T1110.001", ident="hit"),
                      detection("T1136.001", ident="noise", rule="account-change")])
        self.assertEqual(card.precision, 0.5)
        self.assertEqual([d["id"] for d in card.false_positives], ["noise"])
        self.assertIn("false positives:", render(card))

    def test_no_detections_reports_undefined_precision_not_zero(self):
        # "0% precision, 0 false positives" contradicted itself: nothing was
        # predicted, so precision was never measured.
        card = score([truth("T1110.001")], [])
        self.assertIsNone(card.precision)
        self.assertIn("precision  n/a", render(card))

    def test_false_positive_list_is_truncated_but_counted(self):
        noise = [detection("T1105", ident=f"n{i}", rule="x") for i in range(12)]
        text = render(score([truth("T1110.001")], noise))
        self.assertIn("and 2 more", text)


if __name__ == "__main__":
    unittest.main()
