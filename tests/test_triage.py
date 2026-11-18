"""The queue is the difference between a detection list and a shift: state has
to survive the process, and an ambiguous id must never be guessed."""
import json
import tempfile
import unittest
from pathlib import Path

from nightshift.queue import TriageQueue, resolve


def detection(ident, ts="2026-10-30T20:04:11.000000Z", rule="auth-brute-force"):
    return {
        "id": ident, "rule_id": rule, "title": "Repeated authentication failures",
        "severity": "high", "technique": "T1110.001", "count": 5, "key": "198.51.100.7",
        "host": "soc-lab", "ts_first": ts, "ts_last": ts, "event_ids": ["e1"],
    }


class QueueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "queue.json"
        self.queue = TriageQueue(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unseen_detection_is_new(self):
        self.assertEqual(self.queue.status_of("abc")["status"], "new")

    def test_status_survives_a_new_queue_instance(self):
        self.queue.set_status("abc", "dismissed", "known scanner")
        reopened = TriageQueue(self.path)
        state = reopened.status_of("abc")
        self.assertEqual(state["status"], "dismissed")
        self.assertEqual(state["note"], "known scanner")
        self.assertIsNotNone(state["at"])

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            self.queue.set_status("abc", "probably-fine")

    def test_corrupt_queue_does_not_crash_triage(self):
        self.path.write_text("{not json")
        self.assertEqual(self.queue.status_of("abc")["status"], "new")

    def test_entries_join_state_and_sort_newest_first(self):
        self.queue.set_status("old", "confirmed")
        rows = self.queue.entries([
            detection("old", ts="2026-10-30T20:00:00.000000Z"),
            detection("new", ts="2026-10-30T21:00:00.000000Z"),
        ])
        self.assertEqual([r["id"] for r in rows], ["new", "old"])
        self.assertEqual(rows[1]["status"], "confirmed")
        self.assertEqual(rows[0]["status"], "new")

    def test_counts_include_every_status(self):
        self.queue.set_status("a", "confirmed")
        self.queue.set_status("b", "dismissed")
        totals = self.queue.counts([detection("a"), detection("b"), detection("c")])
        self.assertEqual(totals, {"new": 1, "confirmed": 1, "dismissed": 1})


class ResolveTest(unittest.TestCase):
    rows = [detection("a1b2c3d4e5f6a7b8"), detection("a1ff000011112222")]

    def test_exact_id_resolves(self):
        self.assertEqual(resolve("a1b2c3d4e5f6a7b8", self.rows)["id"], "a1b2c3d4e5f6a7b8")

    def test_unique_prefix_resolves(self):
        self.assertEqual(resolve("a1b2", self.rows)["id"], "a1b2c3d4e5f6a7b8")

    def test_ambiguous_prefix_is_an_error_not_a_coin_flip(self):
        with self.assertRaises(KeyError) as ctx:
            resolve("a1", self.rows)
        self.assertIn("matches 2", str(ctx.exception))

    def test_unknown_prefix_is_an_error(self):
        with self.assertRaises(KeyError):
            resolve("zzzz", self.rows)


class QueueFileTest(unittest.TestCase):
    def test_file_is_written_atomically_without_a_tmp_leftover(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "queue.json"
            TriageQueue(path).set_status("abc", "confirmed")
            self.assertTrue(path.exists())
            self.assertFalse(path.with_suffix(".tmp").exists())
            self.assertEqual(json.loads(path.read_text())["abc"]["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
