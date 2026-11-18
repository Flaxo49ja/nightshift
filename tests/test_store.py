"""Duplicate events would double-count in every detection and metric."""
import json
import tempfile
import unittest
from pathlib import Path

from nightshift.schema import Event
from nightshift.store import EventStore


def event(ident, message="x"):
    return Event(
        id=ident, ts="2026-10-30T20:04:11.000000Z", host="soc-lab",
        provider="journald", source="sudo", event_type="sudo_command",
        priority=6, unit=None, user="alice", pid=1, process="sudo",
        cmdline=None, src_ip=None, src_port=None, message=message,
    )


class EventStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "var" / "events.jsonl"
        self.store = EventStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_has_no_ids(self):
        self.assertEqual(self.store.existing_ids(), set())

    def test_append_creates_parents_and_writes_jsonl(self):
        written = self.store.append([event("a"), event("b")])
        self.assertEqual(written, 2)
        lines = self.path.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["id"], "a")

    def test_existing_ids_reads_back_what_was_written(self):
        self.store.append([event("a"), event("b")])
        self.assertEqual(self.store.existing_ids(), {"a", "b"})

    def test_append_new_skips_known_ids(self):
        self.store.append([event("a")])
        written = self.store.append_new([event("a"), event("b")])
        self.assertEqual(written, 1)
        self.assertEqual([json.loads(l)["id"] for l in self.path.read_text().splitlines()], ["a", "b"])

    def test_torn_line_is_skipped_rather_than_stopping_collection(self):
        # A crash mid-write leaves half a line; the next run must still collect.
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(event("a").to_dict()) + "\n" + '{"id": "tor')
        self.assertEqual(self.store.existing_ids(), {"a"})
        self.assertEqual(self.store.append_new([event("b")]), 1)

    def test_append_new_writes_nothing_when_all_known(self):
        self.store.append([event("a")])
        before = self.path.read_text()
        self.assertEqual(self.store.append_new([event("a")]), 0)
        self.assertEqual(self.path.read_text(), before)


if __name__ == "__main__":
    unittest.main()
