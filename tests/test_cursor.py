"""A cursor that is wrong silently loses telemetry, so the rules are pinned:
missing -> None, provider mismatch -> None, corrupt -> None, write is atomic.
"""
import json
import tempfile
import unittest
from pathlib import Path

from nightshift.cursor import Cursor, CursorFile


class CursorFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "var" / "cursor.json"
        self.store = CursorFile(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_is_none(self):
        self.assertIsNone(self.store.load("journald"))

    def test_roundtrip(self):
        saved = Cursor(provider="journald", cursor="s=1", saved_at="2026-10-30T20:00:00Z", host="soc-lab")
        self.store.save(saved)
        self.assertEqual(self.store.load("journald"), saved)

    def test_another_providers_cursor_is_not_reused(self):
        self.store.save(Cursor("journald", "s=1", "2026-10-30T20:00:00Z", "soc-lab"))
        self.assertIsNone(self.store.load("auditd"))

    def test_corrupt_file_is_none_not_a_crash(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{not json")
        self.assertIsNone(self.store.load("journald"))

    def test_save_leaves_no_temp_file_behind(self):
        self.store.save(Cursor("journald", "s=1", "2026-10-30T20:00:00Z", "soc-lab"))
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["cursor.json"])

    def test_saved_file_is_readable_json(self):
        self.store.save(Cursor("journald", "s=1", "2026-10-30T20:00:00Z", "soc-lab"))
        self.assertEqual(json.loads(self.path.read_text())["cursor"], "s=1")


if __name__ == "__main__":
    unittest.main()
