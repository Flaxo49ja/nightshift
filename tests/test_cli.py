"""The collector is where telemetry can silently disappear, so these tests
drive it through a fake provider: no journald, no system changes.
"""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from nightshift.cli import collect, parse_since, shift
from nightshift.providers.base import CursorInvalid
from nightshift.providers.journald import JournaldProvider


def raw(cursor, identifier, message, micros=1_793_390_651_000_000):
    return {
        "__CURSOR": cursor, "__REALTIME_TIMESTAMP": str(micros),
        "_HOSTNAME": "soc-lab", "SYSLOG_IDENTIFIER": identifier,
        "MESSAGE": message, "PRIORITY": "6", "_PID": "1", "_COMM": identifier,
    }


class FakeProvider:
    name = "journald"

    def __init__(self, entries, fail_once_with=None):
        self.entries = entries
        self.fail_once_with = fail_once_with
        self.calls = []

    def fetch(self, after_cursor=None, since=None):
        self.calls.append((after_cursor, since))
        if self.fail_once_with and len(self.calls) == 1:
            raise CursorInvalid(self.fail_once_with)
        return list(self.entries)

    source_of = staticmethod(JournaldProvider.source_of)

    def normalize(self, entry):
        return JournaldProvider().normalize(entry)


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.entries = [
            raw("s=1", "sudo", "    alice : TTY=pts/1 ; USER=root ; COMMAND=list"),
            raw("s=2", "ABDownloadManager", "downloading episode"),
            raw("s=3", "su", "FAILED su for root by nstest-ns7f3a2c"),
        ]

    def tearDown(self):
        self.tmp.cleanup()

    def run_collect(self, provider, all_sources=False, since=None):
        buf = io.StringIO()
        args = SimpleNamespace(state_dir=self.state, all=all_sources, since=since)
        with redirect_stdout(buf):
            code = collect(args, provider=provider)
        return code, buf.getvalue()

    def stored(self):
        path = self.state / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def test_the_local_display_manager_and_pam_helper_are_allowlisted(self):
        from nightshift.providers.journald import DEFAULT_SOURCES

        for identifier in ("ly", "ly-dm", "unix_chkpwd"):
            with self.subTest(identifier=identifier):
                self.assertIn(identifier, DEFAULT_SOURCES)

    def test_allowlist_drops_noisy_identifiers_and_reports_the_count(self):
        code, out = self.run_collect(FakeProvider(self.entries))
        self.assertEqual(code, 0)
        self.assertEqual([e["source"] for e in self.stored()], ["sudo", "su"])
        self.assertIn("ABDownloadManager 1", out)

    def test_all_collects_every_identifier(self):
        self.run_collect(FakeProvider(self.entries), all_sources=True)
        self.assertEqual(len(self.stored()), 3)

    def test_first_run_uses_a_seven_day_window(self):
        provider = FakeProvider(self.entries)
        self.run_collect(provider)
        _, since = provider.calls[0]
        self.assertIsNotNone(since)
        self.assertAlmostEqual(
            (datetime.now(timezone.utc) - since).total_seconds(),
            timedelta(days=7).total_seconds(), delta=60,
        )

    def test_cursor_is_saved_and_reused_on_the_next_run(self):
        provider = FakeProvider(self.entries)
        self.run_collect(provider)
        self.assertIn("cursor", json.loads((self.state / "cursor.json").read_text()))
        self.run_collect(provider)
        cursor, _ = provider.calls[-1]
        self.assertEqual(cursor, "s=3")

    def test_a_second_run_over_the_same_entries_writes_nothing_new(self):
        provider = FakeProvider(self.entries)
        self.run_collect(provider)
        code, out = self.run_collect(provider)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.stored()), 2)
        self.assertIn("0 new events", out)

    def test_invalid_cursor_falls_back_to_the_saved_time_and_reports_a_gap(self):
        self.run_collect(FakeProvider(self.entries))
        provider = FakeProvider(self.entries, fail_once_with="Failed to seek to cursor")
        code, out = self.run_collect(provider)
        self.assertEqual(code, 0)
        self.assertIn("telemetry gap", out)
        # the retry ignores the dead cursor and starts from the saved timestamp
        self.assertIsNone(provider.calls[-1][0])
        self.assertIsNotNone(provider.calls[-1][1])

    def test_empty_journal_still_exits_cleanly(self):
        code, out = self.run_collect(FakeProvider([]))
        self.assertEqual(code, 0)
        self.assertIn("0 new events", out)


class ShiftNoteTest(unittest.TestCase):
    def test_note_without_a_decision_is_refused_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(state_dir=Path(tmp), all=False,
                                   confirm=None, dismiss=None, note="looks benign")
            err = io.StringIO()
            with redirect_stderr(err):
                code = shift(args)
        self.assertEqual(code, 2)
        self.assertIn("--note needs", err.getvalue())


class ParseSinceTest(unittest.TestCase):
    def test_relative_days_hours_and_minutes(self):
        now = datetime.now(timezone.utc)
        self.assertAlmostEqual((now - parse_since("24h")).total_seconds(), 86_400, delta=5)
        self.assertAlmostEqual((now - parse_since("3d")).total_seconds(), 259_200, delta=5)
        self.assertAlmostEqual((now - parse_since("45m")).total_seconds(), 2_700, delta=5)

    def test_iso_timestamp_is_accepted_with_z(self):
        parsed = parse_since("2026-10-01T00:00:00Z")
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_garbage_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            parse_since("yesterday-ish")

    def test_default_is_seven_days(self):
        now = datetime.now(timezone.utc)
        self.assertAlmostEqual((now - parse_since(None)).total_seconds(), 604_800, delta=5)


if __name__ == "__main__":
    unittest.main()
