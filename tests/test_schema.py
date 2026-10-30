"""The event record is the contract every later slice depends on.

If a field name or the timestamp format drifts, rules and the scorecard
break silently — so these pin the shape rather than the values.
"""
import unittest

from nightshift.schema import EVENT_TYPES, Event, event_id, rfc3339_utc

FIELDS = [
    "id", "ts", "host", "provider", "source", "event_type", "priority",
    "unit", "user", "pid", "process", "cmdline", "src_ip", "src_port", "message",
]


class EventIdTest(unittest.TestCase):
    def test_same_cursor_gives_the_same_id(self):
        self.assertEqual(event_id("journald", "s=abc"), event_id("journald", "s=abc"))

    def test_different_cursor_or_provider_gives_a_different_id(self):
        self.assertNotEqual(event_id("journald", "s=abc"), event_id("journald", "s=abd"))
        self.assertNotEqual(event_id("journald", "s=abc"), event_id("auditd", "s=abc"))

    def test_id_is_a_short_hex_string(self):
        ident = event_id("journald", "s=abc")
        self.assertEqual(len(ident), 16)
        int(ident, 16)  # raises if it is not hex


class TimestampTest(unittest.TestCase):
    def test_epoch_microseconds_render_as_rfc3339_utc(self):
        # 2026-10-30T20:04:11.500000Z
        self.assertEqual(rfc3339_utc(1_793_390_651_500_000), "2026-10-30T20:04:11.500000Z")

    def test_output_is_always_utc_and_microsecond_precision(self):
        rendered = rfc3339_utc(0)
        self.assertEqual(rendered, "1970-01-01T00:00:00.000000Z")
        self.assertFalse(rendered.endswith("+00:00"))


class EventShapeTest(unittest.TestCase):
    def test_to_dict_uses_the_documented_field_order(self):
        event = Event(
            id="abc", ts="2026-10-30T20:04:11.000000Z", host="soc-lab",
            provider="journald", source="sudo", event_type="sudo_command",
            priority=6, unit=None, user="alice", pid=42, process="sudo",
            cmdline=None, src_ip=None, src_port=None, message="COMMAND=list",
        )
        self.assertEqual(list(event.to_dict()), FIELDS)

    def test_vocabulary_is_closed_and_known(self):
        self.assertIn("auth_failure", EVENT_TYPES)
        self.assertIn("timer_run", EVENT_TYPES)
        self.assertIn("unknown", EVENT_TYPES)
        self.assertIn("cron_run", EVENT_TYPES)
        self.assertIn("account_change", EVENT_TYPES)


if __name__ == "__main__":
    unittest.main()
