"""Normalization is the riskiest code in the slice: a silent field mistake
poisons every rule built on top. Each raw fixture is compared whole against a
reviewed golden file, the way PhishGuard pins model output.
"""
import json
import unittest
from pathlib import Path

from nightshift.providers.journald import JournaldProvider, classify

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

GOLDEN_PAIRS = [
    ("auth_failed_su_burst.jsonl", "auth_failed_su_burst.expected.jsonl"),
    ("sudo_commands.jsonl", "sudo_commands.expected.jsonl"),
    ("systemd_units.jsonl", "systemd_units.expected.jsonl"),
    ("cron_and_logind.jsonl", "cron_and_logind.expected.jsonl"),
    ("firewall_blocks.jsonl", "firewall_blocks.expected.jsonl"),
]


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class GoldenNormalizationTest(unittest.TestCase):
    def test_each_fixture_normalizes_to_its_golden_file(self):
        provider = JournaldProvider(runner=lambda **_: [])
        for raw_name, golden_name in GOLDEN_PAIRS:
            with self.subTest(fixture=raw_name):
                raw = read_jsonl(FIXTURES / raw_name)
                expected = read_jsonl(FIXTURES / "expected" / golden_name)
                actual = [provider.normalize(entry).to_dict() for entry in raw]
                self.assertEqual(actual, expected)


class ClassificationTest(unittest.TestCase):
    def test_unknown_identifier_stays_unknown(self):
        self.assertEqual(classify("ABDownloadManager", "downloading", None), "unknown")

    def test_sudo_list_is_a_sudo_command_after_the_failure_check(self):
        message = "    alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=list"
        self.assertEqual(classify("sudo", message, None), "sudo_command")

    def test_sudo_failure_wins_over_the_command_field(self):
        message = "    alice : a password is required ; USER=root ; COMMAND=/usr/bin/id"
        self.assertEqual(classify("sudo", message, None), "auth_failure")

    def test_user_timer_start_is_a_timer_run_not_a_service_start(self):
        self.assertEqual(classify("systemd", "Started ns7f3a2c.timer.", "ns7f3a2c.timer"), "timer_run")

    def test_unit_failure_is_service_failed(self):
        message = "demo.service: Main process exited, code=exited, status=1/FAILURE"
        self.assertEqual(classify("systemd", message, "demo.service"), "service_failed")

    def test_ufw_block_from_the_kernel_is_a_firewall_block(self):
        message = "[UFW BLOCK] IN=wlan0 OUT= MAC= SRC=192.168.0.112 DST=224.0.0.252 PROTO=UDP"
        self.assertEqual(classify("kernel", message, None), "firewall_block")

    def test_rate_limited_block_is_the_same_verdict(self):
        message = "[UFW LIMIT BLOCK] IN=wlan0 OUT= SRC=203.0.113.45 PROTO=TCP"
        self.assertEqual(classify("kernel", message, None), "firewall_block")

    def test_ordinary_kernel_noise_stays_unknown(self):
        self.assertEqual(classify("kernel", "wlan0: associated with ap", None), "unknown")

    def test_ufw_text_from_another_source_is_not_a_firewall_block(self):
        self.assertEqual(classify("systemd", "[UFW BLOCK] not really", None), "unknown")


class FieldExtractionTest(unittest.TestCase):
    def setUp(self):
        self.provider = JournaldProvider(runner=lambda **_: [])

    def entry(self, **overrides):
        base = {
            "__CURSOR": "s=x;i=1", "__REALTIME_TIMESTAMP": "1793390651000000",
            "_HOSTNAME": "soc-lab", "SYSLOG_IDENTIFIER": "sudo",
            "MESSAGE": "    alice : TTY=pts/2 ; USER=root ; COMMAND=list",
            "PRIORITY": "6", "_PID": "42", "_COMM": "sudo",
        }
        base.update(overrides)
        return base

    def test_missing_cursor_or_timestamp_is_dropped_not_guessed(self):
        self.assertIsNone(self.provider.normalize(self.entry(__CURSOR=None)))
        self.assertIsNone(self.provider.normalize(self.entry(__REALTIME_TIMESTAMP="nope")))

    def test_binary_message_is_decoded_instead_of_crashing(self):
        raw = self.entry(MESSAGE=[72, 105])
        self.assertEqual(self.provider.normalize(raw).message, "Hi")

    def test_absent_optional_fields_are_none(self):
        event = self.provider.normalize(self.entry(_PID=None, PRIORITY=None, _HOSTNAME=None))
        self.assertIsNone(event.pid)
        self.assertIsNone(event.priority)
        self.assertEqual(event.host, "unknown")

    def test_ssh_network_fields_are_parsed(self):
        message = "Failed password for invalid user admin from 198.51.100.7 port 51515 ssh2"
        event = self.provider.normalize(self.entry(SYSLOG_IDENTIFIER="sshd", MESSAGE=message))
        self.assertEqual((event.src_ip, event.src_port), ("198.51.100.7", 51515))
        self.assertEqual(event.user, "admin")

    def test_a_sentence_period_is_not_part_of_the_username(self):
        raw = self.entry(SYSLOG_IDENTIFIER="systemd-logind", MESSAGE="New session 42 of user alice.")
        self.assertEqual(self.provider.normalize(raw).user, "alice")

    def test_quoted_logind_username_is_not_dropped(self):
        message = "New session '1' of user 'anayo' with class 'manager' and type 'unspecified'."
        raw = self.entry(SYSLOG_IDENTIFIER="systemd-logind", MESSAGE=message)
        self.assertEqual(self.provider.normalize(raw).user, "anayo")

    def test_manager_lines_take_the_unit_named_in_the_message(self):
        message = "crowdsec-firewall-bouncer.service: Failed with result 'exit-code'."
        raw = self.entry(SYSLOG_IDENTIFIER="systemd", MESSAGE=message,
                         _SYSTEMD_UNIT="init.scope")
        event = self.provider.normalize(raw)
        self.assertEqual(event.unit, "crowdsec-firewall-bouncer.service")
        self.assertEqual(event.event_type, "service_failed")

    def test_transient_unit_name_is_recovered_from_the_prefix(self):
        message = "dbus-:1.1-org.kde.kwalletd6@11.service: Failed with result 'exit-code'."
        raw = self.entry(SYSLOG_IDENTIFIER="systemd", MESSAGE=message,
                         _SYSTEMD_UNIT="init.scope")
        self.assertEqual(self.provider.normalize(raw).unit,
                         "dbus-:1.1-org.kde.kwalletd6@11.service")

    def test_a_real_unit_is_not_overridden_by_the_message(self):
        raw = self.entry(SYSLOG_IDENTIFIER="systemd", MESSAGE="demo.service: failed",
                         _SYSTEMD_UNIT="other.service")
        self.assertEqual(self.provider.normalize(raw).unit, "other.service")

    def test_manager_line_without_a_unit_keeps_its_placeholder(self):
        raw = self.entry(SYSLOG_IDENTIFIER="systemd", MESSAGE="Started Steam.",
                         _SYSTEMD_UNIT="init.scope")
        self.assertEqual(self.provider.normalize(raw).unit, "init.scope")

    def test_firewall_block_peer_is_parsed_from_ufw_fields(self):
        message = ("[UFW BLOCK] IN=wlan0 OUT= MAC= SRC=203.0.113.44 DST=192.168.0.10 "
                   "PROTO=TCP SPT=40221 DPT=22")
        event = self.provider.normalize(self.entry(SYSLOG_IDENTIFIER="kernel", MESSAGE=message))
        self.assertEqual((event.src_ip, event.src_port), ("203.0.113.44", 40221))

    def test_ipv6_peer_survives_intact(self):
        message = "[UFW BLOCK] IN=wlan0 OUT= SRC=fe80:0000:0000:0000:cb2b:404a:6dd0:8f6c PROTO=UDP SPT=5353"
        event = self.provider.normalize(self.entry(SYSLOG_IDENTIFIER="kernel", MESSAGE=message))
        self.assertEqual(event.src_ip, "fe80:0000:0000:0000:cb2b:404a:6dd0:8f6c")
        self.assertEqual(event.src_port, 5353)

    def test_source_falls_back_to_comm(self):
        self.assertEqual(self.provider.source_of({"SYSLOG_IDENTIFIER": "sudo"}), "sudo")
        self.assertEqual(self.provider.source_of({"_COMM": "su"}), "su")
        self.assertEqual(self.provider.source_of({}), "unknown")

    def test_same_entry_always_gets_the_same_id(self):
        first = self.provider.normalize(self.entry())
        second = self.provider.normalize(self.entry())
        self.assertEqual(first.id, second.id)


if __name__ == "__main__":
    unittest.main()
