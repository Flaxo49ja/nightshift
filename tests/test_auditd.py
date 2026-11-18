"""auditd is the provider that makes execve visible. The tests are fixture-only:
no root, no audit daemon, no system state."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from nightshift.providers.auditd import (AuditdProvider, classify, group_records,
                                         normalize, parse_line)
from nightshift.providers.base import CursorInvalid

SYSCALL = ('type=SYSCALL msg=audit(1660000000.123:456): arch=c000003e syscall=59 '
           'success=yes exit=0 a0=55d0 items=2 ppid=1234 pid=5678 auid=1000 uid=1000 '
           'comm="curl" exe="/usr/bin/curl" key="exec"')
EXECVE = ('type=EXECVE msg=audit(1660000000.123:456): argc=2 a0="curl" '
          'a1="http://127.0.0.1:8080/payload"')
USER_CMD = ('type=USER_CMD msg=audit(1660000100.000:457): pid=900 uid=0 auid=1000 '
            'msg=\'cwd="/home/alice" cmd=6C73202D6C terminal=pts/1 res=success\'')
USER_AUTH = ('type=USER_AUTH msg=audit(1660000200.000:458): pid=901 uid=0 '
             'msg=\'op=PAM:authentication acct="alice" exe="/usr/bin/sudo" '
             'hostname=? addr=? terminal=/dev/pts/1 res=failed\'')
CRON = 'type=CRON msg=audit(1660000300.000:459): table=root action=start'


class ParseLineTest(unittest.TestCase):
    def test_header_fields_are_extracted(self):
        record = parse_line(SYSCALL)
        self.assertEqual(record["type"], "SYSCALL")
        self.assertEqual(record["serial"], "456")
        self.assertAlmostEqual(record["seconds"], 1660000000.123)
        self.assertEqual(record["fields"]["syscall"], "59")

    def test_quoted_values_lose_their_quotes(self):
        self.assertEqual(parse_line(SYSCALL)["fields"]["comm"], "curl")

    def test_garbage_lines_are_ignored(self):
        for line in ("", "not audit at all", "type=SYSCALL no header here"):
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))


class GroupTest(unittest.TestCase):
    def test_records_with_the_same_serial_become_one_event(self):
        groups = group_records([SYSCALL, EXECVE, USER_CMD])
        self.assertEqual(len(groups), 2)
        self.assertEqual([r["type"] for r in groups[0]], ["SYSCALL", "EXECVE"])

    def test_order_is_preserved(self):
        groups = group_records([USER_CMD, SYSCALL])
        self.assertEqual(groups[0][0]["type"], "USER_CMD")


class ClassifyTest(unittest.TestCase):
    def test_execve_is_process_execution(self):
        self.assertEqual(classify(group_records([SYSCALL, EXECVE])[0]), "process_exec")

    def test_user_cmd_is_sudo(self):
        self.assertEqual(classify(group_records([USER_CMD])[0]), "sudo_command")

    def test_failed_user_auth_is_auth_failure(self):
        self.assertEqual(classify(group_records([USER_AUTH])[0]), "auth_failure")

    def test_unmapped_record_type_stays_unknown(self):
        self.assertEqual(classify(group_records([CRON])[0]), "unknown")


class NormalizeTest(unittest.TestCase):
    def test_exec_event_carries_the_command_line(self):
        event = normalize(group_records([SYSCALL, EXECVE])[0])
        self.assertEqual(event.provider, "auditd")
        self.assertEqual(event.event_type, "process_exec")
        self.assertEqual(event.cmdline, "curl http://127.0.0.1:8080/payload")
        self.assertEqual(event.pid, 5678)
        self.assertEqual(event.process, "curl")
        self.assertTrue(event.ts.startswith("2022-08-08"))

    def test_hex_encoded_sudo_command_is_decoded(self):
        event = normalize(group_records([USER_CMD])[0])
        self.assertEqual(event.event_type, "sudo_command")
        self.assertEqual(event.cmdline, "ls -l")

    def test_user_comes_from_acct_only_never_from_a_numeric_uid(self):
        event = normalize(group_records([USER_AUTH])[0])
        self.assertEqual(event.user, "alice")
        # uid=0 is recorded, but mapping it to a name would be a guess
        self.assertNotEqual(event.user, "root")

    def test_missing_acct_leaves_user_null(self):
        event = normalize(group_records([SYSCALL, EXECVE])[0])
        self.assertIsNone(event.user)

    def test_event_ids_are_stable_for_the_same_serial(self):
        first = normalize(group_records([SYSCALL, EXECVE])[0])
        second = normalize(group_records([SYSCALL, EXECVE])[0])
        self.assertEqual(first.id, second.id)


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.log"
        self.path.write_text("\n".join([SYSCALL, EXECVE, USER_CMD, USER_AUTH]) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_fetch_returns_groups(self):
        groups = AuditdProvider(self.path).fetch()
        self.assertEqual(len(groups), 3)

    def test_cursor_filters_older_serials(self):
        groups = AuditdProvider(self.path).fetch(after_cursor="456")
        self.assertEqual([g[0]["serial"] for g in groups], ["457", "458"])

    def test_since_filters_by_time(self):
        # serial 456 is 23:06:40Z, 457 is 23:08:20Z, 458 is 23:10:00Z
        since = datetime(2022, 8, 8, 23, 8, 0, tzinfo=timezone.utc)
        groups = AuditdProvider(self.path).fetch(since=since)
        self.assertEqual([g[0]["serial"] for g in groups], ["457", "458"])

    def test_a_cursor_older_than_the_log_is_reported_as_a_gap(self):
        with self.assertRaises(CursorInvalid):
            AuditdProvider(self.path).fetch(after_cursor="100")

    def test_missing_log_is_a_clear_runtime_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            AuditdProvider(Path(self.tmp.name) / "nope.log").fetch()
        self.assertIn("no audit log", str(ctx.exception))

    def test_normalize_and_source_of_are_usable_through_the_provider(self):
        provider = AuditdProvider(self.path)
        groups = provider.fetch()
        self.assertEqual(provider.source_of(groups[0]), "SYSCALL")
        self.assertEqual(provider.normalize(groups[0]).event_type, "process_exec")

    def test_no_allowlist_means_auditd_keeps_every_record(self):
        self.assertIsNone(AuditdProvider(self.path).allowlist)


if __name__ == "__main__":
    unittest.main()
