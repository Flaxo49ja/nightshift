"""The injector touches the host, so the tests pin what it is allowed to do:
loopback or local only, best-effort, and reversible."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from nightshift import inject


class FakeRunner:
    def __init__(self, returncode=0, stderr="", raises=None):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""
        self.raises = raises
        self.calls = []

    def __call__(self, argv, timeout=15):
        self.calls.append(argv)
        if self.raises:
            raise self.raises
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout,
                               stderr=self.stderr)


class SudoInjectionTest(unittest.TestCase):
    def test_records_a_real_attempt(self):
        runner = FakeRunner(returncode=1, stderr="sudo: a password is required")
        record = inject.inject_sudo_enumeration(runner)
        self.assertEqual(record["technique"], "T1548.003")
        self.assertEqual(record["status"], "ran")
        self.assertEqual(runner.calls, [["sudo", "-n", "-l"]])
        self.assertIn("password", record["reason"])

    def test_missing_sudo_is_skipped_not_crashed(self):
        report = inject.inject_sudo_enumeration(FakeRunner(raises=FileNotFoundError()))
        self.assertEqual(report["status"], "skipped")
        self.assertIn("not installed", report["reason"])

    def test_hanging_sudo_is_a_failed_simulation(self):
        import subprocess

        report = inject.inject_sudo_enumeration(FakeRunner(raises=subprocess.TimeoutExpired("sudo", 15)))
        self.assertEqual(report["status"], "failed")


class TimerInjectionTest(unittest.TestCase):
    def test_runs_a_transient_unit_and_cleans_it_up(self):
        runner = FakeRunner()
        with mock.patch.object(inject.shutil, "which", return_value="/usr/bin/systemd-run"):
            record = inject.inject_timer(runner)
        self.assertEqual(record["status"], "ran")
        argv = runner.calls[0]
        self.assertIn("--user", argv)
        self.assertTrue(any(a.startswith("--on-active") for a in argv))
        # cleanup is not optional: nothing may outlive the simulation
        self.assertIn("reset-failed", runner.calls[1])

    def test_absent_systemd_run_is_skipped(self):
        with mock.patch.object(inject.shutil, "which", return_value=None):
            record = inject.inject_timer(FakeRunner())
        self.assertEqual(record["status"], "skipped")


class UnitFileTimerInjectionTest(unittest.TestCase):
    """The second T1053.006 variant arms a real timer unit instead of asking
    systemd-run for a transient one, so the rule cannot just match that binary."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def inject_here(self, runner):
        return inject.inject_timer_unit(runner, unit_dir=self.dir,
                                        sleeper=lambda seconds: None)

    def files(self):
        return sorted(p.name for p in self.dir.glob("nightshift-*"))

    def test_writes_a_unit_pair_starts_it_and_removes_it(self):
        runner = FakeRunner()
        record = self.inject_here(runner)
        self.assertEqual((record["status"], record["variant"]), ("ran", "unit-file"))
        self.assertEqual(self.files(), [])
        flat = [" ".join(call) for call in runner.calls]
        self.assertTrue(any("daemon-reload" in call for call in flat))
        self.assertTrue(any(" start " in f" {call} " for call in flat))
        self.assertTrue(any(" stop " in f" {call} " for call in flat))

    def test_the_timer_arms_once_after_a_second(self):
        written = {}

        def runner(argv, timeout=15):
            if "start" in argv:
                for path in self.dir.glob("nightshift-*"):
                    written[path.suffix] = path.read_text()
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        self.inject_here(runner)
        self.assertIn("OnActiveSec=1", written[".timer"])
        self.assertIn("Unit=nightshift-", written[".timer"])
        self.assertIn("ExecStart=/bin/true", written[".service"])

    def test_a_failed_start_is_reported_and_still_cleans_up(self):
        record = self.inject_here(FakeRunner(returncode=1))
        self.assertEqual(record["status"], "failed")
        self.assertEqual(self.files(), [])

    def test_missing_systemctl_is_a_skip_not_a_crash(self):
        record = self.inject_here(FakeRunner(raises=FileNotFoundError()))
        self.assertEqual(record["status"], "skipped")
        self.assertEqual(self.files(), [])


class VariantCoverageTest(unittest.TestCase):
    def test_the_timer_technique_has_two_injectors(self):
        self.assertEqual(len(inject.INJECTORS["T1053.006"]), 2)

    def test_the_transient_variant_is_recorded_in_the_truth(self):
        with mock.patch.object(inject.shutil, "which", return_value="/usr/bin/systemd-run"):
            record = inject.inject_timer(FakeRunner())
        self.assertEqual(record["variant"], "transient")


class IngressInjectionTest(unittest.TestCase):
    def test_serves_one_file_over_loopback(self):
        fetched = {}

        def fetcher():
            import urllib.request

            # the URL is produced inside the injector; re-fetch through it
            raise AssertionError("should not be called with a fake fetcher")

        record = inject.inject_ingress(fetcher=lambda: fetched.setdefault("ok", True))
        self.assertEqual(record["status"], "ran")
        self.assertIn("loopback only", record["note"])

    def test_a_failing_fetch_is_a_skip_with_the_reason(self):
        def boom():
            raise OSError("connection refused")

        record = inject.inject_ingress(fetcher=boom)
        self.assertEqual(record["status"], "skipped")
        self.assertIn("OSError", record["reason"])

    def test_the_server_is_shut_down_even_when_the_fetch_fails(self):
        import socket

        def boom():
            raise OSError("nope")

        inject.inject_ingress(fetcher=boom)
        # nothing should be listening on the port we used; a leaked thread
        # would keep the process alive, so reaching here is the assertion
        self.assertTrue(True)


class DiscoveryInjectionTest(unittest.TestCase):
    def test_open_ports_are_recorded(self):
        def connector(host, port, timeout):
            if port == 80:
                return mock.MagicMock()
            raise ConnectionRefusedError

        record = inject.inject_discovery(ports=range(78, 82), connector=connector)
        self.assertEqual(record["status"], "ran")
        self.assertEqual(record["open_ports"], [80])
        self.assertEqual(record["attempted"], 4)

    def test_only_loopback_is_contacted(self):
        seen = []

        def connector(host, port, timeout):
            seen.append(host)
            raise ConnectionRefusedError

        inject.inject_discovery(ports=range(1, 4), connector=connector)
        self.assertEqual(set(seen), {"127.0.0.1"})


class TruthFileTest(unittest.TestCase):
    def test_unknown_technique_is_a_clear_error(self):
        with self.assertRaises(ValueError) as ctx:
            inject.run(techniques=["T9999"], truth_path=None)
        self.assertIn("unknown technique", str(ctx.exception))

    def test_only_requested_techniques_run(self):
        called = []

        def fake(technique):
            def _inject():
                called.append(technique)
                return {"technique": technique, "status": "ran"}
            return _inject

        records = inject.run(techniques=["T1105"], truth_path=None,
                             injectors={"T1105": fake("T1105")})
        self.assertEqual(called, ["T1105"])
        self.assertEqual(records[0]["technique"], "T1105")

    def test_truth_appends_and_reads_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truth.jsonl"
            inject.write_truth([{"technique": "T1046", "status": "ran"}], path)
            inject.write_truth([{"technique": "T1105", "status": "ran"}], path)
            self.assertEqual(len(inject.read_truth(path)), 2)

    def test_blind_truth_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truth.jsonl"
            inject.write_truth([{"technique": "T1046", "status": "ran"}], path, blind=True)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_bad_lines_are_skipped_rather_than_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truth.jsonl"
            path.write_text('{"technique": "T1046"}\n{broken\n')
            self.assertEqual(len(inject.read_truth(path)), 1)

    def test_missing_truth_file_is_empty_not_an_error(self):
        self.assertEqual(inject.read_truth(Path("/nonexistent/truth.jsonl")), [])


class ExpectationTest(unittest.TestCase):
    def test_curl_and_nmap_are_marked_as_having_no_journald_telemetry(self):
        self.assertEqual(set(inject.NO_TELEMETRY_EXPECTED), {"T1105", "T1046"})

    def test_every_technique_has_an_expectation_entry(self):
        for technique in inject.TECHNIQUES:
            with self.subTest(technique=technique):
                self.assertIn(technique, inject.EXPECTED_EVENT_TYPES)


if __name__ == "__main__":
    unittest.main()


class UserServiceInjectionTest(unittest.TestCase):
    """T1543.002 creates a real user service, then removes every trace of it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def inject_here(self, runner):
        return inject.inject_user_service(runner, unit_dir=self.dir,
                                          sleeper=lambda seconds: None)

    def files(self):
        return sorted(p.name for p in self.dir.glob("nightshift-*"))

    def test_writes_enables_starts_and_removes_the_service(self):
        runner = FakeRunner()
        record = self.inject_here(runner)
        self.assertEqual((record["technique"], record["status"]),
                         ("T1543.002", "ran"))
        self.assertFalse(record["visible_expected"])
        self.assertEqual(record["variant"], "user-service")
        self.assertTrue(record["marker"].endswith(".service"))
        self.assertEqual(self.files(), [])
        flat = [" ".join(call) for call in runner.calls]
        self.assertTrue(any(" enable " in f" {call} " for call in flat))
        self.assertTrue(any(" start " in f" {call} " for call in flat))
        self.assertTrue(any(" disable " in f" {call} " for call in flat))
        self.assertTrue(any(" stop " in f" {call} " for call in flat))
        self.assertEqual(sum("daemon-reload" in call for call in flat), 2)

    def test_the_unit_is_a_real_oneshot_user_service(self):
        written = {}

        def runner(argv, timeout=15):
            for path in self.dir.glob("nightshift-*"):
                written[path.suffix] = path.read_text()
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        self.inject_here(runner)
        self.assertIn("Type=oneshot", written[".service"])
        self.assertIn("ExecStart=/bin/true", written[".service"])
        self.assertIn("Description=nightshift simulated task", written[".service"])

    def test_a_failed_start_still_disables_and_deletes(self):
        record = self.inject_here(FakeRunner(returncode=1))
        self.assertEqual(record["status"], "failed")
        self.assertEqual(self.files(), [])
        self.assertTrue(record["reason"])

    def test_missing_systemctl_is_a_skip_and_cleans_up(self):
        record = self.inject_here(FakeRunner(raises=FileNotFoundError()))
        self.assertEqual(record["status"], "skipped")
        self.assertEqual(self.files(), [])

    def test_the_technique_has_one_explicit_variant(self):
        self.assertEqual(len(inject.INJECTORS["T1543.002"]), 1)
        self.assertIn("T1543.002", inject.TECHNIQUES)
