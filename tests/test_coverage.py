"""The scorecard leans on this table to stay honest about missed detections."""
import re
import unittest

from nightshift.coverage import FIXTURE_ONLY, is_real_coverage, visibility


class VisibilityTest(unittest.TestCase):
    def test_journald_observes_auth_and_timer_techniques(self):
        for technique in ("T1110.001", "T1548.003", "T1053.006"):
            with self.subTest(technique=technique):
                self.assertEqual(visibility(technique, "journald"), "observed")

    def test_curl_and_nmap_have_no_journald_telemetry(self):
        for technique in ("T1105", "T1046"):
            with self.subTest(technique=technique):
                self.assertEqual(visibility(technique, "journald"), "no-telemetry")

    def test_unmapped_technique_is_unknown_not_observed(self):
        self.assertEqual(visibility("T9999", "journald"), "unknown")

    def test_another_provider_does_not_inherit_journald_visibility(self):
        self.assertEqual(visibility("T1110.001", "auditd"), "unknown")


class FixtureOnlyTest(unittest.TestCase):
    def test_cron_is_fixture_only_and_never_real_coverage(self):
        self.assertIn("cron_run", FIXTURE_ONLY)
        self.assertFalse(is_real_coverage("cron_run"))

    def test_observed_event_types_count_as_real_coverage(self):
        self.assertTrue(is_real_coverage("auth_failure"))
        self.assertTrue(is_real_coverage("timer_run"))


class AttackIdFormatTest(unittest.TestCase):
    def test_every_mapped_technique_uses_a_valid_attack_id(self):
        from nightshift.coverage import COVERAGE

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for technique in COVERAGE:
            with self.subTest(technique=technique):
                self.assertRegex(technique, pattern)


if __name__ == "__main__":
    unittest.main()
