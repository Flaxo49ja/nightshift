"""Coverage reporting exists to say "no". These tests keep it from flattering
the tool."""
import unittest

from nightshift.report import blind_spots, matrix, render


class RenderTest(unittest.TestCase):
    def test_journald_blind_spots_are_named(self):
        text = render("journald")
        self.assertIn("blind spot", text)
        self.assertIn("T1105", text)
        self.assertIn("T1046", text)

    def test_auditd_closes_the_execve_gap(self):
        grid = matrix()
        self.assertEqual(grid["T1046"]["auditd"], "observed")
        self.assertEqual(grid["T1046"]["journald"], "no-telemetry")
        self.assertIn("no mapped blind spots", render("auditd"))

    def test_fixture_only_is_disclosed(self):
        self.assertIn("fixture-only", render("journald"))

    def test_rule_column_marks_uncovered_visible_techniques(self):
        text = render("journald", {"T1110.001"})
        self.assertIn("visible but no rule yet", text)

    def test_summary_counts_visible_techniques(self):
        self.assertIn("visible to journald", render("journald"))


class MatrixTest(unittest.TestCase):
    def test_matrix_covers_both_providers(self):
        grid = matrix()
        self.assertEqual(set(grid["T1105"]), {"journald", "auditd"})
        self.assertEqual(grid["T1105"]["auditd"], "observed")

    def test_blind_spots_are_sorted(self):
        self.assertEqual(blind_spots("journald"), ["T1046", "T1105", "T1543.002"])


if __name__ == "__main__":
    unittest.main()
