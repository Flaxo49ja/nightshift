"""Rules are data, so the loader is the only thing standing between a typo and
a detection that silently never fires."""
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nightshift.providers.journald import JournaldProvider
from nightshift.schema import parse_ts
from nightshift.rules import (RuleError, detection_id, evaluate, load_rule,
                              load_rules, matches, parse_duration)


def event(ident, ts, event_type="auth_failure", **fields):
    base = {
        "id": ident, "ts": ts, "host": "soc-lab", "provider": "journald",
        "source": "su", "event_type": event_type, "priority": 4, "unit": None,
        "user": "alice", "pid": 1, "process": "su", "cmdline": None,
        "src_ip": None, "src_port": None, "message": "",
    }
    base.update(fields)
    return base


BASE = {
    "id": "test-rule", "title": "Test", "severity": "high",
    "when": {"event_type": "auth_failure"},
}


def rule(**overrides):
    return load_rule({**BASE, **overrides})


ROOT = Path(__file__).resolve().parent.parent


def normalize_fixture(name):
    provider = JournaldProvider()
    rows = [json.loads(line) for line in (ROOT / "fixtures" / name).read_text().splitlines()
            if line.strip()]
    return [event.to_dict() for event in (provider.normalize(row) for row in rows) if event]


class DetectedAtTest(unittest.TestCase):
    """A detection has two times: when the journal line happened, and when the
    scan saw it. MTTD uses the second."""

    def test_every_detection_records_when_the_scan_ran(self):
        rules = load_rules(ROOT / "rules")
        detections = evaluate(normalize_fixture("timer_variants.jsonl"), rules,
                              detected_at="2026-11-26T09:00:00.000000Z")
        self.assertTrue(detections)
        for item in detections:
            self.assertEqual(item["detected_at"], "2026-11-26T09:00:00.000000Z")

    def test_detected_at_defaults_to_the_moment_of_the_scan(self):
        rules = load_rules(ROOT / "rules")
        detections = evaluate(normalize_fixture("timer_variants.jsonl"), rules)
        self.assertTrue(detections)
        for item in detections:
            self.assertTrue(item["detected_at"].endswith("Z"))
            # never older than the event that produced it
            self.assertGreaterEqual(parse_ts(item["detected_at"]), parse_ts(item["ts_first"]))


class UserServicePersistenceTest(unittest.TestCase):
    """T1543.002 was investigated and deliberately got no rule: `systemctl
    --user enable` writes nothing to the journal, and the start line carries a
    Description ("Starting <description>...") with the unit left as the manager
    scope. A rule for it would fire on every user service on the box."""

    def setUp(self):
        self.events = normalize_fixture("user_service_persistence.jsonl")
        self.rules = load_rules(ROOT / "rules")

    def test_no_shipped_rule_claims_a_plain_user_service_start(self):
        self.assertEqual(evaluate(self.events, self.rules), [])

    def test_the_persistence_start_is_indistinguishable_from_a_benign_one(self):
        starts = [e for e in self.events if e["event_type"] == "service_start"]
        self.assertEqual(len(starts), 2)
        self.assertEqual({e["unit"] for e in starts}, {"user@1000.service"})
        # Both are Description lines, so neither carries the unit name that a
        # timer line carries; the only difference is text the attacker chooses.
        self.assertTrue(all(e["message"].startswith("Starting ") for e in starts))


class VariantAttributionTest(unittest.TestCase):
    """Each rule must own one variant. A rule that also fires on the other
    variant would let "both variants caught" be true while one rule is dead."""

    def setUp(self):
        self.rules = load_rules(ROOT / "rules")
        self.events = normalize_fixture("timer_variants.jsonl")

    def test_the_two_rules_split_the_two_variants(self):
        fired = {d["rule_id"] for d in evaluate(self.events, self.rules)}
        self.assertEqual(fired, {"transient-unit-started", "timer-unit-introduced"})

    def test_the_on_disk_timer_is_only_the_timer_rule(self):
        timer_line = next(e for e in self.events
                          if e["event_type"] == "timer_run" and (e["unit"] or "").endswith(".timer"))
        self.assertEqual({r.id for r in self.rules if matches(r.when, timer_line)},
                         {"timer-unit-introduced"})

    def test_the_on_disk_service_line_is_not_transient_evidence(self):
        service_line = next(e for e in self.events
                            if e["event_type"] == "service_start"
                            and e["message"].startswith("Starting nightshift"))
        self.assertEqual({r.id for r in self.rules if matches(r.when, service_line)}, set())


class RuleHashTest(unittest.TestCase):
    """A detection without the rule text that produced it cannot be reviewed
    a week later, when the rule has changed."""

    def test_a_loaded_rule_carries_the_hash_of_its_file(self):
        rules = {r.id: r for r in load_rules(ROOT / "rules")}
        path = ROOT / "rules" / "timer-unit-introduced.json"
        expected = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        self.assertEqual(rules["timer-unit-introduced"].sha, expected)

    def test_two_rules_with_the_same_id_never_share_a_hash(self):
        rules = {r.id: r for r in load_rules(ROOT / "rules")}
        shas = [r.sha for r in rules.values()]
        self.assertEqual(len(set(shas)), len(shas))

    def test_a_detection_names_the_rule_version_that_fired(self):
        rules = load_rules(ROOT / "rules")
        events = normalize_fixture("timer_variants.jsonl")
        detection = next(d for d in evaluate(events, rules)
                         if d["rule_id"] == "timer-unit-introduced")
        rule = next(r for r in rules if r.id == "timer-unit-introduced")
        self.assertEqual(detection["rule_sha"], rule.sha)
        self.assertEqual(len(rule.sha), 12)


class TimerVariantRuleTest(unittest.TestCase):
    """T1053.006 shows up in two shapes. Both must fire, and a timer that only
    fires must not, or the rule is counting scheduler noise."""

    def setUp(self):
        self.events = normalize_fixture("timer_variants.jsonl")
        self.rules = load_rules(ROOT / "rules")

    def technique_hits(self, events):
        return [d for d in evaluate(events, self.rules) if d["technique"] == "T1053.006"]

    def test_the_transient_variant_is_caught(self):
        transient = [e for e in self.events if "[systemd-run]" in e["message"]]
        self.assertEqual(len(self.technique_hits(transient)), 1)

    def test_the_unit_file_variant_is_caught(self):
        timer_started = [e for e in self.events
                         if e["event_type"] == "timer_run" and (e["unit"] or "").endswith(".timer")]
        self.assertEqual(len(timer_started), 1)
        self.assertEqual(len(self.technique_hits(timer_started)), 1)

    def test_the_whole_fixture_gives_one_detection_per_variant(self):
        # Two variants, two detections. If a rule also matched the other
        # variant's service line this would be three and the counts would lie.
        self.assertEqual(len(self.technique_hits(self.events)), 2)

    def test_a_timer_that_fires_is_not_a_timer_being_introduced(self):
        # "Auto-organize ~/Downloads" is a real user timer on this machine.
        # Its service starting is the timer working, not new persistence.
        benign = [e for e in self.events if "Auto-organize" in e["message"]]
        self.assertTrue(benign)
        self.assertEqual(self.technique_hits(benign), [])

    def test_no_timer_rule_keys_on_the_injector_binary(self):
        timer_rules = [r for r in self.rules if r.technique == "T1053.006"]
        self.assertTrue(timer_rules)
        for rule in timer_rules:
            with self.subTest(rule=rule.id):
                self.assertNotIn("systemd-run", json.dumps(rule.when).lower())


class DurationTest(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_duration("30s"), 30)
        self.assertEqual(parse_duration("10m"), 600)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("1d"), 86400)

    def test_garbage_and_zero_are_rejected(self):
        for bad in ("10", "ten minutes", "0m", "-5m", "m"):
            with self.subTest(bad=bad):
                with self.assertRaises(RuleError):
                    parse_duration(bad)


class LoadingTest(unittest.TestCase):
    def test_minimal_rule_loads_with_safe_defaults(self):
        loaded = rule()
        self.assertEqual(loaded.count_gte, 1)
        self.assertIsNone(loaded.within)
        self.assertFalse(loaded.is_burst)

    def test_unknown_match_field_is_rejected_not_ignored(self):
        with self.assertRaises(RuleError) as ctx:
            rule(when={"event_typo": "auth_failure"})
        self.assertIn("unknown match field", str(ctx.exception))

    def test_unknown_rule_key_is_rejected(self):
        with self.assertRaises(RuleError):
            rule(severty="high")

    def test_bad_severity_is_rejected(self):
        with self.assertRaises(RuleError):
            rule(severity="urgent")

    def test_burst_needs_within_and_group_by(self):
        with self.assertRaises(RuleError) as ctx:
            rule(count_gte=3, group_by="user")
        self.assertIn("within", str(ctx.exception))
        with self.assertRaises(RuleError) as ctx:
            rule(count_gte=3, within="5m")
        self.assertIn("group_by", str(ctx.exception))

    def test_within_without_count_is_a_mistake(self):
        with self.assertRaises(RuleError):
            rule(within="5m")

    def test_group_by_must_be_an_event_field(self):
        with self.assertRaises(RuleError):
            rule(count_gte=2, within="5m", group_by="not_a_field")

    def test_boolean_value_is_rejected_not_silently_never_matching(self):
        # bool is a subclass of int: without an explicit check this loads and
        # then compares an event field against True forever.
        with self.assertRaises(RuleError):
            rule(when={"user": True})

    def test_title_must_be_a_non_empty_string(self):
        with self.assertRaises(RuleError):
            rule(title=123)

    def test_false_positives_must_be_a_list_of_strings(self):
        # A bare string would become a tuple of characters.
        with self.assertRaises(RuleError):
            rule(false_positives="mistyped")

    def test_malformed_technique_is_rejected(self):
        with self.assertRaises(RuleError):
            rule(technique="T1110.01")

    def test_duplicate_ids_across_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.json", "b.json"):
                Path(tmp, name).write_text(json.dumps(BASE))
            with self.assertRaises(RuleError) as ctx:
                load_rules(Path(tmp))
            self.assertIn("duplicate rule id", str(ctx.exception))

    def test_invalid_json_names_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.json").write_text("{nope")
            with self.assertRaises(RuleError) as ctx:
                load_rules(Path(tmp))
            self.assertIn("broken.json", str(ctx.exception))

    def test_shipped_rules_all_load(self):
        rules_dir = Path(__file__).resolve().parents[1] / "rules"
        rules = load_rules(rules_dir)
        self.assertGreaterEqual(len(rules), 5)
        self.assertTrue(all(r.technique for r in rules), "every shipped rule is mapped to ATT&CK")


class MatchingTest(unittest.TestCase):
    def test_scalar_equality(self):
        self.assertTrue(matches({"event_type": "auth_failure"}, event("a", "t")))
        self.assertFalse(matches({"event_type": "session_open"}, event("a", "t")))

    def test_list_membership(self):
        when = {"event_type": ["auth_failure", "auth_success"]}
        self.assertTrue(matches(when, event("a", "t")))
        self.assertFalse(matches(when, event("a", "t", event_type="cron_run")))

    def test_message_contains_is_case_insensitive(self):
        ev = event("a", "t", message="alice : COMMAND=list")
        self.assertTrue(matches({"message_contains": "command=list"}, ev))

    def test_unit_contains_targets_the_unit_field(self):
        ev = event("a", "t", unit="cleanup.timer", message="nothing here")
        self.assertTrue(matches({"unit_contains": ".timer"}, ev))
        self.assertFalse(matches({"unit_contains": ".timer"}, event("a", "t")))

    def test_null_field_matches_null_expectation(self):
        self.assertTrue(matches({"user": None}, event("a", "t", user=None)))


class EvaluateTest(unittest.TestCase):
    def test_single_rule_fires_per_event(self):
        events = [event("a", "2026-10-30T20:00:00.000000Z"),
                  event("b", "2026-10-30T20:00:01.000000Z")]
        detections = evaluate(events, [rule()])
        self.assertEqual(len(detections), 2)
        self.assertEqual(detections[0]["rule_id"], "test-rule")
        self.assertEqual(detections[0]["count"], 1)

    def test_burst_fires_once_per_window_not_once_per_event(self):
        burst = rule(count_gte=3, within="1m", group_by="src_ip")
        events = [event(f"e{i}", f"2026-10-30T20:00:{i:02d}.000000Z")
                  for i in range(10)]
        detections = evaluate(events, [burst])
        self.assertEqual(len(detections), 1, "a 10-event burst is one alert")
        self.assertEqual(detections[0]["count"], 3)

    def test_burst_fires_again_after_the_window(self):
        burst = rule(count_gte=2, within="1m", group_by="src_ip")
        events = [event("a", "2026-10-30T20:00:00.000000Z"),
                  event("b", "2026-10-30T20:00:10.000000Z"),
                  event("c", "2026-10-30T20:05:00.000000Z"),
                  event("d", "2026-10-30T20:05:05.000000Z")]
        self.assertEqual(len(evaluate(events, [burst])), 2)

    def test_events_outside_the_window_do_not_count(self):
        burst = rule(count_gte=2, within="1m", group_by="src_ip")
        events = [event("a", "2026-10-30T20:00:00.000000Z"),
                  event("b", "2026-10-30T20:09:00.000000Z")]
        self.assertEqual(evaluate(events, [burst]), [])

    def test_groups_are_counted_separately(self):
        burst = rule(count_gte=2, within="5m", group_by="src_ip")
        events = [event("a", "2026-10-30T20:00:00.000000Z", src_ip="198.51.100.7"),
                  event("b", "2026-10-30T20:00:05.000000Z", src_ip="203.0.113.9")]
        self.assertEqual(evaluate(events, [burst]), [])

    def test_output_is_time_ordered_even_when_input_is_not(self):
        events = [event("b", "2026-10-30T20:00:09.000000Z"),
                  event("a", "2026-10-30T20:00:01.000000Z")]
        detections = evaluate(events, [rule()])
        self.assertEqual([d["ts_first"] for d in detections],
                         ["2026-10-30T20:00:01.000000Z", "2026-10-30T20:00:09.000000Z"])

    def test_detection_id_is_stable_and_depends_on_the_first_event(self):
        self.assertEqual(detection_id("r", "e1"), detection_id("r", "e1"))
        self.assertNotEqual(detection_id("r", "e1"), detection_id("r", "e2"))
        self.assertNotEqual(detection_id("r", "e1"), detection_id("s", "e1"))

    def test_detection_carries_the_technique_and_event_ids(self):
        burst = rule(count_gte=2, within="1m", group_by="src_ip",
                     technique="T1110.001")
        events = [event("a", "2026-10-30T20:00:00.000000Z"),
                  event("b", "2026-10-30T20:00:05.000000Z")]
        detection = evaluate(events, [burst])[0]
        self.assertEqual(detection["technique"], "T1110.001")
        self.assertEqual(detection["event_ids"], ["a", "b"])


class FirewallBlockRuleTest(unittest.TestCase):
    """The shipped rule is data, so its threshold is worth pinning."""

    @classmethod
    def setUpClass(cls):
        rules_dir = Path(__file__).resolve().parents[1] / "rules"
        cls.rule = next(r for r in load_rules(rules_dir) if r.id == "firewall-block-burst")

    def blocks(self, count, src="203.0.113.44"):
        start = datetime(2026, 10, 30, 20, 0, tzinfo=timezone.utc)
        return [event(f"b{src}-{i}", (start + timedelta(seconds=5 * i)).isoformat()
                      .replace("+00:00", "Z"),
                      event_type="firewall_block", source="kernel", src_ip=src)
                for i in range(count)]

    def test_a_scan_against_one_address_is_one_alert(self):
        detections = evaluate(self.blocks(40), [self.rule])
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["count"], 40)
        self.assertEqual(detections[0]["technique"], "T1595.002")
        self.assertEqual(detections[0]["key"], "203.0.113.44")

    def test_just_under_the_threshold_stays_quiet(self):
        self.assertEqual(evaluate(self.blocks(39), [self.rule]), [])

    def test_two_quiet_sources_are_not_added_together(self):
        events = self.blocks(20, "198.51.100.7") + self.blocks(20, "203.0.113.9")
        self.assertEqual(evaluate(events, [self.rule]), [])


if __name__ == "__main__":
    unittest.main()
