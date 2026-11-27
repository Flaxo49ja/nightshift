"""The export is only shareable if the machine it came from cannot be named."""
import getpass
import hashlib
import json
import platform
import re
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from nightshift.scenario import (DOC_HOST, DOC_MAC, DOC_USER, Sanitizer,
                                  allow_benign, export, scenario_id)

ROOT = Path(__file__).resolve().parent.parent


def local_ips() -> set[str]:
    """Addresses this machine actually has, discovered at test time."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True,
                             timeout=5).stdout
        found.update(re.findall(r"inet6? ([0-9a-fA-F.:]+)/", out))
    except (OSError, subprocess.SubprocessError):
        pass
    # Loopback is not an identifier and the scenarios use it on purpose.
    return {ip for ip in found if ip and ip not in {"::1", "127.0.0.1"}}


def real_identifiers() -> set[str]:
    ids = {socket.gethostname(), platform.node(), getpass.getuser(), str(Path.home())}
    ids |= local_ips()
    return {value for value in ids if value and len(value) > 2}


def event(**extra) -> dict:
    base = {
        "id": "e1", "ts": "2026-11-26T05:04:40.947274Z", "host": "soc-lab",
        "provider": "journald", "source": "systemd", "event_type": "service_start",
        "priority": 6, "unit": "user@1000.service", "user": None, "pid": 1,
        "process": "systemd", "cmdline": None, "src_ip": None, "src_port": None,
        "message": "Started [systemd-run] /usr/sbin/true.",
    }
    base.update(extra)
    return base


class SanitizerTest(unittest.TestCase):
    def test_known_identifiers_are_replaced_by_value(self):
        cleaner = Sanitizer(hostname="cachyos-x8664", username="anayo",
                            home="/home/anayo")
        text = cleaner.text("anayo on cachyos-x8664 in /home/anayo connected from 10.1.2.3")
        self.assertNotIn("anayo", text)
        self.assertNotIn("cachyos-x8664", text)
        self.assertIn("analyst", text)
        self.assertIn("ws-01", text)
        self.assertIn("192.0.2.", text)

    def test_each_address_gets_its_own_documentation_address(self):
        cleaner = Sanitizer(hostname="box", username="user", home="/home/user")
        text = cleaner.text("10.0.0.1 then 10.0.0.2 then 10.0.0.1")
        self.assertEqual(text, "192.0.2.1 then 192.0.2.2 then 192.0.2.1")

    def test_a_clock_time_is_not_mistaken_for_an_address(self):
        cleaner = Sanitizer(hostname="box", username="user", home="/home/user")
        self.assertEqual(cleaner.text("at 05:04:11 and 20:04:11"),
                         "at 05:04:11 and 20:04:11")

    def test_an_ipv6_address_is_scrubbed(self):
        cleaner = Sanitizer(hostname="box", username="user", home="/home/user")
        text = cleaner.text("from fe80::1a2b and 2001:db8::5")
        self.assertNotIn("fe80", text)
        self.assertNotIn("2001:db8", text)
        self.assertIn("192.0.2.", text)

    def test_a_mac_gets_a_documentation_mac_not_an_ip(self):
        cleaner = Sanitizer(hostname="box", username="user", home="/home/user")
        text = cleaner.text("aa:bb:cc:dd:ee:ff and 11:22:33:44:55:66 and aa:bb:cc:dd:ee:ff")
        self.assertEqual(text, f"{DOC_MAC}01 and {DOC_MAC}02 and {DOC_MAC}01")
        self.assertNotIn("192.0.2.", text)

    def test_the_ipv6_matcher_does_not_treat_a_mac_as_an_address(self):
        cleaner = Sanitizer(hostname="box", username="user", home="/home/user")
        self.assertEqual(cleaner._scrub_v6(re.match(
            r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w:])",
            "aa:bb:cc:dd:ee:ff")), "aa:bb:cc:dd:ee:ff")


class ExportTest(unittest.TestCase):
    def truth(self):
        return [{"id": "t1", "technique": "T1053.006", "status": "ran",
                 "started": "2026-11-26T05:04:40.881183Z",
                 "ended": "2026-11-26T05:04:40.983996Z", "observed": 1,
                 "variant": "transient", "title": "User timer", "provider": "journald"}]

    def test_document_has_the_documented_shape(self):
        doc = export([event()], self.truth(), lang="en")
        self.assertEqual(set(doc), {"id", "lang", "events", "truth", "side_effect_ids",
                                    "excluded", "teach", "limits"})
        self.assertEqual(doc["lang"], "en")
        self.assertEqual(doc["events"][0]["host"], "soc-lab")
        self.assertTrue(doc["teach"]["prompt"])

    def test_the_id_is_stable_and_content_addressed(self):
        first = export([event()], self.truth())
        second = export([event()], self.truth())
        self.assertEqual(first["id"], second["id"])
        changed = export([event(message="different")], self.truth())
        self.assertNotEqual(first["id"], changed["id"])
        self.assertEqual(first["id"], scenario_id(first["events"], first["truth"]))

    def test_portuguese_and_english_do_not_share_text(self):
        en = export([event()], self.truth(), lang="en")
        pt = export([event()], self.truth(), lang="pt")
        self.assertNotEqual(en["teach"]["prompt"], pt["teach"]["prompt"])
        self.assertEqual(en["id"], pt["id"])      # content is the same scenario
        with self.assertRaises(ValueError):
            export([event()], self.truth(), lang="de")


class NoRealIdentifiersTest(unittest.TestCase):
    """Reads this machine's identity at run time, then proves it is gone."""

    def test_an_export_never_contains_this_machines_identity(self):
        host = socket.gethostname()
        user = getpass.getuser()
        home = str(Path.home())
        ips = sorted(local_ips())[:3]
        message = f"{user}@{host} in {home}" + "".join(f" from {ip}" for ip in ips)
        events = [event(host=host, user=user, message=message,
                        src_ip=ips[0] if ips else "127.0.0.1")]
        doc = export(events, self.truth(), lang="en")
        raw = json.dumps(doc)
        for identifier in real_identifiers():
            self.assertNotIn(identifier, raw,
                             f"real identifier leaked into the scenario: {identifier}")
        self.assertEqual(doc["events"][0]["host"], DOC_HOST)
        self.assertEqual(doc["events"][0]["user"], DOC_USER)

    def test_the_cli_writes_a_sanitized_file(self):
        from nightshift.cli import main

        host = socket.gethostname()
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / "events.jsonl").write_text(
                json.dumps(event(host=host, message=f"on {host}")) + "\n")
            (state / "truth.jsonl").write_text(json.dumps(self.truth()[0]) + "\n")
            out = state / "scenario.json"
            code = main(["export-scenario", "--state-dir", str(state),
                         "--out", str(out), "--lang", "pt"])
            self.assertEqual(code, 0)
            raw = out.read_text()
            self.assertNotIn(host, raw)
            doc = json.loads(raw)
            self.assertEqual(doc["lang"], "pt")
            self.assertEqual(len(doc["events"]), 1)

    def truth(self):
        return [{"id": "t1", "technique": "T1053.006", "status": "ran",
                 "started": "2026-11-26T05:04:40.881183Z",
                 "ended": "2026-11-26T05:04:40.983996Z", "observed": 1,
                 "variant": "transient", "title": "User timer", "provider": "journald"}]


def playable():
    """One transient run and one on-disk timer run, with reload lines."""
    events = [
        event(id="e1", ts="2026-11-26T10:00:00.100000Z",
              message="Started [systemd-run] /usr/sbin/true."),
        event(id="e2", ts="2026-11-26T10:00:00.200000Z", event_type="unknown",
              source="systemd", message="Reload requested from client PID 1 ('systemctl')"),
        event(id="e3", ts="2026-11-26T10:00:02.000000Z",
              message="Started [systemd-run] /usr/sbin/true."),
        event(id="e4", ts="2026-11-26T10:00:05.000000Z", event_type="auth_failure",
              source="su", message="FAILED su for root by analyst"),
        event(id="e5", ts="2026-11-26T10:01:01.000000Z", event_type="timer_run",
              unit="nightshift-bbbb2222.timer",
              message="Started nightshift-bbbb2222.timer."),
        event(id="e6", ts="2026-11-26T10:01:03.500000Z",
              message="Starting nightshift simulated task..."),
        event(id="e7", ts="2026-11-26T10:01:04.000000Z", event_type="unknown",
              source="systemd", message="Reloading finished in 1004 ms."),
    ]
    truth = [
        {"id": "nightshift-sim-aaaa1111.timer", "marker": "nightshift-sim-aaaa1111.timer",
         "technique": "T1053.006", "variant": "transient", "status": "ran",
         "observed": 2, "expected_rules": ["transient-unit-started"],
         "started": "2026-11-26T10:00:00.000000Z",
         "ended": "2026-11-26T10:00:01.000000Z"},
        {"id": "nightshift-bbbb2222.timer", "marker": "nightshift-bbbb2222.timer",
         "technique": "T1053.006", "variant": "unit-file", "status": "ran",
         "observed": 1, "expected_rules": ["timer-unit-introduced"],
         "started": "2026-11-26T10:01:00.000000Z",
         "ended": "2026-11-26T10:01:03.000000Z"},
    ]
    return events, truth


class PlayableScenarioTest(unittest.TestCase):
    """A scenario has to say which line is the attack, which is the injector's
    own noise, and which is unrelated background."""

    def setUp(self):
        self.events, self.truth = playable()
        self.doc = export(self.events, self.truth, lang="en")

    def test_every_event_has_exactly_one_label(self):
        for item in self.doc["events"]:
            self.assertIn(item["label"],
                          {"attack_evidence", "side_effect", "benign"})

    def test_attack_evidence_is_owned_by_exactly_one_record(self):
        owned = {}
        for record in self.doc["truth"]:
            for event_id in record["event_ids"]:
                self.assertNotIn(event_id, owned)
                owned[event_id] = record["id"]
        attack = {item["id"] for item in self.doc["events"]
                  if item["label"] == "attack_evidence"}
        self.assertEqual(attack, set(owned))

    def test_observed_equals_the_evidence_that_record_owns(self):
        for record in self.doc["truth"]:
            self.assertEqual(record["observed"], len(record["event_ids"]))

    def test_reload_lines_are_side_effects_not_attack_evidence(self):
        self.assertEqual(len(self.doc["side_effect_ids"]), 2)
        by_id = {item["id"]: item for item in self.doc["events"]}
        for event_id in self.doc["side_effect_ids"]:
            self.assertEqual(by_id[event_id]["label"], "side_effect")
            self.assertIn("reload", by_id[event_id]["message"].lower())

    def test_injector_names_are_renamed_to_fixed_aliases(self):
        raw = json.dumps(self.doc["events"]) + json.dumps(self.doc["teach"])
        self.assertNotIn("nightshift", raw.lower())
        names = {item["unit"] for item in self.doc["events"] if item["unit"]}
        self.assertEqual(names, {"backup-sync.timer", "user@1000.service"})

    def test_the_alias_mapping_is_stable(self):
        again = export(self.events, self.truth, lang="en")
        self.assertEqual(self.doc["id"], again["id"])
        self.assertEqual([e["unit"] for e in self.doc["events"]],
                         [e["unit"] for e in again["events"]])

    def test_teaching_is_per_technique_and_names_the_rule(self):
        from nightshift.rules import load_rules

        doc = export(self.events, self.truth, rules=load_rules(ROOT / "rules"))
        entries = {entry["technique"]: entry for entry in doc["teach"]["techniques"]}
        timer = entries["T1053.006"]
        self.assertEqual(timer["rule_id"], "transient-unit-started")
        self.assertTrue(timer["why"])
        self.assertTrue(timer["looks_like"])
        self.assertFalse(timer["blind_spot"])
        self.assertTrue(entries["T1543.002"]["blind_spot"])
        self.assertIn("enable", entries["T1543.002"]["why"])
        self.assertIsNone(entries["T1543.002"]["rule_id"])

    def test_noise_is_sanitized_ordered_and_benign(self):
        noise = [event(id="n1", ts="2026-11-26T09:59:00.000000Z",
                       host=socket.gethostname(), src_ip="10.9.8.7",
                       source="sudo", event_type="sudo_command",
                       message=f"analyst on {socket.gethostname()} ran /usr/bin/true from 10.9.8.7")]
        doc = export(self.events, self.truth, noise=noise)
        times = [item["ts"] for item in doc["events"]]
        self.assertEqual(times, sorted(times))
        first = doc["events"][0]
        self.assertEqual(first["id"], "n1")
        self.assertEqual(first["label"], "benign")
        self.assertEqual(first["host"], DOC_HOST)
        self.assertIn("192.0.2.", first["message"])
        self.assertNotIn("10.9.8.7", json.dumps(doc))
        self.assertNotIn(socket.gethostname(), json.dumps(doc))


class AllowlistTest(unittest.TestCase):
    """Background is a closed list, not "whatever the host happened to log"."""

    def test_the_allowed_shapes_are_kept(self):
        kept = [
            event(source="kernel", event_type="firewall_block",
                  message="[UFW BLOCK] IN=wlan0 MAC=aa:bb:cc:dd:ee:ff"),
            event(source="sudo", event_type="sudo_command",
                  message="analyst ran /usr/bin/true"),
            event(event_type="auth_failure", message="Failed password for analyst"),
            event(event_type="timer_run", message="Started backup-sync.timer."),
            event(event_type="service_stop", message="Stopped backup-sync.timer."),
        ]
        for item in kept:
            self.assertTrue(allow_benign(item), item["message"])

    def test_hardware_desktop_and_personal_lines_are_dropped(self):
        dropped = [
            event(source="kernel", event_type="unknown",
                  message="Freezing user space processes"),
            event(source="systemd-logind", event_type="unknown", message="Lid opened."),
            event(message="Started Konsole - Terminal."),
            event(message="Starting Auto-organize ~/Downloads into subfolders..."),
            event(event_type="unknown", message="Reloading finished in 21 ms."),
        ]
        for item in dropped:
            self.assertFalse(allow_benign(item), item["message"])


class OneSessionTest(unittest.TestCase):
    """A store can hold many runs. An export that includes the others is not a
    scenario of this session, it is a dump with an answer key."""

    def test_an_earlier_session_is_excluded_entirely(self):
        earlier = [
            event(id="old-inject", ts="2026-11-26T09:00:00.100000Z",
                  message="Started [systemd-run] /usr/sbin/true."),
            event(id="old-timer", ts="2026-11-26T09:00:01.000000Z",
                  event_type="timer_run", unit="nightshift-old11111.timer",
                  message="Started nightshift-old11111.timer."),
        ]
        events, truth = playable()
        # The second session's truth is what is being exported; the store still
        # holds the first session's events.
        doc = export(earlier + events, truth)
        ids = {item["id"] for item in doc["events"]}
        self.assertNotIn("old-inject", ids)
        self.assertNotIn("old-timer", ids)
        self.assertEqual(doc["excluded"]["outside_session"], 2)
        self.assertTrue({item["id"] for item in doc["events"]}
                        <= {e["id"] for e in events})

    def test_a_leftover_injector_line_inside_the_window_is_dropped_and_counted(self):
        events, truth = playable()
        leftover = event(id="leftover", ts="2026-11-26T09:59:30.000000Z",
                         message="Started [systemd-run] /usr/sbin/true.")
        doc = export(events + [leftover], truth)
        self.assertNotIn("leftover", {item["id"] for item in doc["events"]})
        self.assertEqual(doc["excluded"]["untied_injector"], 1)
        self.assertEqual(doc["excluded"]["outside_session"], 0)

    def test_labels_and_observed_match_only_this_sessions_truth(self):
        events, truth = playable()
        doc = export(events, truth)
        attack = {item["id"] for item in doc["events"]
                  if item["label"] == "attack_evidence"}
        owned = {event_id for record in doc["truth"]
                 for event_id in record["event_ids"]}
        self.assertEqual(attack, owned)
        for record in doc["truth"]:
            self.assertEqual(record["observed"], len(record["event_ids"]))

    def test_without_truth_there_is_no_session_to_export(self):
        events, _ = playable()
        doc = export(events, [])
        self.assertEqual(doc["events"], [])
        self.assertEqual(doc["excluded"]["outside_session"], len(events))


class LevelSizeTest(unittest.TestCase):
    """A level is small enough to work, but never small enough to hide the attack."""

    def required(self):
        events, truth = playable()
        doc = export(events, truth, max_events=100)
        return events, truth, [item for item in doc["events"] if item["label"] != "benign"]

    def test_n_cannot_be_smaller_than_the_attack_set(self):
        events, truth, required = self.required()
        self.assertEqual(len(required), 5)
        with self.assertRaises(ValueError):
            export(events, truth, max_events=len(required) - 1)
        doc = export(events, truth, max_events=len(required))
        self.assertEqual(len(doc["events"]), len(required))
        self.assertEqual({item["label"] for item in doc["events"]}, {"attack_evidence", "side_effect"})

    def test_background_is_filled_nearest_the_attacks_first(self):
        events, truth, required = self.required()
        noise = [
            event(id="far", ts="2026-11-26T10:02:02.000000Z", event_type="auth_failure",
                  source="su", message="FAILED su for root by analyst"),
            event(id="near", ts="2026-11-26T10:01:03.000000Z", event_type="auth_failure",
                  source="su", message="FAILED su for root by analyst"),
        ]
        # e6 sits closest to the second run; the nearby noise line is next.
        doc = export(events, truth, noise=noise, max_events=len(required) + 2)
        benign = [item["id"] for item in doc["events"] if item["label"] == "benign"]
        self.assertEqual(sorted(benign), ["e6", "near"])
        self.assertNotIn("far", {item["id"] for item in doc["events"]})
        times = [item["ts"] for item in doc["events"]]
        self.assertEqual(times, sorted(times))

    def test_the_seed_breaks_distance_ties_reproducibly(self):
        events, truth, required = self.required()
        noise = [event(id=f"tie{index}", ts="2026-11-26T10:00:10.000000Z",
                       event_type="auth_failure", source="su",
                       message="FAILED su for root by analyst")
                 for index in range(6)]
        slots = len(required) + 4       # two in-window lines, then two ties
        first = export(events, truth, noise=noise, max_events=slots, seed=7)
        again = export(events, truth, noise=noise, max_events=slots, seed=7)
        self.assertEqual(first["events"], again["events"])
        chosen = [item["id"] for item in first["events"]
                  if item["label"] == "benign" and item["id"] not in {"e4", "e6"}]
        expected = sorted(noise, key=lambda item: hashlib.sha256(
            f"7:{item['id']}".encode()).hexdigest())[:2]
        self.assertEqual(sorted(chosen), sorted(item["id"] for item in expected))


class ExampleLeakSweepTest(unittest.TestCase):
    """What a reader of the example could learn about the host it came from."""

    MAC_SHAPE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
    EMAIL_SHAPE = re.compile(r"[\w.+-]+@[A-Za-z][\w-]*(?:\.[A-Za-z]{2,})+")
    HOME_PATH = re.compile(r"/home/[^/\"\s]+")
    PCI = re.compile(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")

    def test_examples_stay_inside_documentation_ranges(self):
        paths = sorted((ROOT / "examples").glob("*.json"))
        self.assertTrue(paths, "no example was scanned")
        for path in paths:
            text = path.read_text()
            for mac in self.MAC_SHAPE.findall(text):
                self.assertTrue(mac.lower().startswith(DOC_MAC),
                                f"{path.name} leaks a MAC outside {DOC_MAC}xx: {mac}")
            self.assertEqual(self.EMAIL_SHAPE.findall(text), [], path.name)
            homes = set(self.HOME_PATH.findall(text)) - {"/home/analyst"}
            self.assertEqual(homes, set(), path.name)
            self.assertEqual(self.PCI.findall(text), [], path.name)


class BlindScenarioTest(unittest.TestCase):
    def test_blind_drops_the_answer_key_and_attack_labels(self):
        events, truth = playable()
        doc = export(events, truth, blind=True)
        self.assertEqual(doc["truth"], [])
        self.assertEqual(doc["side_effect_ids"], [])
        self.assertTrue(doc["events"])
        self.assertEqual({item["label"] for item in doc["events"]}, {"benign"})

    def test_blind_keeps_the_teaching_block(self):
        events, truth = playable()
        doc = export(events, truth, blind=True)
        techniques = {entry["technique"] for entry in doc["teach"]["techniques"]}
        self.assertIn("T1053.006", techniques)
        self.assertIn("T1543.002", techniques)

    def test_the_cli_blind_flag_writes_no_truth(self):
        from nightshift.cli import main

        events, truth = playable()
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / "events.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in events))
            (state / "truth.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in truth))
            out = state / "blind.json"
            code = main(["export-scenario", "--state-dir", str(state),
                         "--out", str(out), "--blind"])
            self.assertEqual(code, 0)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["truth"], [])
            self.assertEqual({item["label"] for item in doc["events"]}, {"benign"})


class FixtureIdentifierTest(unittest.TestCase):
    def test_no_export_names_the_range(self):
        for path in sorted((ROOT / "examples").glob("*.json")):
            doc = json.loads(path.read_text())
            text = json.dumps(doc["events"]) + json.dumps(doc["teach"])
            self.assertNotIn("nightshift", text.lower(), path.name)

    def test_no_fixture_mentions_this_machine(self):
        identifiers = real_identifiers()
        paths = sorted((ROOT / "fixtures").rglob("*.jsonl"))
        paths += sorted((ROOT / "examples").glob("*.json"))
        self.assertTrue(paths, "no sample files were scanned")
        for path in paths:
            text = path.read_text()
            for identifier in identifiers:
                self.assertNotIn(identifier, text,
                                 f"{path.name} leaks a real identifier: {identifier}")
