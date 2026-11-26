"""The export is only shareable if the machine it came from cannot be named."""
import getpass
import json
import platform
import re
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from nightshift.scenario import DOC_HOST, DOC_USER, Sanitizer, export, scenario_id

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


class ExportTest(unittest.TestCase):
    def truth(self):
        return [{"id": "t1", "technique": "T1053.006", "status": "ran",
                 "started": "2026-11-26T05:04:40.881183Z",
                 "ended": "2026-11-26T05:04:40.983996Z", "observed": 1,
                 "variant": "transient", "title": "User timer", "provider": "journald"}]

    def test_document_has_the_documented_shape(self):
        doc = export([event()], self.truth(), lang="en")
        self.assertEqual(set(doc), {"id", "lang", "events", "truth", "teach", "limits"})
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


class FixtureIdentifierTest(unittest.TestCase):
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
