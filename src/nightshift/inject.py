"""Safe technique injector.

The point of a practice range is ground truth: you need to know an attack
happened before you can judge whether it was detected. Every action here is
chosen to be harmless by construction:

* loopback or local-process only — nothing leaves the machine;
* no state is created that survives the run (timers are transient and reset);
* every technique is best-effort: a missing binary is `skipped`, not a crash;
* ground truth is written *before* any scoring reads it, so the scorecard can
  never be tuned after the fact.

`--blind` writes the truth to a separate file and prints only counts, so you can
triage the queue honestly instead of reading the answers first.

What is deliberately absent: credential attacks. Simulating password guessing
needs a password prompt, a real account and a plausible failure mode, and getting
that wrong means locking an account on your own box. Use the fixtures for
T1110.001 (see coverage.py); the injector says so rather than pretending.
"""
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .coverage import visibility
from .schema import parse_ts

PROVIDER = "journald"

# journald writes asynchronously; a line belonging to a run can land seconds
# after the injector has returned.
OBSERVATION_GRACE = 5

TECHNIQUES = {
    "T1548.003": "Sudo privilege enumeration (`sudo -n -l`)",
    "T1053.006": "User timer: transient (`systemd-run`) or a unit pair on disk",
    "T1543.002": "User service persistence (enable, start, then remove)",
    "T1105": "Loopback ingress transfer (fetch from a local mock server)",
    "T1046": "Loopback service discovery (TCP connect sweep)",
}

# Techniques this machine can inject but journald cannot see. Recorded anyway:
# a technique with no telemetry must never be scored as "missed".
NO_TELEMETRY_EXPECTED = frozenset({"T1105", "T1046"})

# What each simulation should leave in the journal, if anything. Used to tell
# "the rule missed it" apart from "nothing was emitted".
EXPECTED_EVENT_TYPES = {
    "T1110.001": {"auth_failure"},
    "T1548.003": {"sudo_command", "auth_failure"},
    "T1053.006": {"service_start", "timer_run"},
    "T1543.002": {"service_start"},
    "T1105": {"process_exec"},
    "T1046": {"process_exec"},
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _record(technique: str, status: str, started: str, reason: str = "",
            marker: str = "", **extra) -> dict:
    return {
        "id": marker or secrets.token_hex(6),
        # The unit name this record created, so an exporter can find its lines
        # again without guessing from timestamps.
        "marker": marker,
        "technique": technique,
        "title": TECHNIQUES.get(technique, technique),
        "status": status,                     # ran | skipped | failed
        "reason": reason,
        "started": started,
        "ended": now(),
        "provider": PROVIDER,
        "visible_expected": (visibility(technique, PROVIDER) == "observed"
                             and technique not in NO_TELEMETRY_EXPECTED),
        **extra,
    }


def _run(argv: list[str], timeout: int = 15):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def inject_sudo_enumeration(runner=_run) -> dict:
    started = now()
    try:
        proc = runner(["sudo", "-n", "-l"])
    except FileNotFoundError:
        return _record("T1548.003", "skipped", started, "sudo is not installed")
    except subprocess.TimeoutExpired:
        return _record("T1548.003", "failed", started, "sudo hung; nothing was changed")
    # Without a cached credential this fails with "a password is required",
    # which journald records as an auth_failure. Either outcome is real
    # telemetry and neither changes state.
    status = "ran" if proc.returncode is not None else "failed"
    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return _record("T1548.003", status, started,
                   reason=detail[0] if detail else "", attempts=1)


def inject_timer(runner=_run) -> dict:
    """Variant 1: a transient unit, as `systemd-run --on-active` creates it."""
    started = now()
    unit = f"nightshift-sim-{secrets.token_hex(4)}.timer"
    if not shutil.which("systemd-run"):
        return _record("T1053.006", "skipped", started, "systemd-run is not installed",
                       marker=unit, variant="transient",
                       expected_rules=["transient-unit-started"])
    try:
        runner(["systemd-run", "--user", "--on-active=1", f"--unit={unit}", "true"])
        # Cleanup is part of the simulation: nothing may outlive the run.
        runner(["systemctl", "--user", "reset-failed", unit])
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _record("T1053.006", "skipped", started, str(exc), marker=unit,
                       variant="transient")
    return _record("T1053.006", "ran", started, marker=unit, variant="transient",
                   expected_rules=["transient-unit-started"],
                   note="transient timer; reset with systemctl --user reset-failed")


UNIT_DIR = Path.home() / ".config" / "systemd" / "user"

SERVICE_UNIT = "[Unit]\nDescription=nightshift simulated task\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n"

# The timer has no Description= on purpose: systemd then logs its unit name,
# which is the line the timer rule reads. The service keeps one so its start
# is not mistaken for a description-less transient unit.
TIMER_UNIT = "[Unit]\n\n[Timer]\nOnActiveSec=1\nUnit={name}.service\n"


def inject_user_service(runner=_run, sleeper=time.sleep, unit_dir: Path | None = None) -> dict:
    """T1543.002: install a real user service, arm it, then remove it.

    `enable` writes only a symlink and `disable` writes nothing to the journal,
    which is the blind spot this simulation exists to show. The unit file is
    removed and the manager reloaded in `finally`, whatever happened above.
    """
    started = now()
    directory = Path(unit_dir) if unit_dir else UNIT_DIR
    name = f"nightshift-{secrets.token_hex(4)}.service"
    service = directory / name
    try:
        directory.mkdir(parents=True, exist_ok=True)
        service.write_text(SERVICE_UNIT, encoding="utf-8")
        runner(["systemctl", "--user", "daemon-reload"])
        enabled = runner(["systemctl", "--user", "enable", name])
        if enabled.returncode != 0:
            reason = (enabled.stderr or enabled.stdout or "").strip()
            return _record("T1543.002", "failed", started,
                           reason or f"enable exit {enabled.returncode}",
                           marker=name, variant="user-service")
        proc = runner(["systemctl", "--user", "start", name])
        if proc.returncode != 0:
            reason = (proc.stderr or proc.stdout or "").strip()
            return _record("T1543.002", "failed", started,
                           reason or f"start exit {proc.returncode}",
                           marker=name, variant="user-service")
        sleeper(0.5)                    # let journald receive the start line
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _record("T1543.002", "skipped", started,
                       f"{type(exc).__name__}: {exc}", marker=name,
                       variant="user-service")
    finally:
        for argv in (["systemctl", "--user", "disable", name],
                     ["systemctl", "--user", "stop", name],
                     ["systemctl", "--user", "daemon-reload"]):
            try:
                runner(argv)
            except (OSError, subprocess.TimeoutExpired):
                continue
        try:
            service.unlink()
        except FileNotFoundError:
            pass
    return _record("T1543.002", "ran", started, marker=name,
                   variant="user-service",
                   note="user service disabled, stopped and removed; daemon reloaded")


def inject_timer_unit(runner=_run, sleeper=time.sleep, unit_dir: Path | None = None) -> dict:
    """Variant 2: arm a persistent timer the way an operator would.

    The pair lands in the user's systemd directory, is started, and is removed
    in `finally` whether or not anything worked, so nothing outlives the run.
    """
    started = now()
    directory = Path(unit_dir) if unit_dir else UNIT_DIR
    name = f"nightshift-{secrets.token_hex(4)}"
    service = directory / f"{name}.service"
    timer = directory / f"{name}.timer"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        service.write_text(SERVICE_UNIT, encoding="utf-8")
        timer.write_text(TIMER_UNIT.format(name=name), encoding="utf-8")
        runner(["systemctl", "--user", "daemon-reload"])
        proc = runner(["systemctl", "--user", "start", f"{name}.timer"])
        if proc.returncode != 0:
            reason = (proc.stderr or proc.stdout or "").strip()
            return _record("T1053.006", "failed", started,
                           reason or f"systemctl exit {proc.returncode}",
                           marker=f"{name}.timer", variant="unit-file",
                           expected_rules=["timer-unit-introduced"])
        sleeper(2.5)                    # OnActiveSec=1, plus room to land
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _record("T1053.006", "skipped", started,
                       f"{type(exc).__name__}: {exc}", marker=f"{name}.timer",
                       variant="unit-file", expected_rules=["timer-unit-introduced"])
    finally:
        for argv in (["systemctl", "--user", "stop", f"{name}.timer"],
                     ["systemctl", "--user", "reset-failed", f"{name}.service"],
                     ["systemctl", "--user", "daemon-reload"]):
            try:
                runner(argv)
            except (OSError, subprocess.TimeoutExpired):
                continue
        for path in (timer, service):
            try:
                path.unlink()
            except FileNotFoundError:
                continue
    return _record("T1053.006", "ran", started, marker=f"{name}.timer",
                   variant="unit-file",
                   expected_rules=["timer-unit-introduced"],
                   note="timer unit pair removed; daemon reloaded")


class _OneShot(BaseHTTPRequestHandler):
    def do_GET(self):                      # noqa: N802 - stdlib naming
        body = b"nightshift-sim\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):         # silence the default stderr spam
        return


def inject_ingress(fetcher=None) -> dict:
    """Fetch one file from a loopback server, then shut it down."""
    started = now()
    server = HTTPServer(("127.0.0.1", 0), _OneShot)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if fetcher is None:
            import urllib.request

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/payload", timeout=5) as rsp:
                fetcher = rsp.read
        fetcher()
    except Exception as exc:               # noqa: BLE001 - any failure is a skip
        return _record("T1105", "skipped", started, f"{type(exc).__name__}: {exc}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return _record("T1105", "ran", started, note="loopback only; server closed",
                   bytes_moved=14)


def inject_discovery(ports=range(1, 21), connector=None) -> dict:
    """Connect-sweep loopback ports. Closed ports are the normal outcome."""
    started = now()
    connector = connector or (lambda host, port, timeout: socket.create_connection(
        (host, port), timeout=timeout))
    opened, attempted = [], 0
    for port in ports:
        attempted += 1
        try:
            connector("127.0.0.1", port, 0.2)
            opened.append(port)
        except OSError:
            continue
    return _record("T1046", "ran", started, note="loopback only", attempted=attempted,
                   open_ports=opened)


INJECTORS = {
    "T1548.003": (inject_sudo_enumeration,),
    # Two variants of one technique, not two techniques.
    "T1053.006": (inject_timer, inject_timer_unit),
    "T1543.002": (inject_user_service,),
    "T1105": (inject_ingress,),
    "T1046": (inject_discovery,),
}


def evidence(record: dict, events: list[dict]) -> list[dict]:
    """The journal events this injection record owns.

    Used both to count `observed` at injection time and to label a scenario, so
    the answer key and the evidence cannot disagree. A record with a marker only
    claims lines that carry it; the transient variant is the exception, because
    systemd logs its units by description (`Started [systemd-run] ...`) and the
    unit name appears nowhere in the line.
    """
    expected = EXPECTED_EVENT_TYPES.get(record["technique"], set())
    if not expected:
        return []
    start = parse_ts(record["started"])
    end = parse_ts(record["ended"]) + timedelta(seconds=OBSERVATION_GRACE)
    marker = record.get("marker") or ""
    owned = []
    for event in events:
        if event.get("event_type") not in expected:
            continue
        if not start <= parse_ts(event["ts"]) <= end:
            continue
        message = event.get("message") or ""
        if marker and marker not in message:
            transient_line = (record.get("variant") == "transient"
                              and event.get("event_type") == "service_start"
                              and message.lower().startswith("started ["))
            # A user service is logged by description, not by unit name.
            described_service = (record.get("variant") == "user-service"
                                 and event.get("event_type") == "service_start"
                                 and "nightshift simulated task" in message.lower())
            if not transient_line and not described_service:
                continue
        owned.append(event)
    return owned


def run(techniques: list[str] | None = None, truth_path: Path | None = None,
        blind: bool = False, injectors: dict | None = None) -> list[dict]:
    """Run each technique once and record ground truth."""
    injectors = injectors or INJECTORS
    chosen = techniques or list(injectors)
    unknown = [t for t in chosen if t not in injectors]
    if unknown:
        raise ValueError(f"unknown technique(s): {', '.join(unknown)} "
                         f"(choose from {', '.join(sorted(injectors))})")

    records = []
    for technique in chosen:
        variants = injectors[technique]
        for injector in (variants if isinstance(variants, tuple) else (variants,)):
            records.append(injector())
    if truth_path is not None:
        write_truth(records, Path(truth_path), blind)
    return records


def write_truth(records: list[dict], path: Path, blind: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    if blind:
        # 0600: the answers exist, but reading them is a deliberate act.
        path.chmod(0o600)


def read_truth(path: Path) -> list[dict]:
    if not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
