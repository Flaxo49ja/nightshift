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
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .coverage import visibility

PROVIDER = "journald"

TECHNIQUES = {
    "T1548.003": "Sudo privilege enumeration (`sudo -n -l`)",
    "T1053.006": "Transient user timer (`systemd-run --user`)",
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
    "T1105": {"process_exec"},
    "T1046": {"process_exec"},
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _record(technique: str, status: str, started: str, reason: str = "",
            marker: str = "", **extra) -> dict:
    return {
        "id": marker or secrets.token_hex(6),
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
    started = now()
    unit = f"nightshift-sim-{secrets.token_hex(4)}.timer"
    if not shutil.which("systemd-run"):
        return _record("T1053.006", "skipped", started, "systemd-run is not installed",
                       marker=unit)
    try:
        runner(["systemd-run", "--user", "--on-active=1", f"--unit={unit}", "true"])
        # Cleanup is part of the simulation: nothing may outlive the run.
        runner(["systemctl", "--user", "reset-failed", unit])
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _record("T1053.006", "skipped", started, str(exc), marker=unit)
    return _record("T1053.006", "ran", started, marker=unit,
                   note="transient timer; reset with systemctl --user reset-failed")


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
    "T1548.003": inject_sudo_enumeration,
    "T1053.006": inject_timer,
    "T1105": inject_ingress,
    "T1046": inject_discovery,
}


def run(techniques: list[str] | None = None, truth_path: Path | None = None,
        blind: bool = False, injectors: dict | None = None) -> list[dict]:
    """Run each technique once and record ground truth."""
    injectors = injectors or INJECTORS
    chosen = techniques or list(injectors)
    unknown = [t for t in chosen if t not in injectors]
    if unknown:
        raise ValueError(f"unknown technique(s): {', '.join(unknown)} "
                         f"(choose from {', '.join(sorted(injectors))})")

    records = [injectors[technique]() for technique in chosen]
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
