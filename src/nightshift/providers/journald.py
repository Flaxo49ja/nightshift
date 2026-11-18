"""journald provider.

`journalctl -o json` is the only source in slice 1. Two honest limits:
- it logs service output, not process execution, so curl/nmap runs are
  invisible here (see coverage.py);
- `_CMDLINE` is often absent for system services, so `cmdline` is best-effort.
"""
import json
import re
import subprocess
from datetime import datetime

from ..schema import Event, event_id, rfc3339_utc

# Identifiers worth keeping by default. The rest of this machine's journal is
# application stdout: collecting it would bury the signal without teaching
# anything. `--all` overrides.
DEFAULT_SOURCES = frozenset({
    "sudo", "su", "sshd", "systemd", "systemd-logind", "systemd-user-sessions",
    "polkitd", "pkexec", "useradd", "usermod", "userdel", "passwd",
    "CRON", "crond", "sddm", "gdm", "lightdm", "greetd", "ly", "ly-dm",
    "unix_chkpwd", "login", "kernel",
})

_USER_PATTERNS = {
    "sudo": re.compile(r"^\s*([\w.@-]+)\s*:"),
    "su": re.compile(r" by ([\w.@-]+)"),
    "sshd": re.compile(r"for (?:invalid user )?([\w.@-]+) from"),
    # logind quotes the name on this machine: "New session '1' of user 'alice'".
    "systemd-logind": re.compile(r"of user '?([\w.@-]+)'?"),
    "CRON": re.compile(r"^\(([\w.@-]+)\) CMD"),
    "useradd": re.compile(r"name=([\w.@-]+)"),
    "polkitd": re.compile(r"unix-user:([\w.@-]+)"),
}

_NETWORK = re.compile(r"from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)")

# systemd's own manager logs every line from `init.scope`, so for those entries
# the owning unit is only named at the start of the message:
#   "crowdsec-firewall-bouncer.service: Failed with result 'exit-code'."
_MANAGER_UNIT = "init.scope"
_UNIT_PREFIX = re.compile(
    r"^([A-Za-z0-9][\w@:.\-]*\."
    r"(?:automount|device|mount|path|scope|service|slice|socket|swap|target|timer)):"
)


def run_journalctl(after_cursor: str | None, since: datetime | None) -> list[dict]:
    cmd = ["journalctl", "--quiet", "--no-pager", "-o", "json"]
    if after_cursor:
        cmd.append(f"--after-cursor={after_cursor}")
    elif since:
        cmd.append(f"--since={since.isoformat()}")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        from .base import CursorInvalid

        if "cursor" in proc.stderr.lower():
            raise CursorInvalid(proc.stderr.strip())
        raise RuntimeError(f"journalctl failed: {proc.stderr.strip()}")
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a truncated final line must not abort a run
    return entries


class JournaldProvider:
    name = "journald"
    # The collector drops non-security identifiers unless `--all` is given.
    # auditd sets this to None: every record there is security relevant.
    allowlist = DEFAULT_SOURCES

    def __init__(self, runner=run_journalctl):
        self._runner = runner

    def fetch(self, after_cursor: str | None = None, since: datetime | None = None) -> list[dict]:
        return self._runner(after_cursor, since)

    @staticmethod
    def source_of(raw: dict) -> str:
        return raw.get("SYSLOG_IDENTIFIER") or raw.get("_COMM") or "unknown"

    def normalize(self, raw: dict) -> Event | None:
        cursor = raw.get("__CURSOR")
        realtime = raw.get("__REALTIME_TIMESTAMP")
        if not cursor or realtime is None:
            return None
        try:
            micros = int(realtime)
        except (TypeError, ValueError):
            return None
        message = _message(raw)
        source = self.source_of(raw)
        unit = _unit(raw, message)
        src_ip, src_port = _network(message)
        return Event(
            id=event_id(self.name, cursor),
            ts=rfc3339_utc(micros),
            host=raw.get("_HOSTNAME") or "unknown",
            provider=self.name,
            source=source,
            event_type=classify(source, message, unit),
            priority=_int_or_none(raw.get("PRIORITY")),
            unit=unit,
            user=_user(source, message),
            pid=_int_or_none(raw.get("_PID")),
            process=raw.get("_COMM"),
            cmdline=raw.get("_CMDLINE"),
            src_ip=src_ip,
            src_port=src_port,
            message=message,
        )


def classify(source: str, message: str, unit: str | None) -> str:
    """Map one line to the closed vocabulary; anything unknown stays unknown."""
    text = message.lower()

    if source == "sudo":
        if ("incorrect password" in text or "a password is required" in text
                or "not in sudoers" in text or "authentication failure" in text):
            return "auth_failure"
        if "command=" in text:
            return "sudo_command"

    if source == "su":
        if "failed su" in text or "authentication failure" in text or "incorrect password" in text:
            return "auth_failure"
        if "successful su" in text:
            return "auth_success"

    if source == "sshd":
        if "failed password" in text or "invalid user" in text or "authentication failure" in text:
            return "auth_failure"
        if "accepted" in text:
            return "auth_success"

    if source in {"systemd-logind", "systemd-user-sessions"}:
        if "new session" in text or "session opened" in text:
            return "session_open"
        if "logged out" in text or "session closed" in text or "removed session" in text:
            return "session_close"

    if source in {"polkitd", "pkexec"}:
        if "authentication failure" in text or "not authorized" in text:
            return "auth_failure"
        if "successfully authenticated" in text or "authenticating" in text or "granted" in text:
            return "auth_success"

    if source in {"useradd", "usermod", "userdel", "passwd"}:
        return "account_change"

    if source in {"sddm", "gdm", "lightdm", "greetd"}:
        if "authentication failure" in text or "failed" in text:
            return "auth_failure"
        if "authenticated" in text or "session opened" in text:
            return "auth_success"

    if source in {"CRON", "crond"}:
        return "cron_run"

    if source == "systemd":
        if unit and unit.endswith(".timer") and "started" in text:
            return "timer_run"
        if "failed" in text or "failure" in text:
            return "service_failed"
        if "stopped" in text or "stopping" in text:
            return "service_stop"
        if "started" in text or "starting" in text:
            return "service_start"

    return "unknown"


def _message(raw: dict) -> str:
    message = raw.get("MESSAGE", "")
    if isinstance(message, list):
        # journald emits an array of byte values for non-text messages
        return bytes(message).decode("utf-8", errors="replace")
    return str(message)


def _user(source: str, message: str) -> str | None:
    pattern = _USER_PATTERNS.get(source)
    if not pattern:
        return None
    match = pattern.search(message)
    # usernames never end in a full stop; "of user alice." is a sentence, not a name
    return match.group(1).rstrip(".") if match else None


def _unit(raw: dict, message: str) -> str | None:
    """The unit that owns this entry, or the one the manager names in the line."""
    unit = raw.get("_SYSTEMD_UNIT") or raw.get("_SYSTEMD_USER_UNIT")
    if unit and unit != _MANAGER_UNIT:
        return unit
    match = _UNIT_PREFIX.match(message)
    return match.group(1) if match else unit


def _network(message: str) -> tuple[str | None, int | None]:
    match = _NETWORK.search(message)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
