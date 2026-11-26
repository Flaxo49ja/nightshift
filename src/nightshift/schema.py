"""The one event shape every provider must produce.

Rules and the scorecard read only these fields, so a new provider (auditd)
never leaks its own format into detection logic.
"""
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

# Closed vocabulary: an unrecognised line stays "unknown" rather than being
# forced into a bucket. A wrong event_type is worse than an honest one.
EVENT_TYPES = frozenset({
    "auth_success", "auth_failure", "sudo_command", "session_open",
    "session_close", "service_start", "service_stop", "service_failed",
    "timer_run", "cron_run", "account_change", "process_exec",
    "firewall_block", "unknown",
})


@dataclass(frozen=True)
class Event:
    id: str
    ts: str                    # RFC3339, UTC, microseconds
    host: str
    provider: str              # "journald" now, "auditd" later
    source: str                # SYSLOG_IDENTIFIER, falls back to _COMM
    event_type: str
    priority: int | None
    unit: str | None
    user: str | None           # None when not confidently known — never guessed
    pid: int | None
    process: str | None
    cmdline: str | None
    src_ip: str | None
    src_port: int | None
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def event_id(provider: str, cursor: str) -> str:
    """Stable across re-runs: a journal cursor never changes for an entry."""
    return hashlib.sha256(f"{provider}:{cursor}".encode()).hexdigest()[:16]


def parse_ts(value: str) -> datetime:
    """Read both spellings we produce: rfc3339_utc's "Z" and isoformat's
    "+00:00". Comparing these as strings is not comparing times."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def rfc3339_utc(microseconds: int) -> str:
    """One timestamp format everywhere, so MTTD is subtraction, not parsing."""
    dt = datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")
