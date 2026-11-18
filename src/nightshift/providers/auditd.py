"""auditd provider.

journald logs service output, so process execution is invisible there: `curl`
and `nmap` never appear. auditd records `execve`, which is the whole reason this
provider exists.

`/var/log/audit/audit.log` is root-only on a default install, so the provider
takes a path and says plainly when it cannot read it instead of reporting a
clean zero. Fixtures drive the tests; a real box needs the sudo the README
mentions.

Parsing is deliberately narrow: SYSCALL/EXECVE/PROCTITLE for execution,
USER_CMD for sudo, USER_AUTH/LOGIN for authentication. Anything else stays
`unknown` — a wrong event_type is worse than an honest gap.
"""
import binascii
import re
from datetime import datetime
from pathlib import Path

from ..schema import Event, event_id, rfc3339_utc
from .base import CursorInvalid

AUDIT_LOG = Path("/var/log/audit/audit.log")

_HEADER = re.compile(r"^type=(\w+) msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s?(.*)$")
_FIELD = re.compile(r"(\w+)=(\".*?\"|'[^']*'|[^\s]+)")

# execve / execveat on x86_64. Other architectures differ; those records land as
# `unknown` rather than being mislabelled as execution.
_EXEC_SYSCALLS = frozenset({"59", "322"})


def parse_line(line: str) -> dict | None:
    match = _HEADER.match(line.strip())
    if not match:
        return None
    record_type, seconds, serial, body = match.groups()
    fields = {}
    for key, value in _FIELD.findall(body):
        quoted = len(value) > 1 and value[0] == value[-1] and value[0] in "\"'"
        fields[key] = value[1:-1] if quoted else value
    # USER_AUTH/USER_CMD/LINUX messages nest their real fields inside
    # `msg='...'`; without this, `res=failed` and `acct="alice"` are invisible.
    nested = fields.pop("msg", None)
    if nested:
        for key, value in _FIELD.findall(nested):
            quoted = len(value) > 1 and value[0] == value[-1] and value[0] in "\"'"
            fields[key] = value[1:-1] if quoted else value
        fields["msg"] = nested
    return {"type": record_type, "seconds": float(seconds), "serial": serial, "fields": fields}


def _decode(text: str) -> str:
    """auditd hex-encodes values that would break its own format."""
    if not text or len(text) % 2:
        return text
    try:
        raw = binascii.unhexlify(text)
    except (binascii.Error, ValueError):
        return text
    return raw.decode("utf-8", errors="replace")


def _cmdline(records: list[dict]) -> str | None:
    for record in records:
        if record["type"] == "EXECVE":
            args = [(k, v) for k, v in record["fields"].items() if re.fullmatch(r"a\d+", k)]
            args.sort(key=lambda kv: int(kv[0][1:]))
            if args:
                return " ".join(v for _, v in args)
    for record in records:
        proctitle = record["fields"].get("proctitle")
        if proctitle:
            return _decode(proctitle).replace("\x00", " ").strip()
    return None


def _first(records: list[dict], name: str) -> str | None:
    for record in records:
        if name in record["fields"]:
            return record["fields"][name]
    return None


def classify(records: list[dict]) -> str:
    syscall = _first(records, "syscall")
    record_types = {r["type"] for r in records}
    if syscall in _EXEC_SYSCALLS or "EXECVE" in record_types:
        return "process_exec"
    if "USER_CMD" in record_types:
        return "sudo_command"
    result = (_first(records, "res") or "").lower()
    if "USER_AUTH" in record_types or "CRED_ACQ" in record_types or "LOGIN" in record_types:
        if result in {"failed", "no"}:
            return "auth_failure"
        if result in {"success", "yes"}:
            return "auth_success"
    if "USER_ACCT" in record_types or "ADD_USER" in record_types:
        return "account_change"
    if "SERVICE_START" in record_types:
        return "service_start"
    if "SERVICE_STOP" in record_types:
        return "service_stop"
    return "unknown"


def normalize(records: list[dict], name: str = "auditd") -> Event | None:
    if not records:
        return None
    head = records[0]
    micros = int(round(head["seconds"] * 1_000_000))
    event_type = classify(records)
    cmdline = _cmdline(records) if event_type == "process_exec" else None
    if event_type == "sudo_command":
        cmdline = _decode(_first(records, "cmd") or "") or None
    message = _first(records, "msg") or ""
    if not message:
        message = cmdline or _first(records, "comm") or head["type"].lower()
    return Event(
        id=event_id(name, f"{int(head['seconds'] * 1_000_000)}:{head['serial']}"),
        ts=rfc3339_utc(micros),
        host=_first(records, "hostname") or "unknown",
        provider=name,
        source=(_first(records, "comm") or head["type"]),
        event_type=event_type,
        priority=None,                      # auditd has no syslog priority
        unit=None,
        # Only a name auditd actually recorded: auid is numeric and mapping it
        # through /etc/passwd would be a guess about a different machine.
        user=_first(records, "acct"),
        pid=_int_or_none(_first(records, "pid")),
        process=_first(records, "comm") or _first(records, "exe"),
        cmdline=cmdline,
        src_ip=_first(records, "addr") if _first(records, "addr") not in (None, "?", "::1") else None,
        src_port=None,
        message=message,
    )


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def group_records(lines: list[str]) -> list[list[dict]]:
    """Records sharing an audit serial are one event, kept in file order."""
    grouped: dict[tuple[float, str], list[dict]] = {}
    order: list[tuple[float, str]] = []
    for line in lines:
        record = parse_line(line)
        if record is None:
            continue
        key = (record["seconds"], record["serial"])
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(record)
    return [grouped[key] for key in order]


class AuditdProvider:
    name = "auditd"
    # auditd has no noisy-identifier problem: every record is security relevant.
    allowlist = None

    def __init__(self, path: Path = AUDIT_LOG):
        self.path = Path(path)

    def _lines(self) -> list[str]:
        try:
            return self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError as exc:
            raise RuntimeError(f"no audit log at {self.path} "
                               f"(install auditd or pass --file)") from exc
        except PermissionError as exc:
            raise RuntimeError(f"cannot read {self.path}: permission denied "
                               f"(audit.log is root-only; run with sudo or use --file)") from exc

    def fetch(self, after_cursor: str | None = None, since: datetime | None = None) -> list[list[dict]]:
        groups = group_records(self._lines())
        serials = [int(group[0]["serial"]) for group in groups]
        if after_cursor:
            cursor = int(after_cursor)
            if serials and min(serials) > cursor:
                # The log rotated past our position: report the hole.
                raise CursorInvalid(f"serial {cursor} is older than the log's first record")
            groups = [g for g in groups if int(g[0]["serial"]) > cursor]
        if since is not None:
            cutoff = since.timestamp()
            groups = [g for g in groups if g[0]["seconds"] >= cutoff]
        return groups

    @staticmethod
    def source_of(raw: list[dict]) -> str:
        return raw[0]["type"] if raw else "unknown"

    def normalize(self, raw: list[dict]) -> Event | None:
        return normalize(raw, self.name)
