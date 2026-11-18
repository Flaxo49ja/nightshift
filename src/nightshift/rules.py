"""Detection rules: JSON in, detections out.

A rule is data, never code. That keeps them reviewable in a pull request and
means a typo is a loud error rather than a detection that silently never fires.

Two shapes exist, and only two:

* **single** — one event matching `when` is a detection (`count_gte` absent or 1).
* **burst** — `count_gte` matching events for the same `group_by` value inside
  `within` is a detection. This is what "five failed logins in ten minutes"
  actually needs; a single-event rule cannot express it without becoming noise.

Deliberately missing: joins, correlation across rules, and anything that reads
outside the Event record. Those are engineering, not practice-range value, and
every one of them is a place to hide a bug.
"""
import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# Event fields a rule may filter on. Anything else is a typo, not a feature.
MATCH_FIELDS = frozenset({
    "event_type", "source", "provider", "user", "host", "unit", "process",
    "cmdline", "src_ip", "src_port", "priority",
})
# Derived matchers that are cheap to express and expensive to get wrong.
DERIVED = frozenset({"message_contains", "cmdline_contains", "unit_contains"})
SEVERITIES = ("low", "medium", "high", "critical")

_REQUIRED = ("id", "title", "severity", "when")
_OPTIONAL = ("technique", "group_by", "count_gte", "within", "why", "false_positives")


class RuleError(Exception):
    """A rule that would load but behave wrongly. Refuse it at load time."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    when: dict
    technique: str | None = None
    group_by: str | None = None
    count_gte: int = 1
    within: int | None = None          # seconds; required when count_gte > 1
    why: str = ""
    false_positives: tuple[str, ...] = field(default=())

    @property
    def is_burst(self) -> bool:
        return self.count_gte > 1


def parse_duration(text: str) -> int:
    """`30s`, `10m`, `2h`, `1d` -> seconds. Minutes and above must be whole."""
    value = str(text).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(value) < 2 or value[-1] not in units:
        raise RuleError(f"cannot parse duration {text!r} (use 30s, 10m, 2h, 1d)")
    try:
        amount = int(value[:-1])
    except ValueError as exc:
        raise RuleError(f"cannot parse duration {text!r} (use 30s, 10m, 2h, 1d)") from exc
    if amount <= 0:
        raise RuleError(f"duration must be positive: {text!r}")
    return amount * units[value[-1]]


def _check_when(when, rule_id: str) -> dict:
    if not isinstance(when, dict) or not when:
        raise RuleError(f"{rule_id}: `when` must be a non-empty object")
    for key, value in when.items():
        if key not in MATCH_FIELDS and key not in DERIVED:
            known = ", ".join(sorted(MATCH_FIELDS | DERIVED))
            raise RuleError(f"{rule_id}: unknown match field {key!r} (known: {known})")
        if key in DERIVED:
            if not isinstance(value, str) or not value:
                raise RuleError(f"{rule_id}: {key} must be a non-empty string")
        elif key == "priority":
            if isinstance(value, bool) or not isinstance(value, (int, list)):
                raise RuleError(f"{rule_id}: priority must be an int or a list of ints")
        else:
            # `bool` is an `int` in Python: true/false would load and then
            # never equal an event field, which is the silent failure this
            # validation exists to stop.
            if isinstance(value, bool):
                raise RuleError(f"{rule_id}: {key} must be a string, int or list, not a boolean")
            if isinstance(value, list) and not value:
                raise RuleError(f"{rule_id}: {key} list must not be empty")
            if isinstance(value, list) and any(isinstance(v, bool) for v in value):
                raise RuleError(f"{rule_id}: {key} list must not contain booleans")
            if not isinstance(value, (str, int, list)):
                raise RuleError(f"{rule_id}: {key} must be a string, int or list")
    return dict(when)


def load_rule(data: dict) -> Rule:
    if not isinstance(data, dict):
        raise RuleError("a rule must be a JSON object")
    for key in _REQUIRED:
        if key not in data:
            raise RuleError(f"missing required key {key!r} in rule {data.get('id', '<no id>')}")
    unknown = set(data) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        raise RuleError(f"{data['id']}: unknown rule key(s) {', '.join(sorted(unknown))}")

    rule_id = data["id"]
    if not isinstance(rule_id, str) or not rule_id:
        raise RuleError("rule id must be a non-empty string")
    title = data["title"]
    if not isinstance(title, str) or not title.strip():
        raise RuleError(f"{rule_id}: title must be a non-empty string")
    severity = data["severity"]
    if severity not in SEVERITIES:
        raise RuleError(f"{rule_id}: severity must be one of {', '.join(SEVERITIES)}")
    why = data.get("why", "")
    if not isinstance(why, str):
        raise RuleError(f"{rule_id}: why must be a string")
    false_positives = data.get("false_positives", ())
    # A bare string here would become a tuple of characters, which is worse
    # than an error because it renders almost plausibly.
    if isinstance(false_positives, str) or not isinstance(false_positives, (list, tuple)):
        raise RuleError(f"{rule_id}: false_positives must be a list of strings")
    if any(not isinstance(item, str) for item in false_positives):
        raise RuleError(f"{rule_id}: false_positives must be a list of strings")

    count_gte = data.get("count_gte", 1)
    if not isinstance(count_gte, int) or count_gte < 1:
        raise RuleError(f"{rule_id}: count_gte must be an integer >= 1")
    within = data.get("within")
    if count_gte > 1 and not within:
        raise RuleError(f"{rule_id}: a burst rule needs `within` (e.g. \"10m\")")
    if count_gte == 1 and within:
        raise RuleError(f"{rule_id}: `within` only means something with count_gte > 1")
    group_by = data.get("group_by")
    if count_gte > 1 and not group_by:
        raise RuleError(f"{rule_id}: a burst rule needs `group_by` to count per something")
    if group_by is not None and group_by not in MATCH_FIELDS:
        raise RuleError(f"{rule_id}: group_by must be an event field, got {group_by!r}")

    technique = data.get("technique")
    if technique is not None:
        if not isinstance(technique, str):
            raise RuleError(f"{rule_id}: technique must be a string like T1110.001")
        # Not every valid id is in the coverage matrix (that is a curated
        # subset), but a malformed one is a typo that would leave the rule
        # out of every ATT&CK view without anyone noticing.
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
            raise RuleError(
                f"{rule_id}: technique {technique!r} is not an ATT&CK id "
                f"(expected T1234 or T1234.567)"
            )

    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        when=_check_when(data["when"], rule_id),
        technique=technique,
        group_by=group_by,
        count_gte=count_gte,
        within=parse_duration(within) if within else None,
        why=why,
        false_positives=tuple(false_positives),
    )


def load_rules(directory: Path) -> list[Rule]:
    """Every `*.json` in a directory, sorted by id so output is stable."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(Path(directory).glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleError(f"{path.name}: not valid JSON ({exc})") from exc
        rule = load_rule(data)
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id!r} (see {path.name})")
        seen.add(rule.id)
        rules.append(rule)
    rules.sort(key=lambda r: r.id)
    return rules


def _field(event: dict, name: str):
    return event.get(name)


def matches(when: dict, event: dict) -> bool:
    for key, expected in when.items():
        if key in DERIVED:
            haystack = event.get("message" if key == "message_contains" else key.split("_")[0])
            haystack = (haystack or "").lower()
            if expected.lower() not in haystack:
                return False
            continue
        actual = _field(event, key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))


def detection_id(rule_id: str, first_event_id: str) -> str:
    return hashlib.sha256(f"{rule_id}:{first_event_id}".encode()).hexdigest()[:16]


def evaluate(events: list[dict], rules: list[Rule]) -> list[dict]:
    """Stream events once, keeping one sliding window per (rule, group).

    Sorted first: `events.jsonl` is append-ordered per collector run, and two
    runs can interleave. Rules over time need time order, not file order.
    """
    ordered = sorted(events, key=_ts)
    detections: list[dict] = []
    windows: dict[tuple[str, str], deque] = defaultdict(deque)
    fired_at: dict[tuple[str, str], datetime] = {}

    for event in ordered:
        when = _ts(event)
        for rule in rules:
            if not matches(rule.when, event):
                continue
            if not rule.is_burst:
                detections.append(_detection(rule, [event], event.get(rule.group_by)))
                continue

            key = (rule.id, str(event.get(rule.group_by) or "<none>"))
            window = windows[key]
            window.append(event)
            while window and (when - _ts(window[0])).total_seconds() > rule.within:
                window.popleft()

            last = fired_at.get(key)
            # Fire once per window, not once per event: a 500-event brute force
            # is one alert, which is what an analyst can actually triage.
            cooled = last is None or (when - last).total_seconds() > rule.within
            if len(window) >= rule.count_gte and cooled:
                fired_at[key] = when
                detections.append(_detection(rule, list(window), key[1]))

    detections.sort(key=lambda d: (d["ts_first"], d["rule_id"]))
    return detections


def _detection(rule: Rule, events: list[dict], key: str | None) -> dict:
    first, last = events[0], events[-1]
    return {
        "id": detection_id(rule.id, first["id"]),
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "technique": rule.technique,
        "count": len(events),
        "key": key,
        "host": first.get("host"),
        "ts_first": first["ts"],
        "ts_last": last["ts"],
        "event_ids": [e["id"] for e in events],
    }
