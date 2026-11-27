"""Export a scored session as a shareable, playable triage scenario.

The export exists so one person's real box can become another person's exercise
without leaking the first person's identifiers. Three rules make that true:

* **Deny by substitution.** The exporter replaces the machine's own hostname,
  username, home path and every IP address by value, including inside free text.
* **Say what the evidence is.** Each injection record owns the journal lines it
  produced (`event_ids`); lines caused by the injector's own reloads are listed
  as `side_effect_ids`; everything else is benign. A scenario can then be scored
  without treating a `daemon-reload` notice as an attack.
* **One document, answer key included.** `truth` lives beside `events`, so a
  scenario is self-contained and scoreable offline. That also makes it a
  spoiler: share it after the exercise, not before.

Injector-created names are renamed to aliases from a fixed list, deterministically
per scenario, because `nightshift-*` and "nightshift simulated task" tell the
reader exactly which range produced the file. Documentation ranges are used for
addresses (192.0.2.0/24) and fixed names for identity (`ws-01`, `analyst`).
"""
import getpass
import hashlib
import json
import platform
import re
import socket
from datetime import timedelta
from pathlib import Path

from .inject import OBSERVATION_GRACE, evidence
from .schema import parse_ts

DOC_HOST = "ws-01"
DOC_USER = "analyst"
DOC_HOME = "/home/analyst"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Loosely matched on purpose; `_scrub_v6` then rejects clock times and MACs.
# A time like 05:04:11 has two colons and no `::`; a MAC has five colons and
# also no `::`, so both stay out of the address map.
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w:])")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOC_NET = "192.0.2."
DOC_MAC = "00:00:5e:00:53:"

# A scenario is one session, not one store. Evidence and its context come from
# the truth window plus a minute of padding; anything older is another run.
SESSION_PAD = 60

# Fixed aliases, assigned in sorted order of the injector names a scenario
# contains. Keeping the list short and boring is the point; a reader should not
# be able to tell this was a practice range from the unit names.
ALIASES = ("backup-sync", "media-indexer", "log-rotate", "photo-import",
           "note-sync", "cache-warm")

INJECTOR_NAME = re.compile(r"nightshift-(?:sim-)?[0-9a-f]{8}")
DESCRIPTION = "nightshift simulated task"
DESCRIPTION_ALIAS = "backup sync"

# Manager lines produced by the injectors' own `daemon-reload`, not by the
# simulated technique.
SIDE_EFFECTS = ("reload requested", "reloading", "reloading finished")

TICKET_FIELDS = ("title", "severity", "reported_by", "customer_story",
                 "expected_action")
TICKET_ACTIONS = frozenset({"close_benign", "escalate", "need_more_data"})
RANGE_NAME = re.compile(r"nightshift", re.IGNORECASE)

# How each technique looks in the journal, for the teaching block. Rule text
# comes from the rule itself; this is the shape an analyst has to recognise.
LOOKS_LIKE = {
    "T1053.006": [
        "Started [systemd-run] /usr/sbin/true. (transient timer's service)",
        "Started <name>.timer. (on-disk timer being armed)",
    ],
    "T1548.003": ["a sudo command line, or an auth failure"],
    "T1110.001": ["repeated auth failures for one user"],
    "T1543.002": ["Starting <description>... with the unit recorded as the manager scope"],
    "T1105": ["nothing in journald; auditd execve would be the only trace"],
    "T1046": ["nothing in journald; firewall blocks are the closest signal"],
}

BLIND = {
    "T1543.002": {
        "name": "User service persistence",
        "why": "`systemctl --user enable` and `disable` write nothing, and the "
               "start line is `Starting <description>...` with the unit recorded "
               "as the manager scope. A rule would key on the attacker's own "
               "description or fire on every user service on the machine.",
    },
    "T1105": {"name": "Ingress tool transfer",
             "why": "journald records service output, not process execution; "
                    "the loopback fetch leaves no event to match."},
    "T1046": {"name": "Network service discovery",
              "why": "a connect sweep leaves no journal event; only the firewall's "
                     "view of rejected packets is visible, and that is T1595.002."},
}

TEACH = {
    "en": {
        "title": "What happened on ws-01?",
        "prompt": "Read the events, decide which technique was simulated, and say "
                  "which rule should have caught it before opening the answer key.",
        "hints": [
            "Start from the unit, user and process fields; the message is free text.",
            "A detection is only a catch if it lands after the injection started.",
            "truth records list the attack evidence they own in `event_ids`; "
            "`side_effect_ids` are the injector's own reload lines, not the technique.",
        ],
    },
    "pt": {
        "title": "O que aconteceu na ws-01?",
        "prompt": "Leia os eventos, decida qual técnica foi simulada e diga qual regra "
                  "deveria tê-la detectado antes de abrir o gabarito.",
        "hints": [
            "Comece pelos campos unit, user e process; a mensagem é texto livre.",
            "Uma detecção só conta se ocorrer depois do início da injeção.",
            "Os registros de verdade listam a evidência em `event_ids`; "
            "`side_effect_ids` são recargas do próprio injetor, não a técnica.",
        ],
    },
}

LIMITS = {
    "en": [
        "Sanitized: hostnames, usernames and home paths are replaced, and every IP "
        "address is mapped into 192.0.2.0/24. Background timestamps rebased; "
        "attack and side-effect timestamps are real.",
        "Injector-created unit names and descriptions are aliases from a fixed list; "
        "the aliasing is deterministic per scenario, so two exports of the same "
        "session agree.",
        "The answer key is in this file. It is a scenario, not a quiz you can take blind.",
        "Only what the exporter's providers could see is here; a technique with no "
        "telemetry appears in truth with an empty event set.",
        "Rule text in `teach` is quoted in English even in the Portuguese export.",
    ],
    "pt": [
        "Sanitizado: nomes de host, usuários e caminhos pessoais foram substituídos, e "
        "todo endereço IP foi mapeado para 192.0.2.0/24. Os horários do plano de "
        "fundo foram redistribuídos; ataque e efeitos colaterais são reais.",
        "Nomes de unidades e descrições criados pelo injetor são apelidos de uma lista "
        "fixa; o mapeamento é determinístico por cenário.",
        "O gabarito está neste arquivo. É um cenário, não um teste às cegas.",
        "Só está aqui o que os provedores conseguiam ver; uma técnica sem telemetria "
        "aparece na verdade com zero eventos.",
        "O texto das regras em `teach` é citado em inglês mesmo na exportação em português.",
    ],
}


class Sanitizer:
    """Replace this machine's identifiers by value, everywhere in a document."""

    def __init__(self, hostname: str | None = None, username: str | None = None,
                 home: str | None = None):
        names = {hostname, platform.node(), socket.gethostname()}
        self.hostnames = sorted({n for n in names if n and len(n) > 2},
                                key=len, reverse=True)
        self.usernames = sorted({u for u in {username, getpass.getuser()}
                                 if u and len(u) > 2}, key=len, reverse=True)
        self.home = str(home or Path.home())
        self._ips: dict[str, str] = {}
        self._macs: dict[str, str] = {}

    def address(self, ip: str) -> str:
        if ip not in self._ips:
            self._ips[ip] = f"{DOC_NET}{len(self._ips) + 1}"
        return self._ips[ip]

    def mac(self, value: str) -> str:
        key = value.lower()
        if key not in self._macs:
            self._macs[key] = f"{DOC_MAC}{len(self._macs) + 1:02x}"
        return self._macs[key]

    def text(self, value: str) -> str:
        out = value.replace(self.home, DOC_HOME)
        for name in self.hostnames:
            out = out.replace(name, DOC_HOST)
        for name in self.usernames:
            out = out.replace(name, DOC_USER)
        # Before IPv4/IPv6: a MAC is six colon-separated hex pairs and would
        # otherwise be read as a compressed IPv6 address.
        out = MAC.sub(lambda m: self.mac(m.group()), out)
        out = IPV4.sub(lambda m: self.address(m.group()), out)
        return IPV6.sub(self._scrub_v6, out)

    def _scrub_v6(self, match: re.Match) -> str:
        token = match.group()
        # A clock time has two colons, a MAC five with no `::`, IPv6 at least
        # six (or a `::`). Rejecting by shape keeps MACs in the MAC namespace.
        if "::" not in token and token.count(":") < 6:
            return token
        return self.address(token)

    def document(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.document(item) for item in value]
        if isinstance(value, dict):
            return {key: self.document(item) for key, item in value.items()}
        return value


def alias_map(events: list[dict], truth: list[dict]) -> dict[str, str]:
    """Deterministic per scenario: names sorted, aliases assigned in that order."""
    names = sorted(set(INJECTOR_NAME.findall(json.dumps(events) + json.dumps(truth))))
    return {name: ALIASES[index % len(ALIASES)]
            for index, name in enumerate(names)}


def _rename(value, mapping: dict[str, str]):
    if isinstance(value, str):
        out = value
        for name, alias in mapping.items():
            out = out.replace(name, alias)
        return out.replace(DESCRIPTION, DESCRIPTION_ALIAS)
    if isinstance(value, list):
        return [_rename(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _rename(item, mapping) for key, item in value.items()}
    return value


def session_bounds(truth: list[dict]):
    """Earliest started minus padding through latest ended plus padding."""
    if not truth:
        return None
    starts = [parse_ts(record["started"]) for record in truth]
    ends = [parse_ts(record["ended"]) for record in truth]
    return min(starts) - timedelta(seconds=SESSION_PAD), max(ends) + timedelta(seconds=SESSION_PAD)


# Background is a closed list. Any application, desktop or hardware name is
# dropped: a quiet-host corpus may only contain the generic descriptions below.
# The injector aliases are here too, after _rename makes them safe to publish.
BACKGROUND_DESCRIPTIONS = frozenset({
    "network manager script dispatcher service",
    "user preferences database",
    "virtual console setup",
    "journal service",
    "hostname service",
    "time & date service",
    "load kernel modules",
    "coldplug all udev devices",
    "create system files and directories",
    "rule-based manager for device events and files",
    "update the plocate database",
    "verify integrity of password and group files",
    "system suspend",
    "sleep",
    "suspend",
    "backup sync",
    "backup-sync",
    "log rotate",
    "log-rotate",
    "media indexer",
    "media-indexer",
    "photo import",
    "photo-import",
    "note sync",
    "note-sync",
    "cache warm",
    "cache-warm",
})
AUTH_TYPES = frozenset({"auth_success", "auth_failure", "sudo_command",
                        "session_open", "session_close", "account_change"})
UNIT_EVENT_TYPES = frozenset({"service_start", "service_stop", "service_failed",
                              "timer_run", "cron_run"})
UNIT_LINE = re.compile(r"\.(?:service|timer|socket|scope|target|mount|device|swap)\b")
MANAGER_PREFIXES = tuple(sorted(("starting ", "started ", "stopping ", "stopped ",
                                "finished ", "failed to start ", "failed to stop ",
                                "failed "), key=len, reverse=True))
PERSONAL = re.compile(r"[~/]| - ")
UNIT_SUFFIX = re.compile(r"\.(?:service|timer|socket|scope|target|mount|device|swap)$")


def _description(message: str) -> str | None:
    """The generic task name in a manager line, or None for another shape."""
    text = message.strip()
    lower = text.lower()
    for prefix in MANAGER_PREFIXES:
        if not lower.startswith(prefix):
            continue
        description = text[len(prefix):].strip().rstrip(".")
        if ": " in description:
            description = description.split(": ", 1)[0]
        if description.lower().startswith("target "):
            description = description[7:]
        return UNIT_SUFFIX.sub("", description).lower()
    if ":" in text:
        head = text.split(":", 1)[0].strip()
        if UNIT_LINE.search(head):
            return UNIT_SUFFIX.sub("", head).lower()
    return None


def allow_benign(event: dict) -> bool:
    """True only for a fixed generic description a quiet host may contain."""
    event_type = event.get("event_type")
    if event_type == "firewall_block":
        return True
    if event_type in AUTH_TYPES:
        return True
    if event_type not in UNIT_EVENT_TYPES or event.get("source") == "kernel":
        return False
    message = (event.get("message") or "").strip()
    description = _description(message)
    if description is None or PERSONAL.search(description):
        return False
    return description in BACKGROUND_DESCRIPTIONS


def _injector_shaped(event: dict) -> bool:
    """A line only this range's injectors write, used for leftovers from
    another run that no truth record in this scenario can own."""
    message = (event.get("message") or "").lower()
    unit = (event.get("unit") or "").lower()
    return ("systemd-run" in message or "nightshift-" in message
            or "nightshift simulated" in message or unit.startswith("nightshift"))


def _in_window(event: dict, record: dict) -> bool:
    start = parse_ts(record["started"])
    end = parse_ts(record["ended"]) + timedelta(seconds=OBSERVATION_GRACE)
    return start <= parse_ts(event["ts"]) <= end


def label(events: list[dict], truth: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    """Attach one label per event and derive the per-record evidence ids.

    attack_evidence: the events the injector's own record owns.
    side_effect: the injector's reload lines inside a run window.
    benign: everything else.
    """
    ran = [record for record in truth if record.get("status") == "ran"]
    owned: dict[str, str] = {}
    for record in ran:
        record["event_ids"] = [event["id"] for event in evidence(record, events)]
        for event_id in record["event_ids"]:
            owned[event_id] = record["id"]

    side_effect_ids: list[str] = []
    labelled = []
    for event in events:
        if event["id"] in owned:
            label_name = "attack_evidence"
        elif any(_in_window(event, record) for record in ran) and any(
                marker in (event.get("message") or "").lower() for marker in SIDE_EFFECTS):
            label_name = "side_effect"
            side_effect_ids.append(event["id"])
        else:
            label_name = "benign"
        labelled.append({**event, "label": label_name})
    return labelled, truth, side_effect_ids


def _teach_entries(truth: list[dict], rules) -> list[dict]:
    by_id = {rule.id: rule for rule in (rules or [])}
    entries: list[dict] = []
    seen: set[str] = set()
    for record in truth:
        technique = record["technique"]
        if technique in seen:
            continue
        seen.add(technique)
        rule = next((by_id[rid] for rid in record.get("expected_rules") or []
                     if rid in by_id), None)
        if rule is None:
            rule = next((r for r in (rules or []) if r.technique == technique), None)
        if rule is not None:
            entries.append({
                "technique": technique,
                "name": rule.title,
                "why": rule.why,
                "looks_like": LOOKS_LIKE.get(technique, []),
                "false_positives": list(rule.false_positives),
                "rule_id": rule.id,
                "blind_spot": False,
            })
        else:
            blind = BLIND.get(technique, {})
            entries.append({
                "technique": technique,
                "name": blind.get("name", technique),
                "why": blind.get("why", "no rule covers this technique for this provider"),
                "looks_like": LOOKS_LIKE.get(technique, []),
                "false_positives": [],
                "rule_id": None,
                "blind_spot": True,
            })
    if "T1543.002" not in seen:
        blind = BLIND["T1543.002"]
        entries.append({
            "technique": "T1543.002",
            "name": blind["name"],
            "why": blind["why"],
            "looks_like": LOOKS_LIKE["T1543.002"],
            "false_positives": [],
            "rule_id": None,
            "blind_spot": True,
        })
    return entries


def _clean_ticket(ticket: dict, cleaner: Sanitizer, mapping: dict[str, str]) -> dict:
    """Validate the optional ticket, then run the same sanitizer over it."""
    if not isinstance(ticket, dict):
        raise ValueError("ticket must be an object")
    missing = [field for field in TICKET_FIELDS
               if not isinstance(ticket.get(field), str) or not ticket[field].strip()]
    if missing:
        raise ValueError(f"ticket is missing {', '.join(missing)}")
    if ticket["expected_action"] not in TICKET_ACTIONS:
        raise ValueError(
            f"ticket expected_action must be one of {', '.join(sorted(TICKET_ACTIONS))}")
    cleaned = _rename(cleaner.document({field: ticket[field] for field in TICKET_FIELDS}),
                      mapping)
    # The range's own name must never reach a player, including in prose.
    for field in TICKET_FIELDS:
        cleaned[field] = RANGE_NAME.sub("backup-sync", cleaned[field])
    return cleaned


def scenario_id(events: list[dict], truth: list[dict]) -> str:
    canonical = json.dumps({"events": events, "truth": truth}, sort_keys=True,
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _rebase_noise(events: list[dict], bounds) -> list[dict]:
    """Keep the quiet day's order, but place it inside this session's clock.

    A corpus collected on another day is scenery, not a second timeline. The
    first event lands at the session start and the last at its end, evenly
    spaced between, with timestamps rounded to microseconds.
    """
    if not events or bounds is None:
        return [dict(event) for event in events]
    ordered = sorted(events, key=lambda event: (parse_ts(event["ts"]), event["id"]))
    start, end = bounds
    span = end - start
    count = len(ordered)
    rebased = []
    for index, event in enumerate(ordered):
        fraction = index / (count - 1) if count > 1 else 0.0
        moment = start + span * fraction
        rebased.append({
            **event,
            "ts": moment.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        })
    return rebased


def _background_rank(event: dict, required: list[dict], seed: int):
    """Nearest the attacks first; the seed settles what distance cannot."""
    moment = parse_ts(event["ts"])
    distance = 0.0
    if required:
        distance = min(abs((moment - parse_ts(item["ts"])).total_seconds())
                       for item in required)
    tie = hashlib.sha256(f"{seed}:{event['id']}".encode()).hexdigest()
    return (distance, tie, event["ts"], event["id"])


def export(events: list[dict], truth: list[dict], lang: str = "en",
           sanitizer: Sanitizer | None = None, detections=None,
           noise: list[dict] | None = None, rules=None,
           max_events: int = 20, seed: int = 0, blind: bool = False,
           ticket: dict | None = None) -> dict:
    """Build the scenario document. Pure: same input, same id, no clock.

    `blind` removes the answer key and every attack label, leaving a night where
    the correct answer is what the log does not show. Use it for blind-spot
    exercises, not for a normal scored scenario.
    """
    if lang not in TEACH:
        raise ValueError(f"unknown language {lang!r} (choose from {', '.join(TEACH)})")
    cleaner = sanitizer or Sanitizer()
    mapping = alias_map(events, truth)

    bounds = session_bounds(truth)
    if bounds is None:
        in_session, outside = [], len(events)
    else:
        start, end = bounds
        in_session = [event for event in events
                      if start <= parse_ts(event["ts"]) <= end]
        outside = len(events) - len(in_session)

    labelled, records, side_effect_ids = label(in_session, truth)
    records = [dict(record) for record in records]
    untied = [event for event in labelled
              if event["label"] == "benign" and _injector_shaped(event)
              and not any(_in_window(event, record) for record in truth)]
    dropped = {event["id"] for event in untied}
    labelled = [event for event in labelled if event["id"] not in dropped]

    # Background is allowlisted first, then sized: evidence and side effects
    # are never traded away for scenery.
    benign = [event for event in labelled if event["label"] == "benign"]
    allowed = [event for event in benign if allow_benign(event)]
    not_allowed = len(benign) - len(allowed)

    # Quiet input is held to the same rules as the session: stale injector
    # runs and anything inside a truth window are not scenery.
    noise_in_window = 0
    noise_injector = 0
    clean_noise = []
    for event in (noise or []):
        if any(_in_window(event, record) for record in truth):
            noise_in_window += 1
            continue
        if _injector_shaped(event):
            noise_injector += 1
            continue
        clean_noise.append(event)
    quiet = [{**event, "label": "benign"} for event in clean_noise
             if allow_benign(event)]
    noise_not_allowed = len(clean_noise) - len(quiet)

    if blind:
        # There is no attack label to protect, but the session's own lines must
        # stay: the user-service start is the blind spot the exercise is about.
        required = [event for event in labelled if event["label"] != "benign"] + allowed
        candidates = quiet
    else:
        required = [event for event in labelled if event["label"] != "benign"]
        candidates = allowed + quiet
    if max_events < len(required):
        raise ValueError(
            f"--max-events {max_events} is smaller than the {len(required)} "
            "required session events")
    slots = max_events - len(required)
    chosen = sorted(candidates, key=lambda event: _background_rank(event, required, seed))[:slots]
    # Rebase only the quiet events that survived selection; the session's own
    # timestamps are evidence and must not move.
    quiet_ids = {id(event) for event in quiet}
    chosen_noise = [event for event in chosen if id(event) in quiet_ids]
    rebased = {id(event): moved for event, moved in zip(
        chosen_noise, _rebase_noise(chosen_noise, bounds))}
    chosen = [rebased.get(id(event), event) for event in chosen]
    mixed = required + [{**event, "label": "benign"} for event in chosen]
    mixed.sort(key=lambda event: event["ts"])

    clean_events = [_rename(cleaner.document(event), mapping) for event in mixed]
    clean_truth = _rename(cleaner.document(records), mapping)
    clean_ticket = _clean_ticket(ticket, cleaner, mapping) if ticket is not None else None
    teach = dict(TEACH[lang])
    teach["techniques"] = _teach_entries(records, rules)
    if blind:
        # The teaching block survives so the debrief can name the blind spot,
        # but the scenario itself must not claim an event is an attack.
        clean_events = [{**event, "label": "benign"} for event in clean_events]
        clean_truth = []
        side_effect_ids = []
    document = {
        "id": scenario_id(clean_events, clean_truth),
        "lang": lang,
        "events": clean_events,
        "truth": clean_truth,
        "side_effect_ids": side_effect_ids,
        "excluded": {"outside_session": outside, "untied_injector": len(dropped),
                     "not_allowlisted": not_allowed,
                     "noise_injector": noise_injector,
                     "noise_in_window": noise_in_window,
                     "noise_not_allowlisted": noise_not_allowed},
        "teach": teach,
        "limits": LIMITS[lang],
    }
    if clean_ticket is not None:
        document["ticket"] = clean_ticket
    return document
