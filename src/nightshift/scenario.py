"""Export a scored session as a shareable, sanitized triage scenario.

The export exists so one person's real box can become another person's
exercise without leaking the first person's identifiers. Two rules make that
true rather than aspirational:

* **Deny by substitution.** The exporter does not look for "sensitive-looking"
  strings; it replaces the machine's own hostname, username and home path, and
  every IP address it finds, including inside free text. What is left cannot be
  a real identifier because the real identifiers were removed by value.
* **One document, answer key included.** `truth` is in the same file as
  `events`, so a scenario is self-contained and scoreable offline. That also
  means an exported scenario is a spoiler: share it after the exercise, not
  before.

Documentation ranges are used for addresses (192.0.2.0/24) and fixed names for
identity (`ws-01`, `analyst`), which is what RFC 5737 and every style guide
already reserve for examples.
"""
import getpass
import hashlib
import json
import platform
import re
import socket
from pathlib import Path

DOC_HOST = "ws-01"
DOC_USER = "analyst"
DOC_HOME = "/home/analyst"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Loosely matched on purpose; `_scrub_v6` then rejects clock times. A time
# like 05:04:11 has two colons and no `::`, an address does not.
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w:])")
DOC_NET = "192.0.2."

TEACH = {
    "en": {
        "title": "What happened on ws-01?",
        "prompt": "Read the events, decide which technique was simulated, and say "
                  "which rule should have caught it before opening the answer key.",
        "hints": [
            "Start from the unit, user and process fields; the message is free text.",
            "A detection is only a catch if it lands after the injection started.",
            "The truth records say what ran, not what was detected: no `observed` means "
            "the simulation was not checked against telemetry.",
        ],
    },
    "pt": {
        "title": "O que aconteceu na ws-01?",
        "prompt": "Leia os eventos, decida qual técnica foi simulada e diga qual regra "
                  "deveria tê-la detectado antes de abrir o gabarito.",
        "hints": [
            "Comece pelos campos unit, user e process; a mensagem é texto livre.",
            "Uma detecção só conta se ocorrer depois do início da injeção.",
            "Os registros de verdade dizem o que rodou, não o que foi detectado.",
        ],
    },
}

LIMITS = {
    "en": [
        "Sanitized: hostnames, usernames and home paths are replaced, and every IP "
        "address is mapped into 192.0.2.0/24. Timestamps are real.",
        "The answer key is in this file. It is a scenario, not a quiz you can take blind.",
        "Only what the exporter's providers could see is here; a technique with no "
        "telemetry appears in truth with an empty event set.",
    ],
    "pt": [
        "Sanitizado: nomes de host, usuários e caminhos pessoais foram substituídos, e "
        "todo endereço IP foi mapeado para 192.0.2.0/24. Os horários são reais.",
        "O gabarito está neste arquivo. É um cenário, não um teste às cegas.",
        "Só está aqui o que os provedores conseguiam ver; uma técnica sem telemetria "
        "aparece na verdade com zero eventos.",
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

    def address(self, ip: str) -> str:
        if ip not in self._ips:
            self._ips[ip] = f"{DOC_NET}{len(self._ips) + 1}"
        return self._ips[ip]

    def text(self, value: str) -> str:
        out = value.replace(self.home, DOC_HOME)
        for name in self.hostnames:
            out = out.replace(name, DOC_HOST)
        for name in self.usernames:
            out = out.replace(name, DOC_USER)
        out = IPV4.sub(lambda m: self.address(m.group()), out)
        return IPV6.sub(self._scrub_v6, out)

    def _scrub_v6(self, match: re.Match) -> str:
        token = match.group()
        if "::" not in token and token.count(":") < 3:
            return token            # a clock time, not an address
        return self.address(token)

    def document(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.document(item) for item in value]
        if isinstance(value, dict):
            return {key: self.document(item) for key, item in value.items()}
        return value


def scenario_id(events: list[dict], truth: list[dict]) -> str:
    canonical = json.dumps({"events": events, "truth": truth}, sort_keys=True,
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def export(events: list[dict], truth: list[dict], lang: str = "en",
           sanitizer: Sanitizer | None = None) -> dict:
    """Build the scenario document. Pure: same input, same id, no clock."""
    if lang not in TEACH:
        raise ValueError(f"unknown language {lang!r} (choose from {', '.join(TEACH)})")
    cleaner = sanitizer or Sanitizer()
    clean_events = [cleaner.document(event) for event in events]
    clean_truth = [cleaner.document(record) for record in truth]
    return {
        "id": scenario_id(clean_events, clean_truth),
        "lang": lang,
        "events": clean_events,
        "truth": clean_truth,
        "teach": TEACH[lang],
        "limits": LIMITS[lang],
    }
