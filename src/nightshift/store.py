"""Append-only JSONL store.

JSONL keeps the record greppable with the tools an analyst already uses
(jq, grep, less) and avoids a database before there is anything to query.
"""
import json
import os
from pathlib import Path

from .schema import Event


class EventStore:
    def __init__(self, path: Path):
        self.path = path

    def existing_ids(self) -> set[str]:
        if not self.path.exists():
            return set()
        ids = set()
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    ids.add(json.loads(line)["id"])
        return ids

    def append(self, events) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with self.path.open("a", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                written += 1
            fh.flush()
            os.fsync(fh.fileno())  # the cursor is advanced only after this returns
        return written

    def append_new(self, events) -> int:
        """Write only events whose id is not already in the file."""
        known = self.existing_ids()
        return self.append(e for e in events if e.id not in known)
