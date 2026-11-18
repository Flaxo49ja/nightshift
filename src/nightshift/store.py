"""Append-only JSONL store.

JSONL keeps the record greppable with the tools an analyst already uses
(jq, grep, less) and avoids a database before there is anything to query.
"""
import json
import os
import sys
from pathlib import Path

from .schema import Event


def read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file, skipping blank and unparseable lines.

    A truncated final line is normal after a crash, so one bad line must not
    discard a whole shift's telemetry. It is still telemetry lost, though, so
    say how much on stderr rather than letting the count quietly shrink.
    """
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    bad = 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    if bad:
        print(f"warning: {path}: skipped {bad} unreadable line(s)", file=sys.stderr)
    return rows


def append_jsonl(path: Path, rows, key: str = "id") -> int:
    """Append rows whose `key` is not already present. Returns the count written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    known = {row.get(key) for row in read_jsonl(path)}
    written = 0
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            if row.get(key) in known:
                continue
            known.add(row.get(key))
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            written += 1
        fh.flush()
        os.fsync(fh.fileno())
    return written


class EventStore:
    def __init__(self, path: Path):
        self.path = path

    def existing_ids(self) -> set[str]:
        """Ids already stored. A torn final line must not stop collection."""
        if not self.path.exists():
            return set()
        ids = set()
        bad = 0
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if isinstance(row, dict) and "id" in row:
                    ids.add(row["id"])
        if bad:
            print(f"warning: {self.path}: skipped {bad} unreadable line(s)", file=sys.stderr)
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
