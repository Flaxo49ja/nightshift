"""Cursor persistence.

Order at the call site is append-then-save: a crash may duplicate an event
(dedupe removes it) but never drops one. A lost cursor must not lose data.
"""
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Cursor:
    provider: str
    cursor: str
    saved_at: str      # RFC3339 UTC, used as the fallback anchor if the cursor is vacuumed
    host: str


class CursorFile:
    def __init__(self, path: Path):
        self.path = path

    def load(self, provider: str) -> Cursor | None:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if data.get("provider") != provider:
            return None  # a different provider's position means nothing here
        try:
            return Cursor(
                provider=data["provider"], cursor=data["cursor"],
                saved_at=data["saved_at"], host=data["host"],
            )
        except KeyError:
            return None

    def save(self, cursor: Cursor) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(cursor), indent=2) + "\n")
        os.replace(tmp, self.path)  # atomic: half a cursor is worse than none
