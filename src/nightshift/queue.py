"""The triage queue.

Detections are cheap to produce and expensive to read. This is the small piece
of state that turns a list into a shift: every detection is `new` until a human
says otherwise, and the note is kept because "why did I dismiss this" is the
part you forget in a week.

Status is deliberately three values, not a workflow engine.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

STATUSES = ("new", "confirmed", "dismissed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class TriageQueue:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}          # a corrupt queue must not stop triage
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)   # atomic: never a half-written queue

    def status_of(self, detection_id: str) -> dict:
        return self._load().get(detection_id, {"status": "new", "note": "", "at": None})

    def set_status(self, detection_id: str, status: str, note: str = "") -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r} (use {', '.join(STATUSES)})")
        data = self._load()
        data[detection_id] = {"status": status, "note": note, "at": _now()}
        self._save(data)

    def entries(self, detections: list[dict]) -> list[dict]:
        """Detections joined with triage state, most recent first."""
        state = self._load()
        rows = []
        for detection in detections:
            status = state.get(detection["id"], {"status": "new", "note": "", "at": None})
            rows.append({**detection, **status})
        rows.sort(key=lambda r: r["ts_first"], reverse=True)
        return rows

    def counts(self, detections: list[dict]) -> dict[str, int]:
        totals = {status: 0 for status in STATUSES}
        for row in self.entries(detections):
            totals[row["status"]] = totals.get(row["status"], 0) + 1
        return totals


def resolve(prefix: str, rows: list[dict]) -> dict:
    """Accept any unambiguous id prefix. Guessing between two alerts is worse
    than making the analyst type two more characters."""
    hits = [row for row in rows if row["id"].startswith(prefix)]
    if not hits:
        raise KeyError(f"no detection matches {prefix!r}")
    if len(hits) > 1:
        raise KeyError(f"{prefix!r} matches {len(hits)} detections; use more characters")
    return hits[0]
