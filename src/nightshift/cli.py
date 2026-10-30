"""CLI entry point.

Slice 1 exposes only `collect`; `shift`, `attack` and `score` arrive with
their own slices so nothing runs before it can be tested.
"""
import argparse
import json
import os
import platform
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .cursor import Cursor, CursorFile
from .providers.base import CursorInvalid
from .providers.journald import DEFAULT_SOURCES, JournaldProvider
from .store import EventStore

DEFAULT_WINDOW = timedelta(days=7)


def default_state_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "nightshift"


def parse_since(value: str | None) -> datetime:
    """`7d`, `24h`, or ISO8601. The 7-day default exists because a first run
    with no window would otherwise collect a whole journal or nothing at all."""
    now = datetime.now(timezone.utc)
    if value is None or value == "":
        return now - DEFAULT_WINDOW
    text = value.strip().lower()
    try:
        if text.endswith("d"):
            return now - timedelta(days=int(text[:-1]))
        if text.endswith("h"):
            return now - timedelta(hours=int(text[:-1]))
        if text.endswith("m"):
            return now - timedelta(minutes=int(text[:-1]))
    except ValueError as exc:
        raise ValueError(f"cannot parse window {value!r}") from exc
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"cannot parse window {value!r} (use 7d, 24h or ISO8601)") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nightshift",
        description="A single-machine SOC practice range: collect host telemetry.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect_cmd = sub.add_parser("collect", help="append new journald events to the store")
    collect_cmd.add_argument("--state-dir", type=Path, default=default_state_dir(),
                             help="where events.jsonl and cursor.json live")
    collect_cmd.add_argument("--all", action="store_true",
                             help="collect every identifier, not just the security allowlist")
    collect_cmd.add_argument("--since", default=None,
                             help="first-run window: 7d, 24h, 45m or ISO8601 (default: 7d)")
    return parser


def collect(args, provider=None) -> int:
    provider = provider or JournaldProvider()
    state_dir: Path = args.state_dir
    store = EventStore(state_dir / "events.jsonl")
    cursors = CursorFile(state_dir / "cursor.json")

    saved = cursors.load(provider.name)
    since = None if saved else parse_since(args.since)
    gap = None
    try:
        entries = provider.fetch(saved.cursor if saved else None, since)
    except CursorInvalid as exc:
        # Never resume at "now": that hides the hole instead of reporting it.
        since = datetime.fromisoformat(saved.saved_at.replace("Z", "+00:00"))
        gap = (saved.saved_at, datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print(f"warning: cursor rejected ({exc})", file=sys.stderr)
        entries = provider.fetch(None, since)

    dropped: Counter[str] = Counter()
    malformed = 0
    duplicates = 0
    fresh = []
    known = store.existing_ids()
    for entry in entries:
        source = provider.source_of(entry)
        if not args.all and source not in DEFAULT_SOURCES:
            dropped[source] += 1
            continue
        event = provider.normalize(entry)
        if event is None:
            malformed += 1
            continue
        if event.id in known:
            duplicates += 1
            continue
        known.add(event.id)
        fresh.append(event)

    written = store.append(fresh)

    last_cursor = entries[-1].get("__CURSOR") if entries else None
    if last_cursor:
        cursors.save(Cursor(
            provider=provider.name, cursor=last_cursor,
            saved_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            host=platform.node() or "unknown",
        ))

    print(f"nightshift collect — {provider.name}")
    if saved is None:
        window = "last 7 days" if args.since is None else args.since
        print(f"  window: {window} (first run; override with --since)")
    if gap:
        print(f"  telemetry gap: {gap[0]} → {gap[1]} (journal rotated; restarted from saved_at)")
    print(f"  {written} new events ({duplicates} duplicates, {sum(dropped.values())} filtered, "
          f"{malformed} malformed)")
    if dropped:
        # one identifier per line: you asked to see exactly what is discarded,
        # and a 70-item single line is unreadable
        print("  dropped (set --all to keep any of these):")
        for name, count in dropped.most_common():
            print(f"    {name} {count}")
    if last_cursor:
        print(f"  cursor: {last_cursor[:12]}…")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            return collect(args)
    except ValueError as exc:          # bad --since
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:        # journalctl failed
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
