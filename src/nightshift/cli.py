"""CLI entry point.

Every command is one step of a shift, in the order you would actually work:

    collect -> scan -> shift -> inject -> score

`collect` brings in telemetry, `scan` applies the rules, `shift` is where you
triage, `inject` creates ground truth, and `score` judges the detections against
it. Nothing runs before it can be tested, and nothing changes system state
except the documented, reversible simulations in `inject`.
"""
import argparse
import json
import os
import platform
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import inject as inject_mod
from .baseline import measure as measure_baseline
from .baseline import render as render_baseline
from .coverage import observed as observed_techniques
from .cursor import Cursor, CursorFile
from .providers.base import CursorInvalid
from .providers.journald import DEFAULT_SOURCES, JournaldProvider
from .queue import STATUSES, TriageQueue, resolve
from .report import render as render_coverage
from .rules import RuleError, evaluate, load_rules
from .scenario import export as export_scenario_doc
from .schema import parse_ts
from .score import render as render_score
from .score import score as score_detections
from .store import EventStore, append_jsonl, read_jsonl

DEFAULT_WINDOW = timedelta(days=7)


def default_state_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "nightshift"


def default_rules_dir() -> Path:
    """`rules/` next to the package in a source checkout, else the CWD."""
    repo = Path(__file__).resolve().parents[2] / "rules"
    return repo if repo.is_dir() else Path.cwd() / "rules"


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
        description="A single-machine SOC practice range: collect, detect, triage, score.",
    )
    parser.add_argument("--version", action="version", version="nightshift 0.2.0")
    sub = parser.add_subparsers(dest="command", required=True)

    collect_cmd = sub.add_parser("collect", help="append new events to the store")
    collect_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    collect_cmd.add_argument("--provider", choices=("journald", "auditd"), default="journald")
    collect_cmd.add_argument("--file", type=Path, default=None,
                             help="auditd log to read (default: /var/log/audit/audit.log)")
    collect_cmd.add_argument("--all", action="store_true",
                             help="collect every identifier, not just the security allowlist")
    collect_cmd.add_argument("--since", default=None,
                             help="first-run window: 7d, 24h, 45m or ISO8601 (default: 7d)")

    scan_cmd = sub.add_parser("scan", help="apply detection rules to stored events")
    scan_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    scan_cmd.add_argument("--rules", type=Path, default=default_rules_dir())

    shift_cmd = sub.add_parser("shift", help="work the triage queue")
    shift_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    shift_cmd.add_argument("--all", action="store_true",
                           help="include dismissed detections")
    shift_cmd.add_argument("--confirm", metavar="ID", default=None)
    shift_cmd.add_argument("--dismiss", metavar="ID", default=None)
    shift_cmd.add_argument("--note", default="")

    inject_cmd = sub.add_parser("inject", help="run safe technique simulations")
    inject_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    inject_cmd.add_argument("--technique", action="append", choices=sorted(inject_mod.TECHNIQUES),
                            help="repeatable; default is every technique")
    inject_cmd.add_argument("--blind", action="store_true",
                            help="record ground truth without printing which technique ran")
    inject_cmd.add_argument("--no-verify", action="store_true",
                            help="skip the post-run journal check")

    score_cmd = sub.add_parser("score", help="compare detections against injected truth")
    score_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    score_cmd.add_argument("--truth", type=Path, default=None,
                           help="ground-truth file (default: <state-dir>/truth.jsonl)")

    demo_cmd = sub.add_parser("demo", help="run the whole loop in a throwaway state dir")
    demo_cmd.add_argument("--since", default="1h",
                          help="first collect window (default: 1h)")

    export_cmd = sub.add_parser("export-scenario",
                                help="write a sanitized, self-contained scenario")
    export_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    export_cmd.add_argument("--out", type=Path, required=True,
                            help="scenario JSON to write")
    export_cmd.add_argument("--lang", choices=("en", "pt"), default="en")
    export_cmd.add_argument("--noise", type=Path, default=None,
                            help="events.jsonl from a separate quiet collection, "
                                 "mixed in as benign background")
    export_cmd.add_argument("--rules", type=Path, default=default_rules_dir())
    export_cmd.add_argument("--max-events", type=int, default=20,
                            help="total events to keep, evidence and side effects "
                                 "always included (default 20)")
    export_cmd.add_argument("--seed", type=int, default=0,
                            help="breaks distance ties among background events (default 0)")
    export_cmd.add_argument("--blind", action="store_true",
                            help="omit truth and attack labels for a blind-spot night")
    export_cmd.add_argument("--ticket-title", default=None,
                            help="ticket title; requires the other ticket flags")
    export_cmd.add_argument("--severity", choices=("low", "medium", "high", "critical"),
                            default=None, help="ticket severity")
    export_cmd.add_argument("--reported-by", default=None,
                            help="ticket reporter name")
    export_cmd.add_argument("--story", default=None,
                            help="ticket customer story")
    export_cmd.add_argument("--expected-action",
                            choices=("close_benign", "escalate", "need_more_data"),
                            default=None, help="decision the ticket should receive")

    baseline_cmd = sub.add_parser("baseline",
                                  help="alerts per hour per rule, with no injections")
    baseline_cmd.add_argument("--state-dir", type=Path, default=default_state_dir())
    baseline_cmd.add_argument("--hours", type=float, default=24.0,
                              help="window to measure, ending at the newest event (default 24)")
    baseline_cmd.add_argument("--rules", type=Path, default=default_rules_dir())

    coverage_cmd = sub.add_parser("coverage", help="ATT&CK visibility report")
    coverage_cmd.add_argument("--provider", choices=("journald", "auditd"), default="journald")
    coverage_cmd.add_argument("--rules", type=Path, default=default_rules_dir())
    return parser


def _make_provider(args):
    if getattr(args, "provider", "journald") == "auditd":
        from .providers.auditd import AUDIT_LOG, AuditdProvider

        return AuditdProvider(Path(getattr(args, "file", None) or AUDIT_LOG))
    return JournaldProvider()


def collect(args, provider=None) -> int:
    provider = provider or _make_provider(args)
    state_dir: Path = args.state_dir
    store = EventStore(state_dir / "events.jsonl")
    cursors = CursorFile(state_dir / "cursor.json")
    # A provider that does not declare an allowlist keeps the journald default;
    # auditd declares None because every audit record is security relevant.
    allowlist = (None if getattr(args, "all", False)
                 else getattr(provider, "allowlist", DEFAULT_SOURCES))

    saved = cursors.load(provider.name)
    since = None if saved else parse_since(getattr(args, "since", None))
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
        if allowlist is not None and source not in allowlist:
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

    last_cursor = entries[-1].get("__CURSOR") if entries and isinstance(entries[-1], dict) else None
    if provider.name == "auditd" and entries:
        last_cursor = entries[-1][0]["serial"]
    if last_cursor:
        cursors.save(Cursor(
            provider=provider.name, cursor=str(last_cursor),
            saved_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            host=platform.node() or "unknown",
        ))

    print(f"nightshift collect — {provider.name}")
    if saved is None:
        window = "last 7 days" if getattr(args, "since", None) is None else args.since
        print(f"  window: {window} (first run; override with --since)")
    if gap:
        print(f"  telemetry gap: {gap[0]} → {gap[1]} (source rotated; restarted from saved_at)")
    print(f"  {written} new events ({duplicates} duplicates, {sum(dropped.values())} filtered, "
          f"{malformed} malformed)")
    if dropped:
        # one identifier per line: you asked to see exactly what is discarded,
        # and a 70-item single line is unreadable
        print("  dropped (set --all to keep any of these):")
        for name, count in dropped.most_common():
            print(f"    {name} {count}")
    if last_cursor:
        print(f"  cursor: {str(last_cursor)[:12]}…")
    return 0


def scan(args) -> int:
    state_dir: Path = args.state_dir
    events = read_jsonl(state_dir / "events.jsonl")
    rules = load_rules(args.rules)
    detections = evaluate(events, rules)
    written = append_jsonl(state_dir / "detections.jsonl", detections)
    print(f"nightshift scan — {len(rules)} rule(s) over {len(events)} event(s)")
    print(f"  {written} new detection(s) ({len(detections) - written} already seen)")
    counts = Counter(d["severity"] for d in detections)
    if counts:
        order = ("critical", "high", "medium", "low")
        print("  by severity: " + ", ".join(f"{s} {counts[s]}" for s in order if counts[s]))
    if not rules:
        print("  warning: no rules loaded — check --rules")
    return 0


def shift(args) -> int:
    state_dir: Path = args.state_dir
    detections = read_jsonl(state_dir / "detections.jsonl")
    queue = TriageQueue(state_dir / "queue.json")
    rows = queue.entries(detections)

    # A note belongs to a decision. Accepting one on its own would print the
    # queue and exit 0 while recording nothing, which reads like success.
    if args.note and not (args.confirm or args.dismiss):
        print("error: --note needs --confirm ID or --dismiss ID", file=sys.stderr)
        return 2

    for action in ("confirm", "dismiss"):
        target = getattr(args, action, None)
        if not target:
            continue
        try:
            row = resolve(target, rows)
        except KeyError as exc:
            print(f"error: {exc.args[0]}", file=sys.stderr)
            return 2
        status = "confirmed" if action == "confirm" else "dismissed"
        queue.set_status(row["id"], status, args.note)
        print(f"  {row['id']} {status}" + (f" — {args.note}" if args.note else ""))
        rows = queue.entries(detections)

    visible = rows if args.all else [r for r in rows if r["status"] != "dismissed"]
    totals = queue.counts(detections)
    print(f"nightshift shift — {len(visible)} to look at "
          f"({totals['new']} new, {totals['confirmed']} confirmed, "
          f"{totals['dismissed']} dismissed)")
    if not visible:
        print("  queue is clear — `nightshift collect` then `nightshift scan`")
        return 0
    print(f"  {'ID':<18}{'WHEN':<22}{'SEV':<9}{'RULE':<26}{'KEY':<18}STATUS")
    for row in visible:
        print(f"  {row['id']:<18}{row['ts_first'][:19]:<22}{row['severity']:<9}"
              f"{row['rule_id'][:25]:<26}{str(row['key'] or '—')[:17]:<18}{row['status']}")
        print(f"    {row['title']}  ×{row['count']}")
    return 0


def _verify_observed(records: list[dict]) -> None:
    """Ask the journal what each simulation actually produced.

    This is the difference between "the rule missed it" and "the simulation
    emitted nothing", and those two want different fixes.
    """
    provider = JournaldProvider()
    for record in records:
        if record.get("status") != "ran":
            continue
        start = parse_ts(record["started"])
        try:
            entries = provider.fetch(None, start - timedelta(seconds=2))
        except (RuntimeError, OSError):
            return                      # no journal access: leave `observed` unset
        events = []
        for entry in entries:
            event = provider.normalize(entry)
            if event:
                events.append(event.to_dict())
        # Same ownership rule the exporter uses, so truth.event_ids and
        # `observed` always agree.
        record["observed"] = len(inject_mod.evidence(record, events))


def inject(args) -> int:
    state_dir: Path = args.state_dir
    truth_path = state_dir / "truth.jsonl"
    records = inject_mod.run(
        techniques=args.technique, truth_path=None, blind=args.blind,
    )
    if not args.no_verify:
        _verify_observed(records)
    inject_mod.write_truth(records, truth_path, args.blind)

    print("nightshift inject — safe simulations (loopback or local only)")
    if args.blind:
        print(f"  {len(records)} simulation(s) recorded; technique names withheld")
        print(f"  ground truth: {truth_path} (mode 0600 — reading it is a choice)")
    else:
        for record in records:
            seen = record.get("observed")
            marker = "" if seen is None else f", {seen} event(s) in the journal"
            print(f"  {record['technique']:<10}{record['status']:<8}{record['title']}{marker}")
            if record.get("reason"):
                print(f"    {record['reason']}")
    ran = sum(1 for r in records if r["status"] == "ran")
    print(f"  {ran}/{len(records)} ran; truth appended to {truth_path}")
    print("  next: `nightshift collect`, `nightshift scan`, then `nightshift score`")
    return 0


def score(args) -> int:
    state_dir: Path = args.state_dir
    truth_path = args.truth or (state_dir / "truth.jsonl")
    truth = read_jsonl(truth_path)
    detections = read_jsonl(state_dir / "detections.jsonl")
    if not truth:
        print(f"error: no ground truth at {truth_path} — run `nightshift inject` first",
              file=sys.stderr)
        return 1
    card = score_detections(truth, detections)
    print(render_score(card))
    return 0


def export_scenario(args) -> int:
    events = read_jsonl(args.state_dir / "events.jsonl")
    truth = read_jsonl(args.state_dir / "truth.jsonl")
    if not events:
        print(f"error: no events in {args.state_dir} — run `nightshift collect` first",
              file=sys.stderr)
        return 1
    if not truth:
        print("warning: no ground truth — the export will have no answer key",
              file=sys.stderr)
    detections = read_jsonl(args.state_dir / "detections.jsonl")
    noise = read_jsonl(args.noise) if args.noise else []
    ticket_values = {
        "title": args.ticket_title,
        "severity": args.severity,
        "reported_by": args.reported_by,
        "customer_story": args.story,
        "expected_action": args.expected_action,
    }
    supplied = [name for name, value in ticket_values.items() if value is not None]
    if supplied and len(supplied) != len(ticket_values):
        missing = [name for name, value in ticket_values.items()
                   if value is None and name not in supplied]
        raise ValueError("ticket export needs all five flags; missing " + ", ".join(missing))
    ticket = ticket_values if supplied else None
    document = export_scenario_doc(events, truth, lang=args.lang,
                                   detections=detections, noise=noise,
                                   rules=load_rules(args.rules),
                                   max_events=args.max_events, seed=args.seed,
                                   blind=args.blind, ticket=ticket)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(f"nightshift export-scenario — {len(document['events'])} event(s), "
          f"{len(document['truth'])} truth record(s)")
    print(f"  id {document['id']}  lang {document['lang']}")
    excluded = document["excluded"]
    print(f"  excluded {excluded['outside_session']} event(s) outside this session, "
          f"{excluded['untied_injector']} untied injector line(s), "
          f"{excluded['not_allowlisted']} non-allowlisted background line(s)")
    if args.noise:
        print(f"  noise excluded {excluded['noise_injector']} injector line(s), "
              f"{excluded['noise_in_window']} inside a truth window, "
              f"{excluded['noise_not_allowlisted']} non-allowlisted line(s)")
    if args.blind:
        print("  blind: truth and attack labels omitted")
    print(f"  written to {args.out}")
    return 0


def demo(args) -> int:
    """The shift, end to end, in a directory nobody cares about.

    Every step is the same function the real subcommand calls, so the demo
    cannot drift from the pipeline it is demonstrating.
    """
    state_dir = Path(tempfile.mkdtemp(prefix="nightshift-demo-"))
    rules = default_rules_dir()
    print(f"nightshift demo — throwaway range at {state_dir}")
    print("  your real store is untouched; injection is loopback/local only")

    steps = (
        ("collect", lambda: collect(argparse.Namespace(
            state_dir=state_dir, provider="journald", file=None, all=False,
            since=args.since))),
        ("scan", lambda: scan(argparse.Namespace(state_dir=state_dir, rules=rules))),
        ("inject", lambda: inject(argparse.Namespace(
            state_dir=state_dir, technique=None, blind=False, no_verify=False))),
        ("collect", lambda: collect(argparse.Namespace(
            state_dir=state_dir, provider="journald", file=None, all=False,
            since=None))),
        ("scan", lambda: scan(argparse.Namespace(state_dir=state_dir, rules=rules))),
        ("score", lambda: score(argparse.Namespace(state_dir=state_dir, truth=None))),
    )
    for index, (name, step) in enumerate(steps, 1):
        print(f"\n  ── {index}/{len(steps)} {name} " + "─" * 46)
        code = step()
        if code:
            print(f"\ndemo stopped at `{name}` (exit {code}); nothing was changed",
                  file=sys.stderr)
            return code

    print(f"\n  that is the whole loop. inspect it: ls {state_dir}")
    print(f"  work the queue: nightshift shift --state-dir {state_dir}")
    print(f"  remove it:      rm -rf {state_dir}")
    return 0


def baseline(args) -> int:
    events = read_jsonl(args.state_dir / "events.jsonl")
    if not events:
        print(f"error: no events in {args.state_dir} — run `nightshift collect` first",
              file=sys.stderr)
        return 1
    print(render_baseline(measure_baseline(events, load_rules(args.rules), args.hours)))
    return 0


def coverage(args) -> int:
    techniques = set()
    try:
        techniques = {r.technique for r in load_rules(args.rules) if r.technique}
    except RuleError:
        pass
    print(render_coverage(args.provider, techniques))
    print(f"  {len(observed_techniques(args.provider))} visible technique(s) mapped")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            return collect(args)
        if args.command == "scan":
            return scan(args)
        if args.command == "shift":
            return shift(args)
        if args.command == "inject":
            return inject(args)
        if args.command == "score":
            return score(args)
        if args.command == "export-scenario":
            return export_scenario(args)
        if args.command == "demo":
            return demo(args)
        if args.command == "baseline":
            return baseline(args)
        if args.command == "coverage":
            return coverage(args)
    except ValueError as exc:          # bad --since, unknown technique
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:        # journalctl / audit log failed
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
