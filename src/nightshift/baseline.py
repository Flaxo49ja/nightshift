"""How noisy is a quiet day?

Baseline is the scorecard's opposite: no truth file, no injection window, no
matching. It applies the same rules to events the host produced on its own and
reports alerts per hour per rule, so a rule that fires all day can be seen for
what it is before it is credited with a detection.

The window is the last N hours *of the store*, not of wall-clock time: a store
collected yesterday and scored today should still describe yesterday. Feed it a
collection made when nothing was injected — an injection session inside the
window becomes baseline noise and makes the number meaningless.
"""
from collections import Counter
from datetime import timedelta

from .rules import evaluate
from .schema import parse_ts


def measure(events: list[dict], rules, hours: float = 24.0) -> dict:
    if not events:
        return {"start": None, "end": None, "hours": hours,
                "events": 0, "rows": [], "total": 0}
    end = max(parse_ts(event["ts"]) for event in events)
    start = end - timedelta(hours=hours)
    selected = [event for event in events
                if start <= parse_ts(event["ts"]) <= end]
    detections = evaluate(selected, rules)
    counts = Counter(d["rule_id"] for d in detections)
    rows = [{"rule_id": rule_id, "alerts": count, "per_hour": count / hours}
            for rule_id, count in sorted(counts.items())]
    return {"start": start, "end": end, "hours": hours,
            "events": len(selected), "rows": rows, "total": len(detections)}


def render(result: dict, provider: str = "journald") -> str:
    lines = [f"nightshift baseline — provider {provider}"]
    if result["start"] is None:
        return "\n".join(lines + ["  no events collected — nothing to baseline"])
    lines.append(f"  {result['events']} event(s) over {result['hours']:g} h "
                 f"({result['start'].isoformat(timespec='seconds')} → "
                 f"{result['end'].isoformat(timespec='seconds')})")
    if not result["rows"]:
        lines.append("  no rule fired — a quiet window, which is the useful case")
    else:
        lines.append(f"  {'ALERTS/H':>10}{'ALERTS':>8}  RULE")
        for row in result["rows"]:
            lines.append(f"  {row['per_hour']:>10.2f}{row['alerts']:>8}  {row['rule_id']}")
        lines.append(f"  total {result['total']} alert(s) in {result['hours']:g} h "
                     f"({result['total'] / result['hours']:.2f}/h)")
    lines.append("  no injections were run or consulted; this is host noise only")
    lines.append("  use a quiet day collected separately from any injection session — "
                 "an injection inside the window is noise, not a baseline")
    return "\n".join(lines)
