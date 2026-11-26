"""The scorecard: detections versus ground truth, with the gaps kept honest.

Four numbers matter, and each has a way of lying:

* **recall** — "did we catch what we injected?" A miss is only a miss if the
  provider could have seen it *and* the simulation actually emitted something.
  `coverage.py` decides the first part; the injector's `observed` count decides
  the second. A `sudo -n` attempt that logs nothing is a telemetry fact, not a
  detection failure.
* **precision** — "did we invent alerts?" Any detection that lines up with no
  injection is a false positive, even if it looks plausible.
* **unscored** — techniques where telemetry does not exist. Reported as
  `no telemetry`, never as 0% recall.
* **unobserved** — techniques this host could record in principle but did not
  record for this simulation. Reported separately, because they say something
  about the simulation, not about the rule.

A detection matches ground truth when the technique agrees and the windows
overlap, allowing `SLACK` seconds: journald writes asynchronously, so a `sudo`
call at 12:00:00.100 can appear at 12:00:00.400.

Two kinds of detection are neither catches nor false positives, and counting
them as either is how a scorecard starts lying:

* **out of session** — older than the injection window. The technique may well
  have run (a probe from a previous session), but this experiment did not
  observe it, so it is not evidence either way. Still listed.
* **repeat** — the same technique, inside the same injection window, already
  caught by another rule. One `systemd-run` writes both a unit-started and a
  unit-finished entry; two detections for one injection is one catch and one
  duplicate, not one catch and one false alarm.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .coverage import visibility
from .schema import parse_ts

SLACK = timedelta(seconds=300)


@dataclass
class TechniqueScore:
    technique: str
    injected: int = 0
    detected: int = 0
    visibility: str = "unknown"
    scored: bool = True
    unscored: int = 0        # no telemetry possible: never a miss
    unobserved: int = 0      # ran, but produced no event on this host
    note: str = ""
    # Mean seconds from injection start to the scan that produced the first
    # catch, and to the journal line it was built from. MTTD is the former.
    mttd: float | None = None
    time_to_evidence: float | None = None

    @property
    def missed(self) -> int:
        return max(self.injected - self.detected, 0)


@dataclass
class Scorecard:
    rows: list[TechniqueScore] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    out_of_session: list[dict] = field(default_factory=list)
    repeats: list[dict] = field(default_factory=list)
    window: tuple[datetime, datetime] | None = None
    # (technique, variant) -> {"injected": n, "caught": n, "rules": [...]}. Two
    # variants of one technique stay one technique; this says which shape was
    # caught and by which rule, so "the rule works" cannot mean "one of the
    # rules happens to fire".
    variants: dict[tuple[str, str], dict] = field(default_factory=dict)

    @property
    def scored_rows(self) -> list[TechniqueScore]:
        return [r for r in self.rows if r.scored and r.injected]

    @property
    def true_positives(self) -> int:
        return sum(r.detected for r in self.scored_rows)

    @property
    def false_negatives(self) -> int:
        return sum(r.missed for r in self.scored_rows)

    @property
    def precision(self) -> float | None:
        total = self.true_positives + len(self.false_positives)
        return None if total == 0 else self.true_positives / total

    @property
    def recall(self) -> float | None:
        total = self.true_positives + self.false_negatives
        return None if total == 0 else self.true_positives / total


def _overlaps(detection: dict, truth: dict) -> bool:
    start = parse_ts(truth["started"]) - SLACK
    end = parse_ts(truth["ended"]) + SLACK
    return parse_ts(detection["ts_last"]) >= start and parse_ts(detection["ts_first"]) <= end


def session_window(measures: list[dict]) -> tuple[datetime, datetime] | None:
    """The span this experiment covers: first injection to last, plus `SLACK`."""
    if not measures:
        return None
    start = min(parse_ts(item["started"]) for item in measures) - SLACK
    end = max(parse_ts(item["ended"]) for item in measures) + SLACK
    return start, end


def _in_window(detection: dict, window: tuple[datetime, datetime] | None) -> bool:
    if window is None:
        return True
    start, end = window
    return parse_ts(detection["ts_last"]) >= start and parse_ts(detection["ts_first"]) <= end


def score(truth: list[dict], detections: list[dict],
          provider: str = "journald") -> Scorecard:
    measures = [t for t in truth if t.get("status") == "ran"]
    skipped = [t for t in truth if t.get("status") != "ran"]
    window = session_window(measures)
    out_of_session = [d for d in detections if not _in_window(d, window)]
    detections = [d for d in detections if _in_window(d, window)]
    matched: set[str] = set()
    by_technique: dict[str, TechniqueScore] = {}
    variants: dict[tuple[str, str], dict] = {}
    latencies: dict[str, list[float]] = {}
    evidence: dict[str, list[float]] = {}

    for item in measures:
        technique = item["technique"]
        video = visibility(technique, provider)
        row = by_technique.setdefault(technique, TechniqueScore(
            technique=technique, visibility=video,
            scored=video == "observed",
            note="" if video == "observed" else video,
        ))
        if video != "observed":
            row.unscored += 1
            continue
        if item.get("observed") == 0:
            row.unobserved += 1
            row.note = "no event recorded for this simulation"
            continue
        row.injected += 1
        bucket = variants.setdefault((technique, str(item.get("variant") or "default")),
                                     {"injected": 0, "caught": 0, "rules": []})
        bucket["injected"] += 1
        for detection in detections:
            if detection.get("technique") != technique or detection["id"] in matched:
                continue
            if _overlaps(detection, item):
                matched.add(detection["id"])
                row.detected += 1
                bucket["caught"] += 1
                bucket["rules"].append(detection["rule_id"])
                started = parse_ts(item["started"])
                evidence.setdefault(technique, []).append(
                    (parse_ts(detection["ts_first"]) - started).total_seconds())
                # No detected_at means an old detection file; MTTD stays
                # undefined rather than being invented from ts_first.
                if detection.get("detected_at"):
                    latencies.setdefault(technique, []).append(
                        (parse_ts(detection["detected_at"]) - started).total_seconds())
                break

    for technique, samples in evidence.items():
        by_technique[technique].time_to_evidence = sum(samples) / len(samples)
    for technique, samples in latencies.items():
        by_technique[technique].mttd = sum(samples) / len(samples)

    unmatched = [d for d in detections if d["id"] not in matched]
    # A second detection of a technique that was injected in this window is the
    # same event seen twice, not an invented alert. Anything else is a false
    # positive, including a plausible detection of the wrong technique. Only a
    # simulation that could be caught counts: a blind spot has no telemetry
    # and an unobserved run produced nothing, so neither was already caught.
    catchable = [item for item in measures
                 if visibility(item["technique"], provider) == "observed"
                 and item.get("observed") != 0]
    repeats = [
        d for d in unmatched
        if any(d.get("technique") == item["technique"] and _overlaps(d, item)
               for item in catchable)
    ]
    repeat_ids = {d["id"] for d in repeats}

    return Scorecard(
        rows=sorted(by_technique.values(), key=lambda r: r.technique),
        false_positives=[d for d in unmatched if d["id"] not in repeat_ids],
        skipped=skipped,
        out_of_session=out_of_session,
        repeats=repeats,
        window=window,
        variants=variants,
    )


def render(card: Scorecard, provider: str = "journald") -> str:
    lines = [f"nightshift score — provider {provider}", ""]
    lines.append(f"  {'TECH':<10}{'VISIBILITY':<14}{'INJECTED':>9}{'CAUGHT':>8}"
                 f"{'MISSED':>8}{'MTTD':>9}{'EVIDENCE':>10}")
    for row in card.rows:
        tail = ""
        if not row.scored:
            tail = "   not scored: no telemetry"
        elif row.unobserved and not row.injected:
            tail = "   not scored: nothing observed"
        mttd = f"{row.mttd:.1f}s" if row.mttd is not None else "—"
        evidence = f"{row.time_to_evidence:.1f}s" if row.time_to_evidence is not None else "—"
        lines.append(f"  {row.technique:<10}{row.visibility:<14}{row.injected:>9}"
                     f"{row.detected:>8}{row.missed:>8}{mttd:>9}{evidence:>10}{tail}")
    if not card.rows:
        lines.append("  no injected techniques recorded — run `nightshift inject` first")

    per_technique: dict[str, list[tuple[str, dict]]] = {}
    for (technique, variant), counts in card.variants.items():
        per_technique.setdefault(technique, []).append((variant, counts))
    for technique, parts in sorted(per_technique.items()):
        if len(parts) > 1:
            detail = ", ".join(f"{variant} {counts['caught']}/{counts['injected']}"
                               + (f" ({', '.join(sorted(set(counts['rules']))) })"
                                  if counts.get("rules") else "")
                               for variant, counts in sorted(parts))
            lines.append(f"  {technique} variants: {detail}")

    for item in card.skipped:
        lines.append(f"  skipped {item['technique']}: {item.get('reason') or 'not run'}")

    lines.append("")
    if any(r.mttd is not None for r in card.rows):
        lines.append("  MTTD = injection start → the scan that caught it (includes collect + scan time)")
        lines.append("  EVIDENCE = injection start → the journal line the detection was built from")
        lines.append("")
    scored = card.scored_rows
    if scored:
        lines.append(f"  recall     {(card.recall or 0):.0%}  ({card.true_positives} caught, "
                     f"{card.false_negatives} missed, {len(scored)} scored technique(s))")
        # Precision is undefined when nothing was predicted. "0%" with zero
        # false positives reads as a failure where the truth is "not measured".
        if card.precision is None:
            lines.append("  precision  n/a  (no detections at all)")
        else:
            lines.append(f"  precision  {card.precision:.0%}  "
                         f"({len(card.false_positives)} false positive(s))")
    else:
        lines.append("  nothing was scored: no injected technique produced observable telemetry")

    blind = [r for r in card.rows if not r.scored]
    if blind:
        lines.append("  no telemetry, not a miss: "
                     + ", ".join(f"{r.technique} ({r.note})" for r in blind))
    silent = [r for r in card.rows if r.scored and r.unobserved]
    if silent:
        lines.append("  ran but recorded nothing (simulation limit, not a detection miss): "
                     + ", ".join(r.technique for r in silent))

    if card.out_of_session or card.repeats:
        lines.append("")
        parts = []
        if card.out_of_session:
            parts.append(f"{len(card.out_of_session)} before the injection window")
        if card.repeats:
            parts.append(f"{len(card.repeats)} same technique already caught in the window")
        lines.append("  out of scope, not counted: " + "; ".join(parts))
        for detection in (card.out_of_session + card.repeats)[:10]:
            lines.append(f"    {detection['ts_first']}  {detection.get('rule_id')}"
                         f"  key={detection.get('key')}")

    if card.false_positives:
        lines.append("")
        lines.append("  false positives:")
        for detection in card.false_positives[:10]:
            lines.append(f"    {detection['ts_first']}  {detection.get('severity', '?'):<8}"
                         f"{detection.get('rule_id')}  key={detection.get('key')}")
        if len(card.false_positives) > 10:
            lines.append(f"    … and {len(card.false_positives) - 10} more")
    return "\n".join(lines)
