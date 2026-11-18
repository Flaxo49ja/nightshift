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
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .coverage import visibility

SLACK = timedelta(seconds=300)


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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

    @property
    def missed(self) -> int:
        return max(self.injected - self.detected, 0)


@dataclass
class Scorecard:
    rows: list[TechniqueScore] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

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
    start = _ts(truth["started"]) - SLACK
    end = _ts(truth["ended"]) + SLACK
    return _ts(detection["ts_last"]) >= start and _ts(detection["ts_first"]) <= end


def score(truth: list[dict], detections: list[dict],
          provider: str = "journald") -> Scorecard:
    measures = [t for t in truth if t.get("status") == "ran"]
    skipped = [t for t in truth if t.get("status") != "ran"]
    matched: set[str] = set()
    by_technique: dict[str, TechniqueScore] = {}

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
        for detection in detections:
            if detection.get("technique") != technique or detection["id"] in matched:
                continue
            if _overlaps(detection, item):
                matched.add(detection["id"])
                row.detected += 1
                break

    return Scorecard(
        rows=sorted(by_technique.values(), key=lambda r: r.technique),
        false_positives=[d for d in detections if d["id"] not in matched],
        skipped=skipped,
    )


def render(card: Scorecard, provider: str = "journald") -> str:
    lines = [f"nightshift score — provider {provider}", ""]
    lines.append(f"  {'TECH':<10}{'VISIBILITY':<14}{'INJECTED':>9}{'CAUGHT':>8}{'MISSED':>8}")
    for row in card.rows:
        tail = ""
        if not row.scored:
            tail = "   not scored: no telemetry"
        elif row.unobserved and not row.injected:
            tail = "   not scored: nothing observed"
        lines.append(f"  {row.technique:<10}{row.visibility:<14}{row.injected:>9}"
                     f"{row.detected:>8}{row.missed:>8}{tail}")
    if not card.rows:
        lines.append("  no injected techniques recorded — run `nightshift inject` first")

    for item in card.skipped:
        lines.append(f"  skipped {item['technique']}: {item.get('reason') or 'not run'}")

    lines.append("")
    scored = card.scored_rows
    if scored:
        lines.append(f"  recall     {(card.recall or 0):.0%}  ({card.true_positives} caught, "
                     f"{card.false_negatives} missed, {len(scored)} scored technique(s))")
        lines.append(f"  precision  {(card.precision or 0):.0%}  "
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

    if card.false_positives:
        lines.append("")
        lines.append("  false positives:")
        for detection in card.false_positives[:10]:
            lines.append(f"    {detection['ts_first']}  {detection.get('severity', '?'):<8}"
                         f"{detection.get('rule_id')}  key={detection.get('key')}")
        if len(card.false_positives) > 10:
            lines.append(f"    … and {len(card.false_positives) - 10} more")
    return "\n".join(lines)
