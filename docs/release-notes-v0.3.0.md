# nightshift v0.3.0 — draft, not published

Numbers below come from the demo run at commit `3760554`: 246 tests, 2 of 2
injection variants across 1 technique caught, MTTD 7.2 s, precision 100%.

## What this release changes

**A variant is credited only to its designated rule.** Injection records carry
`expected_rules`, and a same-technique detection from any other rule is a repeat,
never a catch. Deleting `timer-unit-introduced` used to leave "2 of 2 variants
caught" true; now the unit-file variant reads 0/1 and the card shows the miss.

**Timer journal timing is documented, not papered over.** A paired run logs two
`Started [systemd-run]` lines because the transient timer and its service share
a Description. Measurements, per run, are in `docs/timer-journal-timing.md`; the
extra line is refreshed as a repeat.

**`nightshift baseline --hours N`.** Applies the rules to a store with no
injections and prints alerts per hour per rule, over the last N hours of the
store. It needs a quiet day collected separately from any injection session, and
says so. No baseline figure is published yet.

**Exported scenarios are playable.** Every event is labelled `attack_evidence`,
`side_effect` or `benign`; truth records list the event ids they own, and
`observed` equals that count by construction. Injector unit names and the
"nightshift simulated task" description are renamed to fixed aliases,
deterministically. `--noise` mixes in a separate quiet collection. `teach` gains
one entry per technique, including the T1543.002 blind spot.

**A devlog.** `docs/devlog.md` records the dead ends behind the numbers: the 33%
precision, two timestamp and repeat bugs, the negative MTTD, and the export
sweep that found real addresses in old fixtures.

## Numbers

- 2 of 2 injection variants across 1 technique, both timer rules pinned by
  checked-in journal fixtures.
- MTTD 7.2 s: injection start to the scan that caught it, including the
  collect→scan gap. First evidence landed at 1.5 s (`EVIDENCE`).
- Precision 100% on this run. Detections outside the injection window are
  listed as out of scope or repeats, never counted as catches.
- 246 tests, stdlib only, no network, no sudo, no system changes.
- Known blind spots: T1046 and T1105 leave no journald telemetry, T1548.003
  needs a password to log, T1543.002 logs nothing attributable, auditd needs
  root and is unverified here.

## Upgrading

No store format change. Old detection files without `detected_at` show `—` for
MTTD rather than a guessed value. Truth files written before this release have
no `marker`, so `export-scenario` will not attribute their lines; re-run
`inject` to get playable scenarios.

## Profile README row (for the owner to paste)

> **nightshift** — single-machine detection range. 246 tests, 2 of 2 injection
> variants across 1 technique caught, MTTD 7.2 s (injection start to the
> detecting scan, including collect and scan), precision 100% on that run.
> Blind spots reported, never scored as misses.
