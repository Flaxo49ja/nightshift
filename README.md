# nightshift

[![tests](https://github.com/Flaxo49ja/nightshift/actions/workflows/ci.yml/badge.svg)](https://github.com/Flaxo49ja/nightshift/actions/workflows/ci.yml)

A single-machine SOC practice range. It collects **real** host telemetry from
your own Linux box, applies detection rules, gives you a triage queue, injects
safe simulations so detection quality can be measured, and scores the result
against ground truth — so the feedback comes from evidence, not vibes.

> Status: **all four slices** — events + journald/auditd collectors, JSON rules
> and a triage queue, safe technique injector with a scorecard, ATT&CK coverage
> report. Nothing here attacks anything off the machine or changes system state.

New here? **[TEACH.md](TEACH.md)** is a ten-minute copy-paste lab: look at your own
host, run the ground-truth loop, then move a rule threshold and watch the noise
appear.

## Results

- **2 of 2 injection variants across 1 technique** were caught in the last run of
  `nightshift demo`; both timer rules are also pinned by checked-in journal fixtures.
- MTTD **6.1 s**, injection start to the scan that caught it, including the gap
  between `collect` and `scan`; the first journal evidence landed at **1.0 s**.
- Precision **100%**, 0 false positives. Detections from outside the injection
  window are listed as out of scope or as repeats, never counted as catches.
- Each variant is credited **only** to its designated rule: `transient-unit-started`
  for the transient timer, `timer-unit-introduced` for the on-disk pair. A detection
  of the right technique from any other rule is a repeat, never a catch.
- What it cannot see: T1046 and T1105 leave no journald telemetry, T1548.003
  needs a password to log, and auditd needs root — all reported, none scored as a miss.

## Why this shape

Most "SOC projects" end up teaching you to install a SIEM. The daily work is
reading telemetry, writing detections, and deciding fast whether an alert is
real. That needs a ground-truth loop, which this project builds in slices:

| Slice | What it adds |
|---|---|
| **1** | normalized events, journald collector, cursor, fixtures |
| **2** | JSON detection rules + engine + triage queue |
| **3** | safe technique injector, ground truth, blind mode, scorecard |
| **4** | auditd provider + ATT&CK coverage report |

The whole point is `nightshift score`. Anyone can print alerts; only a range with
ground truth can tell you your recall was 100% on one technique, that two of
your three alerts came from outside the experiment, and that the third one was
the injection you asked for.

## Install (fish)

```fish
cd ~/Projects/nightshift
python3 -m venv .venv
source .venv/bin/activate.fish
pip install -e .
```

Without installing, run it from the source tree:

```fish
set -x PYTHONPATH src
python3 -m nightshift.cli --help
```

## The shift

```
collect -> scan -> shift -> inject -> collect -> scan -> score
```

```fish
nightshift collect                 # first run: last 7 days, then cursor-based
nightshift scan                    # apply rules/ to events.jsonl
nightshift shift                   # work the triage queue
nightshift inject                  # run safe simulations, record ground truth
nightshift score                   # detections vs ground truth
nightshift coverage                # ATT&CK visibility report
nightshift export-scenario --out scenario.json   # sanitized, scoreable exercise
```

An export is one JSON file with the events, the answer key and the teaching
text: [docs/scenario-format.md](docs/scenario-format.md), sample in
[`examples/`](examples/). Hostnames, usernames, home paths and every IP are
replaced before the file is written, and a test reads this machine's real
identity to prove it.

See it work before you trust it: `nightshift demo` runs the whole loop —
collect, scan, inject, collect, scan, score — in a throwaway `/tmp` state dir and
tells you where to look afterwards. `--since` sets the first window (default 1h).

**First-run behaviour:** with no saved cursor, `collect` reads the **last 7
days** and says so in its output. After that the cursor takes over: each run
reads only newer entries, and a second run over unchanged data writes **0 new
events**.

### What gets dropped, and why

Default allowlist: `sudo`, `su`, `sshd`, `systemd`, `systemd-logind`,
`systemd-user-sessions`, `polkitd`, `pkexec`, `useradd`, `usermod`, `userdel`,
`passwd`, `CRON`, `crond`, `sddm`, `gdm`, `lightdm`, `greetd`, `ly`, `ly-dm`,
`unix_chkpwd`, `login`, `kernel`.

Everything else on a desktop is application stdout. On this machine one
download manager alone produced ~1,200 of the last 2,000 lines; collecting it
would bury the signal. Every run prints the dropped count **per identifier**,
and `--all` keeps them. auditd has no allowlist: every audit record is security
relevant.

## The normalized event

One JSON object per line in `events.jsonl`. The same keys always, `null` when
the journal does not carry the value.

| Field | Meaning |
|---|---|
| `id` | `sha256(provider + cursor)[:16]` — dedupe key, and how you get back to the raw entry |
| `ts` | RFC3339 UTC, microsecond precision — one format so MTTD is subtraction |
| `host` | `_HOSTNAME` |
| `provider` | `journald` or `auditd` |
| `source` | `SYSLOG_IDENTIFIER`, falling back to `_COMM` |
| `event_type` | closed vocabulary (below) |
| `priority` | journal priority 0–7 (`null` for auditd: it has none) |
| `unit`, `user`, `pid`, `process`, `cmdline`, `src_ip`, `src_port` | context, `null` rather than guessed |
| `message` | the raw human line |

Event types: `auth_success`, `auth_failure`, `sudo_command`, `session_open`,
`session_close`, `service_start`, `service_stop`, `service_failed`,
`timer_run`, `cron_run`, `account_change`, `process_exec`, `firewall_block`,
`unknown`.

There is deliberately no copy of the raw journal record: the journal is the
archive, and `id` can seek back to it.

## Detection rules

Rules are JSON in `rules/`, one file each, and a rule is **data, not code**.

```json
{
  "id": "auth-brute-force",
  "title": "Repeated authentication failures",
  "severity": "high",
  "technique": "T1110.001",
  "when": { "event_type": "auth_failure" },
  "group_by": "src_ip",
  "count_gte": 5,
  "within": "10m",
  "why": "Five failures inside ten minutes, counted per source, is the shape of a password guess.",
  "false_positives": ["a user mistyping a password repeatedly"]
}
```

* `when` — AND over event fields. Scalars match exactly, lists are membership.
  Three derived matchers exist: `message_contains`, `cmdline_contains`,
  `unit_contains` (case-insensitive substrings).
* `count_gte` + `within` + `group_by` — a burst rule. A 500-event brute force
  fires **once**, not 500 times: an alert an analyst cannot triage is not an
  alert.
* `technique` — the ATT&CK mapping the scorecard and coverage report use.

A typo'd field name is a load-time error with the list of valid fields. That is
the whole safety argument for making rules data: a rule that silently never
fires is worse than no rule at all.

## Triage

`shift` joins `detections.jsonl` with `queue.json`. Every detection starts `new`.

```fish
nightshift shift                             # list, newest first
nightshift shift --confirm 5bbaacc8          # any unambiguous id prefix
nightshift shift --dismiss 2f471db4 --note "my own timer, not an attack"
nightshift shift --all                        # include dismissed
```

The note is kept because "why did I dismiss this" is the part you forget in a
week. An ambiguous prefix is an error, never a guess.

## Safe simulations

`nightshift inject` runs each technique once and records ground truth **before**
anything reads it.

| Technique | Simulation | Touches |
|---|---|---|
| T1548.003 | `sudo -n -l` | nothing — no password, no state |
| T1053.006 | transient `systemd-run --user` timer, then `reset-failed` | a unit that is removed again |
| T1105 | fetch one file from a loopback HTTP server | 127.0.0.1 only |
| T1046 | TCP connect sweep of loopback ports 1–20 | 127.0.0.1 only |

Nothing leaves the machine, nothing persists, and a missing binary is `skipped`
with the reason rather than a crash. `--blind` records the truth without
printing which technique ran (the file is chmod `0600`, so reading the answers
is a deliberate act).

Credential attacks are **not** simulated: password guessing needs a password
prompt, a real account and a plausible failure mode, and getting it wrong means
locking an account on your own box. Use the fixtures for T1110.001.

### The finding this design produced

On this box `sudo -n -l` and a failed `su` write **nothing** to the journal: sudo
fails before PAM logging, and `su` to a missing user never reaches auth. So the
injector verifies what actually landed and records `observed: 0`. The scorecard
then reports T1548.003 as *"ran but recorded nothing (simulation limit)"* rather
than as a missed detection — those are different problems and they want
different fixes.

## The scorecard

```
TECH      VISIBILITY     INJECTED  CAUGHT  MISSED     MTTD  EVIDENCE
T1046     no-telemetry          0       0       0        —         —   not scored: no telemetry
T1053.006 observed              2       2       0     6.1s      1.0s
T1105     no-telemetry          0       0       0        —         —   not scored: no telemetry
T1548.003 observed              0       0       0        —         —   not scored: nothing observed
(only detections from a variant's designated rule count; the rest are repeats)
T1053.006 variants: transient 1/1 (transient-unit-started), unit-file 1/1 (timer-unit-introduced)

recall     100%  (2 caught, 0 missed, 1 scored technique(s))
precision  100%  (0 false positive(s))
no telemetry, not a miss: T1046 (no-telemetry), T1105 (no-telemetry)
ran but recorded nothing (simulation limit, not a detection miss): T1548.003

out of scope, not counted: 26 before the injection window; 4 same technique already caught in the window
  (each listed with timestamp and rule; trimmed here)
```

That last part is the fix. The same events, scored against the same truth by
the previous version, read `precision 33% (2 false positive(s))`: those
detections were `systemd-run` probes I ran five minutes before the injection,
and they were being averaged into an experiment that never observed them. Both
readings are in the test suite (`tests/test_score.py`, `session_window`), and
nothing was deleted to get from 33% to 100% — the detections are still printed,
just outside the arithmetic they do not belong in.

* **MTTD is injection start → the scan that caught it**, so it includes the gap
  between `collect` and `scan`. A store that was collected but never scanned has
  no detection and therefore no MTTD; that is a fact about the pipeline, not a
  rounding error. The older, faster figure — injection start → the journal line
  the detection was built from — is printed separately as `EVIDENCE`, because
  the two answer different questions and averaging them into one number is how
  a practice range flatters itself. Detection files written before
  `detected_at` existed show `—` for MTTD rather than a guess.
* A detection matches truth when the technique agrees and the windows overlap
  within five minutes of slack — journald writes asynchronously.
* **No telemetry is not a miss.** Techniques the provider cannot see are shown
  as `no telemetry` and left out of the recall arithmetic. `coverage.py` owns
  that decision in one table so it cannot drift.
* **Nothing observed is not a detection failure.** Same treatment, different
  reason, different line in the report.
* **The window is the session, not the store.** A detection older than the
  first injection (minus slack) is `out of scope`: it is listed with its
  timestamp but kept out of precision, because the experiment did not observe
  it. Counting the host's whole history against one injection measures the host,
  not the rules.
* **A second detection of an already-caught technique in the same window is a
  repeat, not a false alarm.** One `systemd-run` writes more than one journal
  entry, so two rules can fire on one injection; that is one catch and one
  duplicate. A blind spot has no telemetry and an unobserved run produced
  nothing, so neither has a catch to duplicate: a detection of either stays a
  false positive.
* **A variant counts only its designated rule.** Each injection record carries
  `expected_rules`; scoring skips a same-technique detection from any other
  rule, which then lands in the repeat bucket. This is what stops "both variants
  caught" from being true while one of the two rules is dead and the other one
  fires on both lines: with `timer-unit-introduced` deleted, the mutation test
  against the real fixture reports `unit-file 0/1` and one missed, not 2/2.
* **Any other detection that lines up with no injection is a false positive** —
  even if it looks plausible, even if it was a real event on the host, and
  including a plausible detection of the wrong technique inside the window.

## What journald cannot see, and auditd can

`nightshift collect --provider auditd` parses `/var/log/audit/audit.log`
(`--file` for a fixture). `auditd` records `execve`, which is the only way
`curl` and `nmap` become visible on a box where journald logs service output
rather than process execution.

| Technique | journald | auditd |
|---|---|---|
| T1110.001 Password Guessing | observed | unknown |
| T1548.003 Sudo and Sudo Caching | observed | observed |
| T1053.006 Systemd Timers | observed | observed |
| T1105 Ingress Tool Transfer | **no telemetry** | observed |
| T1046 Network Service Discovery | **no telemetry** | observed |
| T1136.001 Local Account Creation | observed | observed |
| T1078.003 Valid Accounts: Local | observed | unknown |

`nightshift coverage` prints this as a matrix, marks blind spots, and lists
visible techniques that no rule covers yet. `cron_run` is marked
**fixture-only**: cron is not installed on this machine, so it must never count
as real coverage.

## Fixtures

Four synthetic files under `fixtures/` (host `soc-lab`, users `alice` /
`nstest-ns7f3a2c`, TEST-NET IPs) with a reviewed golden file each under
`fixtures/expected/`. The repository is meant to be published, so no real
hostname, username or address appears in them.

## Tests

```fish
python3 -m unittest discover -s tests -v
```

179 tests, no network, no journal access, no system changes. They cover the
schema contract, cursor gaps, rule validation and burst windows, the triage
queue, injector safety (loopback only, cleanup, blind file mode), the
scorecard's honesty rules, and one end-to-end shift over the fixtures.

## Honest limits

- On a quiet window the allowlist yields little: a real two-day shift here
  produced 275 inbound firewall blocks and no authentication events. The blocks
  are typed as `firewall_block` now, but a LAN's multicast chatter stays below
  the scan threshold — that is a baseline, not an alert.
- journald sees the packets the firewall rejected, not the scanner's process, so
  `firewall_block` maps to T1595.002 while T1046 remains a blind spot.
- `/var/log/audit/audit.log` is root-only on a default install. Without sudo the
  auditd provider says so instead of reporting a clean zero; use `--file` with a
  fixture to work offline.
- T1543.002 (user service persistence) is a blind spot, and was left one:
  `systemctl --user enable` writes nothing, `disable` writes nothing, and the
  start line is `Starting <description>...` with the unit recorded as the
  manager scope. A rule for it would either key on the injector's own
  description or fire on every user service on the machine. The real lines are
  in `fixtures/user_service_persistence.jsonl` so the negative is testable.
- `sudo` events are only recorded when sudo actually reaches PAM. `sudo -n`
  failures, and `su` to a nonexistent user, are invisible — see above.
- `_CMDLINE` is usually absent for services, so `cmdline` is often `null`
  outside the auditd provider.
- `fetch()` reads the whole window into memory before filtering. Fine for seven
  days on this box; streaming is a v2 concern.
- The scorecard only knows what was injected. Host activity outside injection
  windows counts as false positive by design, so scores are meaningful per run,
  not across a shared timeline.
- One machine, one vantage point. This teaches triage, not detection at scale.
- A paired timer run always logs **two** `Started [systemd-run]` lines, and the
  second is not a duplicate: the transient timer and its service share one
  Description, so arming the timer and running the service look identical. The
  unit-file injector's `daemon-reload` defers the pending transient service onto
  the unit-file timer start, which is why the second line lands there; tightening
  AccuracySec to 100 ms moves it 1.1 s before the unit-file service but not away
  from the timer line. Measurements and the controlled check are in
  [docs/timer-journal-timing.md](docs/timer-journal-timing.md). The extra
  detection is scored as a repeat, never a catch.
