# nightshift

A single-machine SOC practice range. It collects **real** host telemetry from
your own Linux box, and later slices add safe attack simulations, detections
and a scored triage queue — so the feedback comes from evidence, not vibes.

> Status: **slice 1 of 4** — events + journald collector.
> Nothing here attacks anything or changes system state; it only reads the
> journal.

## Why this shape

Most "SOC projects" end up teaching you to install a SIEM. The daily work is
reading telemetry, writing detections, and deciding fast whether an alert is
real. That needs a ground-truth loop, which this project builds in slices:

| Slice | What it adds |
|---|---|
| **1 (this)** | normalized events, journald collector, cursor, fixtures |
| 2 | JSON detection rules + engine + triage queue |
| 3 | safe technique injector, ground truth, blind mode, scorecard |
| 4 | auditd provider + ATT&CK coverage report |

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
python3 -m nightshift.cli collect
```

## Use

```fish
nightshift collect                 # first run: last 7 days, then cursor-based
nightshift collect --since 24h     # explicit first-run window
nightshift collect --since 2026-10-01T00:00:00Z
nightshift collect --all           # keep every identifier, not just the allowlist
nightshift collect --state-dir /tmp/ns
```

**First-run behaviour:** with no saved cursor, `collect` reads the **last 7
days** and says so in its output. A 7-day default is a compromise: a whole
journal is slow and mostly noise, while "since now" would look like a working
collector that found nothing. Override with `--since 7d`, `24h`, `45m`, or an
ISO8601 timestamp.

After the first run the cursor takes over: each run reads only entries newer
than the last one, and a second run over unchanged data writes **0 new events**.

### What gets dropped, and why

Default allowlist: `sudo`, `su`, `sshd`, `systemd`, `systemd-logind`,
`systemd-user-sessions`, `polkitd`, `pkexec`, `useradd`, `usermod`, `userdel`,
`passwd`, `CRON`, `crond`, `sddm`, `gdm`, `lightdm`, `greetd`, `ly`, `ly-dm`,
`unix_chkpwd`, `login`, `kernel`.

Everything else on a desktop is application stdout. On this machine one
download manager alone produced ~1,200 of the last 2,000 lines; collecting it
would bury the signal. Every run prints the dropped count **per identifier**,
and `--all` keeps them.

## The normalized event

One JSON object per line in `events.jsonl`. The same keys always, `null` when
the journal does not carry the value.

| Field | Meaning |
|---|---|
| `id` | `sha256(provider + cursor)[:16]` — dedupe key, and how you get back to the raw entry |
| `ts` | RFC3339 UTC, microsecond precision — one format so MTTD is subtraction |
| `host` | `_HOSTNAME` |
| `provider` | `journald` now, `auditd` later |
| `source` | `SYSLOG_IDENTIFIER`, falling back to `_COMM` |
| `event_type` | closed vocabulary (below) |
| `priority` | journal priority 0–7 |
| `unit` | `_SYSTEMD_USER_UNIT` or `_SYSTEMD_UNIT` |
| `user` | best-effort; `null` rather than guessed |
| `pid`, `process`, `cmdline` | process context when the journal carries it |
| `src_ip`, `src_port` | parsed from auth messages |
| `message` | the raw human line |

Event types: `auth_success`, `auth_failure`, `sudo_command`, `session_open`,
`session_close`, `service_start`, `service_stop`, `service_failed`,
`timer_run`, `cron_run`, `account_change`, `unknown`.

There is deliberately no copy of the raw journal record: the journal is the
archive, and `id` can seek back to it.

## Cursor and gaps

`cursor.json` holds the last `__CURSOR` seen, its timestamp, and the host.
Writing order is **append events → fsync → save cursor**, so a crash can
duplicate a line (dedupe removes it) but never lose one.

If the journal has rotated past the saved cursor, `journalctl` refuses it. The
collector then restarts from the cursor's timestamp and prints:

```
  telemetry gap: <saved_at> → <now> (journal rotated; restarted from saved_at)
```

It never silently resumes at "now" — a hidden gap is how analysts get burned.

## What journald cannot see

`src/nightshift/coverage.py` records this, and the scorecard will consult it so
"no telemetry" is never reported as "you missed it":

| Technique | journald |
|---|---|
| T1110.001 Password Guessing (`su` failures) | observed |
| T1548.003 Sudo and Sudo Caching (`sudo -l`) | observed |
| T1053.006 Systemd Timers | observed |
| T1105 Ingress Tool Transfer (`curl`) | **no telemetry** |
| T1046 Network Service Discovery (`nmap`) | **no telemetry** |

`cron_run` is marked **fixture-only**: cron is not installed on this machine, so
it must never count as real coverage.

## Fixtures

Four synthetic files under `fixtures/` (host `soc-lab`, users `alice` /
`nstest-ns7f3a2c`, TEST-NET IPs) with a reviewed golden file each under
`fixtures/expected/`. The repository is meant to be published, so no real
hostname, username or address appears in them.

## Tests

```fish
python3 -m unittest discover -s tests -v
```

50 tests, no network, no journal access, no system changes.

## Honest limits

- On a quiet window the allowlist yields almost nothing: this machine logged 34
  firewall blocks in 45 minutes and no auth events. That is a real lesson about
  baselines, but it means slice 3's simulations are what create signal.
- `_CMDLINE` is usually absent for services, so `cmdline` is often `null`.
- `fetch()` reads the whole window into memory before filtering. Fine for seven
  days on this box; streaming is a v2 concern.
- journald logs service output, not process execution: `curl` and `nmap` are
  invisible until the auditd provider exists.
