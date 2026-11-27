# Scenario format

A scenario is one JSON file holding a sanitized slice of a real session, the
labelled ground truth for it, and enough teaching material to work it as an
exercise.

```fish
nightshift export-scenario --state-dir ~/.local/share/nightshift \
                           --out my-scenario.json --lang en \
                           [--noise quiet-day/events.jsonl] \
                           [--max-events 20] [--seed 0] [--blind] \
                           [--ticket-title TEXT --severity low|medium|high|critical \
                            --reported-by TEXT --story TEXT \
                            --expected-action close_benign|escalate|need_more_data]
```

`--lang` is `en` or `pt`; only `teach` and `limits` change with it. `--noise`
mixes in events from a separate quiet collection, sanitized the same way and
labelled benign.

`--blind` writes a blind-spot night: `truth` is empty, every event is labelled
`benign`, and `side_effect_ids` is empty. The teaching block still names the
techniques (including T1543.002) so the debrief can explain what the log could
not show. A player who sees no attack evidence should answer "Nothing visible";
the scenario cannot be used to measure a detection that the provider never saw.

All five ticket flags are required together. They write a `ticket` block instead
of hand-editing the exported JSON; the same sanitizer runs over every ticket
field, and the range's own name is replaced with `backup-sync` so
`nightshift` cannot appear in it.

A worked sample lives at [`examples/scenario-timer.json`](../examples/scenario-timer.json).

## Top-level document

| Field | Type | Meaning |
|---|---|---|
| `id` | string | 12 hex chars, sha256 of the sanitized `events` + `truth`. Same session, same id. |
| `lang` | `"en"` \| `"pt"` | Language of `teach` and `limits`. |
| `events` | array | Labelled events, sorted by timestamp. |
| `truth` | array | Ground-truth records. **This is the answer key.** |
| `side_effect_ids` | array | Event ids caused by the injector's own reloads. |
| `excluded` | object | `outside_session`, `untied_injector`, `not_allowlisted`, `noise_injector`, `noise_in_window` and `noise_not_allowlisted` counts: what was left out, and why. |
| `teach` | object | `title`, `prompt`, `hints[]`, and `techniques[]` (see below). |
| `limits` | array | What the scenario is not. |
| `ticket` | object | Optional. `title`, `severity`, `reported_by`, `customer_story`, `expected_action`; all sanitized like event text. |

`truth` is deliberately in the same file: a scenario that needs two files gets
separated, and one without truth cannot be scored. It also means you should not
hand an exported scenario to someone before the exercise.

## One session per scenario

A store holds every run it ever saw. The export contains only the session the
truth describes: events from `earliest truth.started − 60 s` to
`latest truth.ended + 60 s`. An injector-shaped line inside that window that no
truth record can own (a timer from an earlier run, a stale
`Started [systemd-run] …`) is dropped and counted in `excluded.untied_injector`;
events outside the window are counted in `excluded.outside_session`. With no
truth there is no session, so the export is background only.

## Sizing the level

`--max-events` (default 20) is the total number of events. Every
`attack_evidence` and `side_effect` event is kept; if `N` is smaller than that
set, the export fails with an error instead of silently dropping the attack.
The remaining slots are filled with allowlisted background, nearest the
truth windows first. Where two candidates are equally near, `--seed` decides
(sha256 of seed and event id), so a level is reproducible without depending on
store order. The result is still sorted by time. Quiet input selected for those
slots is rebased into the session window in its original order, so a corpus
from another day cannot create a second timeline; `limits` says that background
timestamps are rebased and attack/side-effect timestamps are real.

Background is a closed list, whether it comes from the session window or
`--noise`: auth events, UFW firewall blocks, and a fixed set of generic unit
descriptions (for example `user preferences database`, `network manager script
dispatcher service`, and the injector aliases such as `backup sync`). Any other
application, desktop, hardware or device name is dropped and counted in
`excluded.not_allowlisted`; a description with a path, `~` or `App - Window`
shape is dropped too. Noise gets the same injector-shaped and truth-window drops
as session events, counted as `noise_injector` and `noise_in_window`; its
non-allowlisted count is `noise_not_allowlisted`.

## Events

Each event carries the event-schema fields plus one `label`:

* `attack_evidence` — owned by one truth record. A record claims an event when
  the event type is what the simulation should emit, it falls inside the run
  window (plus the 5 s journald grace), and it carries the record's `marker`
  (the unit name the injector created). The transient variant is the exception:
  systemd logs its units by description, so its `Started [systemd-run] ...`
  service start is claimed by shape instead of name.
* `side_effect` — a manager line caused by the injector's own `daemon-reload`
  (`Reload requested…`, `Reloading…`, `Reloading finished…`) inside a run
  window. Not attack behaviour.
* `benign` — allowlisted background only, from the session window or `--noise`.
  Anything that is not allowlisted is excluded rather than mislabelled.

Event fields themselves are unchanged from `schema.py`: `id`, `ts`, `host`,
`provider`, `source`, `event_type`, `priority`, `unit`, `user`, `pid`, `process`,
`cmdline`, `src_ip`, `src_port`, `message`.

## Truth

The injection records, plus the evidence they own:

| Field | Notes |
|---|---|
| `technique` | ATT&CK id, e.g. `T1053.006`. |
| `variant` | Present when one technique has more than one simulation. |
| `status` | `ran`, `skipped`, `failed`. |
| `started`, `ended` | Injection window, used for matching and labelling. |
| `marker` | The unit name the injector created, renamed to an alias. |
| `observed` | Events the injector confirmed. Always `len(event_ids)` for a ran record. |
| `expected_rules` | Rule ids allowed to credit this variant. |
| `event_ids` | The events labelled `attack_evidence` for this record. |

An event id appears in at most one record's `event_ids`, and every truth record's
`observed` equals the length of its `event_ids` — there is a test for both.

## Teaching block

`teach.techniques` has one entry per technique in the scenario, plus the
T1543.002 blind spot even when nothing simulated it:

```json
{
  "technique": "T1053.006",
  "name": "Transient systemd unit started",
  "why": "…quoted from the rule that should catch it…",
  "looks_like": ["Started [systemd-run] …", "Started <name>.timer. …"],
  "false_positives": ["…from the rule…"],
  "rule_id": "transient-unit-started",
  "blind_spot": false
}
```

A blind spot has `rule_id: null` and `blind_spot: true`; its `why` says why no
rule can be written. Rule text is quoted in English even in a Portuguese export,
which is stated in `limits`.

## Sanitizing and aliases

The exporter replaces identifiers **by value**, not by pattern-guessing:

| Source | Becomes |
|---|---|
| this machine's hostname (short and FQDN) | `ws-01` |
| this user's name | `analyst` |
| the home directory | `/home/analyst` |
| every IPv4 and IPv6 address, in fields and in text | `192.0.2.1`, `192.0.2.2`, … in order of appearance |
| every MAC address | `00:00:5e:00:53:01`, `00:00:5e:00:53:02`, … (the documentation range) |
| injector unit names (`nightshift-…`) | `backup-sync`, `media-indexer`, …, assigned in sorted order per scenario |
| `nightshift simulated task` | `backup sync` |

Timestamps and ports are kept: they are what makes the exercise about detection
rather than about redaction. A clock time such as `05:04:11` is not mistaken for
an IPv6 address, and a MAC is six two-digit groups with five colons, so the IPv6
matcher leaves it to the MAC replacer. The example sweep fails on any MAC outside
`00:00:5e:00:53:xx`, any email-shaped string, any `/home/…` path other than
`/home/analyst`, and any PCI address (`0000:00:1f.3`). The alias list is fixed, so the same session always exports the
same names; a test fails if the string `nightshift` survives into `events` or
`teach`.

If you add a new field that can carry identity, add it to the sanitizer and to
`tests/test_scenario.py` in the same change — that test reads this machine's
hostname, username, home path and local addresses at run time and fails if any
of them appears in an export.
