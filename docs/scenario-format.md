# Scenario format

A scenario is one JSON file holding a sanitized slice of a real session, the
ground truth for it, and the teaching text needed to run it as an exercise.

```fish
nightshift export-scenario --state-dir ~/.local/share/nightshift \
                           --out my-scenario.json --lang en
```

`--lang` is `en` or `pt`. Only `teach` and `limits` change with the language;
the scenario id and the evidence do not.

A worked sample lives at [`examples/scenario-timer.json`](../examples/scenario-timer.json).

## Top-level document

| Field | Type | Meaning |
|---|---|---|
| `id` | string | 12 hex chars, sha256 of the sanitized `events` + `truth`. Two exports of the same session agree; an edited scenario does not. |
| `lang` | `"en"` \| `"pt"` | Language of `teach` and `limits`. |
| `events` | array | Normalized events, one object per line of the source store. |
| `truth` | array | Ground-truth records for the injections in the window. **This is the answer key.** |
| `teach` | object | `title`, `prompt`, `hints[]` — how to work the scenario. |
| `limits` | array | What the scenario is not, in the same language. |

`truth` is deliberately in the same file: a scenario that needs two files gets
separated, and one without truth cannot be scored. It also means you should not
hand an exported scenario to someone before the exercise.

## Events

Exactly the fields of the event schema, unchanged in name and type:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Stable for the source journal cursor. |
| `ts` | string | RFC3339 UTC, microseconds. |
| `host` | string | `ws-01` after sanitizing. |
| `provider` | string | `journald` or `auditd`. |
| `source` | string | `SYSLOG_IDENTIFIER`, falling back to `_COMM`. |
| `event_type` | string | Closed vocabulary; unrecognized lines stay `unknown`. |
| `priority` | int \| null | syslog priority. |
| `unit` | string \| null | systemd unit when it could be recovered, never guessed. |
| `user` | string \| null | `null` when not confidently known. |
| `pid` | int \| null | |
| `process` | string \| null | |
| `cmdline` | string \| null | Often `null` for services. |
| `src_ip`, `src_port` | string / int \| null | Mapped into `192.0.2.0/24` by the exporter. |
| `message` | string | Free text, sanitized. |

## Truth

The same records `inject` writes, sanitized:

| Field | Notes |
|---|---|
| `technique` | ATT&CK id, e.g. `T1053.006`. |
| `variant` | Present when one technique has more than one simulation. |
| `status` | `ran`, `skipped`, `failed`. |
| `started`, `ended` | Injection window, used for matching. |
| `observed` | Events the injector confirmed in the journal. `0` means the simulation left no telemetry. |
| `visible_expected` | Whether the provider could see this technique at all. |

## Sanitizing

The exporter replaces identifiers **by value**, not by pattern-guessing:

| Source | Becomes |
|---|---|
| this machine's hostname (short and FQDN) | `ws-01` |
| this user's name | `analyst` |
| the home directory | `/home/analyst` |
| every IPv4 and IPv6 address, in fields and in text | `192.0.2.1`, `192.0.2.2`, … in order of appearance |

Timestamps and ports are kept: they are what makes the exercise about detection
rather than about redaction. A clock time such as `05:04:11` is not mistaken for
an IPv6 address.

If you add a new field that can carry identity, add it to the sanitizer and to
`tests/test_scenario.py` in the same change — that test reads this machine's
hostname, username, home path and local addresses at run time and fails if any
of them appears in an export.
