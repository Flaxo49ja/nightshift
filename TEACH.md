# nightshift — a lab you can run in ten minutes

Every command below is copy-paste ready. The numbers marked *this box* came from
a real run on Nov 19 2026, so if your output differs, that's your host talking,
not a broken install.

Nothing here needs root, network access, or changes to your system.

## 0. Setup, once

```bash
cd ~/Projects/nightshift
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

No venv wanted? Then put this in your `~/.bashrc` instead:

```bash
export PYTHONPATH="$HOME/Projects/nightshift/src"
alias ns='python3 -m nightshift.cli'
```

Check it works — this should print six subcommands:

```bash
ns --help     # or: python3 -m nightshift.cli --help
```

## 0.5 Show me everything at once

```bash
ns demo
```

That one command runs the whole loop — collect, scan, inject, collect, scan,
score — in a throwaway `/tmp/nightshift-demo-*` directory, stops on the first
step that fails, and prints the path so you can `ls` through the evidence. Your
real store is never touched. `ns demo --since 7d` if one hour of journal feels
thin.

Everything below is the same loop one step at a time, which is how you actually
learn it.

## 1. Look at your own host

```bash
ns collect --since 1h --state-dir /tmp/lab1
ns scan  --state-dir /tmp/lab1
ns shift --state-dir /tmp/lab1
```

`collect` reads your journal through an allowlist. On *this box* a one-hour
window kept **62 events** and dropped 162 lines; over seven days it is 4,120 kept
against 45,259 dropped. That second number is the lesson — one download manager
alone was producing ~1,200 lines per 2,000. Collecting everything buries the
signal, so the allowlist is the first detection decision you make, before any
rule runs.

`--state-dir` keeps lab data in `/tmp` instead of your real shift store. Use it
while you experiment.

## 2. The loop that makes this a range

This is the part that matters. `inject` runs safe local simulations and writes
ground truth; `score` compares what you detected against what actually happened.

```bash
ns collect --since 1h --state-dir /tmp/lab2   # a fresh window
ns scan    --state-dir /tmp/lab2
ns inject  --state-dir /tmp/lab2              # 4 techniques, loopback/local only
ns collect --state-dir /tmp/lab2              # pick up what injection generated
ns scan    --state-dir /tmp/lab2              # now there is something to find
ns score   --state-dir /tmp/lab2
```

*This box* printed:

```
  TECH      VISIBILITY     INJECTED  CAUGHT  MISSED
  T1046     no-telemetry          0       0       0   not scored: no telemetry
  T1053.006 observed              1       1       0
  T1105     no-telemetry          0       0       0   not scored: no telemetry
  T1548.003 observed              0       0       0   not scored: nothing observed

  recall     100%  (1 caught, 0 missed, 1 scored technique(s))
  precision  100%  (0 false positive(s))
```

Read the `not scored` lines, not the 100%. They are the whole design:

- **T1046 / T1105 are `no-telemetry`.** journald cannot see a loopback port sweep
  or an in-memory fetch. `score` refuses to call that a missed detection, because
  a range that scores 0% on impossible things teaches you to chase ghosts.
- **T1548.003 ran and logged nothing.** `sudo -n -l` with a password required
  doesn't reach PAM, so there's no journal entry. That's a simulation limit,
  stated plainly, not a detection failure.

Anyone can print alerts. This is the only step that tells you whether your alerts
were *right*.

## 3. Work the queue like an analyst

```bash
ns shift --state-dir /tmp/lab2
```

You get a table of detections with an ID prefix. Then judge each one:

```bash
ns shift --state-dir /tmp/lab2 --confirm eec29fd5 --note "transient timer was my own systemd-run"
ns shift --state-dir /tmp/lab2 --dismiss eec29fd5 --note "same thing, but no ground truth for it"
```

Rule of thumb for this range: **confirm** a detection you can tie to a recorded
truth entry; **dismiss** same-pattern activity with no ground truth. Write the
note as if you're leaving it for someone at 3am — that note is the deliverable.

## 4. The experiment worth doing: move a threshold

Your real store already holds **275** inbound firewall blocks from 24 addresses.
The shipped rule wants 40 blocks from one source in 10 minutes, so it fires zero
times — deliberately. Lower it and watch the LAN light up:

```bash
cp -r rules /tmp/rules-lab
sed -i 's/"count_gte": 40/"count_gte": 5/' /tmp/rules-lab/firewall-block-burst.json

cp -r /tmp/ns-fwcheck /tmp/lab4 2>/dev/null || ns collect --since 7d --state-dir /tmp/lab4
ns scan --rules /tmp/rules-lab --state-dir /tmp/lab4
```

*This box*: threshold **40 → 0 detections**, threshold **5 → 15 detections**, all
of them neighbours running LLMNR and mDNS. Nobody is attacking you. That is the
job in one dial: too high and you're asleep, too low and you're the boy who cried
wolf. The noisiest legitimate source here peaked at 28 blocks per 10 minutes, and
that measurement is why 40 is the number in the file.

## 5. Write a rule of your own

Copy the smallest existing rule, change the `when`, keep the id unique:

```bash
cp rules/transient-unit-started.json rules/my-rule.json
```

```json
{
  "id": "my-rule",
  "title": "Root shell opened",
  "severity": "high",
  "technique": "T1078.003",
  "why": "A root session is rare enough on this host that every one deserves a look.",
  "false_positives": ["you, doing maintenance"],
  "when": { "event_type": "session_open", "user": "root" }
}
```

```bash
ns scan --state-dir /tmp/lab1    # a typo here is a loud load-time error, by design
```

Valid match fields, so you don't guess: `cmdline`, `cmdline_contains`,
`event_type`, `host`, `message_contains`, `priority`, `process`, `provider`,
`source`, `src_ip`, `src_port`, `unit`, `unit_contains`, `user`. Add `count_gte`
+ `within` + `group_by` to make it a burst rule instead of a per-event rule.

A rule that silently never fires is worse than no rule, so the loader rejects
unknown fields and unknown event types. Try `{"when": {"evnt_type": ...}}` once
and read the error — it lists every legal field.

## 6. Know where you are

```bash
ns coverage                          # ATT&CK techniques vs what journald can see
ls ~/.local/share/nightshift         # default store: events, detections, queue, truth
```

| File | What it is |
| --- | --- |
| `events.jsonl` | one normalized event per line, `id` seeks back to the journal |
| `detections.jsonl` | rule hits; `--confirm`/`--dismiss` add verdicts |
| `queue.json` | triage state, survives re-scans |
| `truth.jsonl` | what injection actually did — the scorecard's only source of truth |

`--state-dir` overrides the whole directory, which is why every lab above stays
in `/tmp` and your real shift is untouched.

## 7. Getting unstuck

- `No module named nightshift` → `PYTHONPATH` isn't set (step 0).
- `collect` wrote 0 events → the cursor is doing its job; nothing new has
  happened. Use a fresh `--state-dir` for a fresh look, or `--since 7d`.
- Too much noise in `detections.jsonl` → you scanned with a lab rules dir. Point
  `--rules` back at `rules/`.
- Want the raw journal line for an event? Take its `id` and search the journal.
  The store keeps no copy of the record on purpose.
