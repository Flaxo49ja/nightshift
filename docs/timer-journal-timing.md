# Why a timer injection logs two `[systemd-run]` lines

A transient timer is two units, not one:

```
$ systemd-run --user --on-active=1 --unit=nightshift-sim-0907b046.timer true
Running timer as unit: nightshift-sim-0907b046.timer
Will run service as unit: nightshift-sim-0907b046.service
```

Both units get the same `Description=[systemd-run] /usr/sbin/true`, so arming
the timer and starting its service produce the same journal line twice:

```
0.06s  nightshift-sim-0907b046.timer    Started [systemd-run] /usr/sbin/true.
3.22s  nightshift-sim-0907b046.service  Started [systemd-run] /usr/sbin/true.
```

The `USER_UNIT` field on each entry (shown above) is what identifies which is
which; the message text cannot. On its own, the service line is not a second
injection, and the transient rule firing on it is a repeat, which the scorecard
already classifies as one.

## Measured, 5 runs per combination

Each run is a fresh injector call; the journal is read back per run with
`journalctl --user -o json`. Times are seconds from the run's start.

| Runs | Bracket lines | Placement |
|---|---|---|
| `inject_timer` alone, 5× | 2 each | first at +0.05 (timer armed); second at +2.0–2.1 (service, coalesced to the next manager wake-up) |
| `inject_timer_unit` alone, 5× | 0 in 4 runs, 1 in 1 run | that one is the *previous* transient run's service, fired by this run's `daemon-reload` at +0.06 |
| both, default accuracy, 5× | 2 each | first at +0.05; second 0.01 s after `Started <name>.timer`, 2.4–2.5 s before the unit-file service starts |
| both, `AccuracySec=100ms` on both timers, 5× | 2 each | first at +0.05; second 0.01 s after `Started <name>.timer`, 1.06–1.11 s before the unit-file service starts |

## The cause is `daemon-reload`, not timer accuracy

`inject_timer_unit` begins with `systemctl --user daemon-reload`, and that
defers the pending transient timer. Controlled check with a 100 ms accuracy
timer:

| Sequence | Service start |
|---|---|
| arm, do nothing | +1.13 s |
| arm, `daemon-reload` after 0.3 s | +3.11 s |

With the default one-minute accuracy the service lands at the next manager
wake-up at all (one measured run fired 15 s later), which is why the paired gap
in the default table is wide and the unpaired gap varies with whatever else runs
next. Tight accuracy makes the unit-file service start deterministic (1.1 s
after its timer), but it does **not** move the transient service line away from
`Started <name>.timer`: the reload reschedules it onto that event either way.

No injector change: the second line is real telemetry for a real second unit,
not a duplicate, and removing it would mean hiding a start rather than fixing
one. The scorecard's repeat bucket is the correct handling. This is the
behaviour recorded in the README's honest limits.
