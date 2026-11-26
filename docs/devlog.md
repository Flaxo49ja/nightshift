# Devlog

Entries are dated by commit. Every number here was printed by a command run on
this machine before it was written down; commit hashes are the whole citation.
No hostname, username, home path or real address appears in this file.

## 2026-11-18 — the first scorecard said 33% precision

**Tried.** Run the loop end to end: collect, inject, collect, scan, score.

**Happened.** Precision came out 33% with two false positives. Both were real
`systemd-run` probes from a manual session five minutes *before* the injection;
the scorecard was averaging the host's whole history into one experiment.

**Changed.** `60c2312` (next day) scoped scoring to the injection window: first
injection minus slack to last injection plus slack. Detections outside it are
listed as out of scope, not deleted. The two detections are still printed.

**Can't tell you.** Whether the rules are quiet on a day nobody injects
anything. That is a different measurement, and `baseline` exists for it.

## 2026-11-25 — window scoping, and what it does not fix

**Tried.** Score the same store twice, with and without the window.

**Happened.** The numbers moved and the detections did not. Window scoping
turned "the host did this earlier" into "out of scope", which is honest, but it
also means a busy host's own activity inside the window is still scored against
the injection.

**Changed.** `60c2312` added `session_window`, the out-of-scope list and tests
for both boundaries.

**Can't tell you.** Whether two things happening in the same window are related.
Overlap is not causation; that limit is in the README.

## 2026-11-26 — bug 1: invented alerts counted as repeats

**Tried.** Add a detection of a technique the provider cannot see, and a
detection of a simulation that recorded nothing, then score.

**Happened.** Both were excused as "same technique already caught in the
window" and vanished from precision. A repeat is only a repeat if something in
the window could have been caught; these could not.

**Changed.** `d791d91` limits repeats to catchable simulations. The two now
appear as false positives, which is the uncomfortable but correct bucket.

**Can't tell you.** Whether those alerts were harmful in practice. Precision
counts them either way; triage is what decides.

## 2026-11-26 — bug 2: timestamps compared as strings

**Tried.** Feed an event exactly on the five-second observation boundary.

**Happened.** It was dropped. One side was formatted `...07.000000Z`, the other
`...07+00:00`, and the comparison was between strings, not times, so the two
spellings of the same instant sorted differently.

**Changed.** `d791d91` routes every comparison through one `parse_ts` helper.
Tests pin the boundary instant and one microsecond past it.

**Can't tell you.** Whether the journal's own timestamps are accurate. It only
makes the comparison say what it means.

## 2026-11-26 — a circular 100%, and why a second variant exists

**Tried.** Get recall to 100%, then ask what that number was measuring.

**Happened.** One injection variant, one rule written against it: 100% recall
was close to circular. Adding a second way to do the same technique (a unit pair
on disk instead of a transient timer) made the scorecard report "both variants
caught" while the transient rule was the only one firing twice — the unit-file
rule could have been dead.

**Changed.** `31bbb9e` added the second variant, its rule and real-journal
fixtures. `ec4eb49` credited each variant to the rule that caught it, and
`f34cd0f` made that strict: a variant counts only its designated rule. Deleting
the unit-file rule now turns that variant into a miss instead of leaving 2/2.

**Can't tell you.** That two variants are coverage. Two shapes of one technique
is still one technique.

## 2026-11-26 — auditd closed without root

**Tried.** Read auditd telemetry to cover process execution (T1046, T1105).

**Happened.** `/var/log/audit/audit.log` is root-only, `auditctl -s` answers
"You must be root", and auditd is inactive. There was no non-sudo path to real
records, so nothing was invented.

**Changed.** Nothing, deliberately. `coverage.py` and the README say auditd is
unverified here; `--file` exists so a fixture can be parsed offline.

**Can't tell you.** Whether auditd would see those techniques on a machine
where it runs. That question is open, and marked open.

## 2026-11-26 — `rule_sha`: which rule said that?

**Tried.** Read an old detection and work out what the rule looked like when it
fired.

**Happened.** Nothing recorded it. A rule id alone survives edits, so a triage
note could not name the text it was written against.

**Changed.** `24cb230` stamps every detection with the first 12 hex characters
of the rule file's sha256, and tests check the hash matches the file and is
unique across rules.

**Can't tell you.** Whether the rule's meaning changed between two files with
different hashes. It identifies a version, not a diff.

## 2026-11-26 — MTTD that wasn't MTTD

**Tried.** Report time to detection.

**Happened.** The first version measured injection start to the journal line
the detection was built from — the fastest possible number, one that ignores
collect and scan entirely. It was labelled MTTD anyway.

**Changed.** `24cb230` printed it. `ec21412` added `detected_at` to every
detection and defined MTTD as injection start to the scan that caught it,
keeping the old figure as `EVIDENCE` beside it. Both are defined in the output.

**Can't tell you.** Why a scan was late. MTTD includes the gap between collect
and scan, so it measures the pipeline, not only the rule.

## 2026-11-26 — detections that predated the injection (negative MTTD)

**Tried.** Report MTTD on a clean run.

**Happened.** It read −0.2 s. The five-minute slack existed for asynchronous
journal writes, and it was wide enough to credit a probe from minutes earlier
as this injection's catch.

**Changed.** `d527ce9` refuses a detection whose first line predates the
injection start. The probe stays visible as a repeat; it stops being evidence.

**Can't tell you.** Whether a detection seconds *after* the start is related.
The scorecard still matches by technique and window, not by provenance.

## 2026-11-26 — T1543.002 stayed a blind spot

**Tried.** Simulate user-service persistence, then write a rule for it.

**Happened.** `systemctl --user enable` and `disable` log nothing. The start
line is `Starting <description>...`, the unit is recorded as the manager scope,
and the description is chosen by whoever created the unit — so the only
reliable match would be the injector's own wording, and a generic match would
fire on every user service on the box.

**Changed.** `a514175` captured the real lines as
`fixtures/user_service_persistence.jsonl`, added tests asserting no shipped rule
fires and that the malicious start is shape-identical to a benign one, and
wrote the reason into the README's limits. No rule was written.

**Can't tell you.** Whether a different host's systemd logs enough to make this
detectable. This box does not.

## 2026-11-26 — the export sweep that found real leaks in the fixtures

**Tried.** Publish an export, so first sweep every checked-in fixture and example
for this machine's identity.

**Happened.** Two earlier artifacts carried real values: a firewall fixture and
its golden file held this box's LAN address, and a provider test embedded its
real link-local IPv6 address. They had passed review because they looked like
private-range examples.

**Changed.** `0070536` replaced them with documentation values, and added a test
that reads this machine's hostname, username, home path and local addresses at
run time, then fails if any of them appears in an export, a fixture or an
example.

**Can't tell you.** That value-based substitution catches every identifier. It
knows the names and addresses it is given; a MAC address or a hostname embedded
in an opaque payload would still get through.

## How this was built

An AI coding agent (Buffy, via Codebuff) wrote most of the code in this repo,
working test-first from the failures above; every command and number in this
file was run on the machine, and the human owner reviewed each commit.
