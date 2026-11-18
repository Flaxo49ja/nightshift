"""What each provider can actually see.

The scorecard must never call a technique "missed" when the provider was
incapable of recording it. That distinction lives here, in one table, so it
cannot drift between the injector, the rules and the report.

Technique choices (sub-techniques, because they describe the actual behaviour):
- T1110.001 Password Guessing  — the failed `su` burst.
- T1548.003 Sudo and Sudo Caching — `sudo -l` privilege probing. ATT&CK has no
  "sudo enumeration" technique; this is the closest, because the probe only
  matters as the step before a sudo abuse. If you would rather frame it as
  discovery, T1069.001 (Local Groups) is the alternative.
- T1053.006 Systemd Timers — the throwaway user timer.
- T1105 Ingress Tool Transfer — `curl` from the loopback mock server.
- T1046 Network Service Discovery — `nmap` against loopback.
"""
COVERAGE: dict[str, dict[str, str]] = {
    "T1110.001": {"journald": "observed"},
    "T1548.003": {"journald": "observed", "auditd": "observed"},
    "T1053.006": {"journald": "observed", "auditd": "observed"},
    # The pair auditd exists for: journald sees service output, not execve.
    "T1105": {"journald": "no-telemetry", "auditd": "observed"},
    "T1046": {"journald": "no-telemetry", "auditd": "observed"},
    # Added with the account-change and root-session rules in slice 2.
    "T1136.001": {"journald": "observed", "auditd": "observed"},
    "T1078.003": {"journald": "observed"},
}

# event_types that only ever exist in fixtures on this machine. They must never
# count towards real coverage, or the scorecard would flatter itself.
FIXTURE_ONLY = frozenset({"cron_run"})


def visibility(technique: str, provider: str = "journald") -> str:
    """observed | no-telemetry | unknown (not yet mapped)."""
    return COVERAGE.get(technique, {}).get(provider, "unknown")


def is_real_coverage(event_type: str) -> bool:
    return event_type not in FIXTURE_ONLY


def gaps(provider: str = "journald") -> list[str]:
    """Techniques this provider cannot see. Never report these as missed."""
    return sorted(t for t in COVERAGE if visibility(t, provider) == "no-telemetry")


def observed(provider: str = "journald") -> list[str]:
    return sorted(t for t in COVERAGE if visibility(t, provider) == "observed")
