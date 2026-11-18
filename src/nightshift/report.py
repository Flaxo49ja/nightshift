"""ATT&CK coverage report.

A matrix is only useful if it can say "no". The point of this report is the
right-hand column: techniques you cannot see are the ones an attacker keeps.
`fixture-only` rows are marked so a synthetic fixture never becomes a coverage
claim.
"""
from .coverage import COVERAGE, FIXTURE_ONLY, gaps, is_real_coverage, observed, visibility

# Event types each technique depends on, so the report can flag a technique the
# provider sees but no rule currently detects.
_EVIDENCE = {
    "T1110.001": "auth_failure",
    "T1548.003": "sudo_command",
    "T1053.006": "timer_run",
    "T1105": "process_exec",
    "T1046": "process_exec",
    "T1136.001": "account_change",
    "T1078.003": "session_open",
    "T1595.002": "firewall_block",
}

_PROVIDERS = ("journald", "auditd")

# Human names, so the report reads like an ATT&CK table rather than a ledger.
_NAMES = {
    "T1110.001": "Password Guessing",
    "T1548.003": "Sudo and Sudo Caching",
    "T1053.006": "Systemd Timers",
    "T1105": "Ingress Tool Transfer",
    "T1046": "Network Service Discovery",
    "T1136.001": "Local Account Creation",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1595.002": "Vulnerability Scanning",
}


def render(provider: str = "journald", rules_techniques: set[str] | None = None) -> str:
    rules_techniques = rules_techniques or set()
    lines = [f"nightshift coverage — ATT&CK techniques vs {provider} visibility", ""]
    header = (f"  {'TECH':<11}{'TECHNIQUE':<32}{'VISIBILITY':<14}"
              f"{'RULE':<8}{'EVIDENCE'}")
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for technique in sorted(COVERAGE):
        state = visibility(technique, provider)
        evidence = _EVIDENCE.get(technique, "?")
        rule = "yes" if technique in rules_techniques else "—"
        note = ""
        if state == "no-telemetry":
            note = "  <- blind spot"
        elif not is_real_coverage(evidence):
            note = "  (fixture-only, not real coverage)"
        lines.append(f"  {technique:<11}{_NAMES.get(technique, technique)[:31]:<32}"
                     f"{state:<14}{rule:<8}{evidence}{note}")

    blind = gaps(provider)
    seen = observed(provider)
    lines.append("")
    lines.append(f"  {len(seen)} of {len(seen) + len(blind)} mapped techniques are visible "
                 f"to {provider}"
                 + (f"; blind: {', '.join(blind)}" if blind else "; no mapped blind spots"))
    if FIXTURE_ONLY:
        lines.append(f"  fixture-only event types (never real coverage): "
                     f"{', '.join(sorted(FIXTURE_ONLY))}")
    if rules_techniques:
        missing = sorted(set(COVERAGE) & set(seen) - rules_techniques)
        if missing:
            lines.append(f"  visible but no rule yet: {', '.join(missing)}")
    if blind:
        lines.append("")
        lines.append("  These are not misses — they are unknowable from this provider.")
        lines.append("  Point a rule at them anyway and the scorecard will call the gap a")
        lines.append("  false negative, which is the flattering direction to be wrong.")
    return "\n".join(lines)


def matrix() -> dict[str, dict[str, str]]:
    """The raw grid, for callers that want data rather than text."""
    return {technique: {p: visibility(technique, p) for p in _PROVIDERS}
            for technique in sorted(COVERAGE)}


def blind_spots(provider: str = "journald") -> list[str]:
    return gaps(provider)
