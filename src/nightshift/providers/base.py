"""The provider seam.

auditd arrives in a later slice, so everything above this line (collector,
rules, scorecard) must only ever see `Event` records — never journald JSON.
"""
from datetime import datetime
from typing import Iterator, Protocol

from ..schema import Event


class CursorInvalid(Exception):
    """The saved cursor no longer exists (journal rotated or vacuumed).

    The collector must report this as an explicit telemetry gap instead of
    silently resuming at "now" — a hidden gap is how analysts get burned.
    """


class Provider(Protocol):
    name: str

    def fetch(self, after_cursor: str | None, since: datetime | None) -> list[dict]:
        """Raw entries after `after_cursor`, or since `since` on a first run."""

    def source_of(self, raw: dict) -> str:
        """The identifier used for allowlist filtering, before normalization."""

    def normalize(self, raw: dict) -> Event | None:
        """One raw entry -> one Event, or None when it cannot be normalized."""
