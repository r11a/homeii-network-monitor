"""Pure device-state transition policy."""

from __future__ import annotations

from .config import RECOVER_THRESHOLD


def next_probe_status(
    previous: str,
    managed: bool,
    reachable: bool,
    fail_count: int,
    success_count: int,
    fail_threshold: int,
) -> str:
    previous = previous or "unknown"
    if not managed:
        return "new"
    if reachable:
        if previous in ("offline", "unstable", "new", "unknown") and success_count >= RECOVER_THRESHOLD:
            return "online"
        return previous
    if fail_count >= max(1, fail_threshold):
        return "offline"
    return previous

