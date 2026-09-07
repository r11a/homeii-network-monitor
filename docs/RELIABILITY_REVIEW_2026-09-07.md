# Monitoring reliability and usability review

## Implemented

- Managed inventory survives prolonged outages: automatic 48-hour cleanup excludes approved/manual devices.
- Scheduled, watchdog and manual monitoring passes share per-lane concurrency guards, released even on failure.
- Ping selects Windows or Linux command arguments. Linux/Home Assistant behavior is preserved.
- Manual-add probes and reverse DNS run in the thread pool instead of blocking the async API event loop.
- Availability stops at the current time and starts no earlier than device discovery. Device, category and global figures weight available durations, including partial hours. Unobserved buckets are marked explicitly; the UI does not fabricate 24 bars from current status.
- Requests have bounded waits; mutation/diagnostic requests receive a longer limit. Periodic refresh and stream events invoke the current refresh callback rather than a stale initial closure.
- Worker staleness and refresh failures are visible; the overview no longer labels empty inventory healthy.
- Manual addition supports Enter submission, pending state, duplicate-submit prevention, inline errors, typed categories and an explicit saved-but-offline result.
- Personal dashboard preferences are scoped to an account in the current browser; category, pinned-only, problems-only and compact filters are available. Category filtering is also available in inventory.

## Verification

- 29 Python tests passed, including managed-device retention, overlapping passes, lock release after errors, Windows/Linux ping arguments and timeline boundaries.
- Production Vite build passed. The pre-existing large JavaScript bundle warning remains.
- Python compilation and diff whitespace validation passed.
- Local browser checks: login, invalid-IP feedback, manual loopback addition with a new Hebrew category, inventory/dashboard display, preference persistence after reload, stale-monitoring warning, recovery to online and 390px mobile layout.
- Browser checks used a separate temporary database, not production Home Assistant data.

## Operational boundaries

This remains an ICMP device monitor, not an HTTP/TCP service monitor or a claim of commercial-product parity. ICMP-blocking devices can appear offline. Availability reconstructs state from recorded transitions; it is not a raw packet-loss measurement or a complete accounting of monitoring-host downtime. Existing manually trashed devices remain in the recycle bin. Preferences do not sync between browsers. Long-duration soak testing, large-network load testing, and deployment validation inside Home Assistant were not performed in this local review.

Existing integration/card work present before this task was preserved.
