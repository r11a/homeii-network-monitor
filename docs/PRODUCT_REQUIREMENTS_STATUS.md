# HOMEii Product Requirements Status

This file is the release truth source. A capability may be marked complete only when its backend flow, UI, authorization, error state, mobile layout, translation, and automated verification are all present.

## Implemented baseline

- React/Vite primary interface and additive migration from 5.x data.
- Protected external Web login on port 8383 and authenticated Home Assistant Ingress.
- Admin, operator, and viewer roles with edge-to-edge viewer mode.
- Background monitoring with a separate 50-percent-faster critical-device cycle.
- Device inventory search, status filters, sorting, card/table views, manual add, clone, and per-device scan profiles.
- Real rolling 24-hour availability strips and historical daily summaries.
- Recycle lifecycle: offline after 48 hours, 14-day retention, automatic recovery, and permanent tombstones.
- Automatic rotating SQLite backups with three retained copies (restore verification is still a release gap).
- New-disconnect toast and sound only, plus persistent-outage reminders.
- Category on-demand check, availability score, online/total ratio, device list, and disconnect ranking.

## Partial - must be deepened before commercial readiness

- Control room: live health and priority queue exist; operator journal, escalation workflow, wall-display density presets, incident ownership, and SLA timers remain incomplete.
- Alerts: acknowledge, resolve, severity and clear-resolved exist; incident deduplication, reopen state, quiet hours, escalation policy, delivery tracking, and notification testing remain incomplete.
- Categories and tags: definitions, rename propagation, colors and icon rendering are implemented; reorder, a centralized assignment picker, and bulk assignment remain incomplete.
- Audit: mutations and state changes are recorded; filters, pagination, detail drawer, export, retention, correlation IDs, and before/after values remain incomplete.
- History: day through year summaries exist; traffic rollups, category comparisons, incident overlays, export, and drill-down remain incomplete.
- Network tools: ping, trace, ports, DNS, speed, free-IP and traffic summaries exist; streamed continuous tests, saved test profiles, baselines, anomaly comparison, and human-readable remediation remain incomplete.
- User management: roles and two permissions exist; granular permission policies, password reset, forced logout, session list, and account audit remain incomplete.
- Settings: core 5.x parameters are retained; validation summaries, unsaved-change protection, restore workflow, help content, and consistent success/error states remain incomplete.
- Home Assistant: entities, diagnostics, blueprints and example cards exist; revocable API token, reauthentication, integration tests, and supported HACS packaging remain incomplete.

## Missing or release-blocking

- Route-level frontend code splitting and virtualized inventory for 1,000-plus devices.
- React component tests and Playwright desktop/mobile/Ingress tests.
- API authorization and validation tests for every role and mutation.
- Container startup/build tests for amd64 and aarch64.
- Restore-tested backup workflow and operator recovery runbook.
- Structured metrics/support bundle and monitoring SLO dashboard.
- Durable device identity model where MAC is primary and IP is an address history.
- Service-aware probes and optional Windows agent architecture.
- Accessibility QA at 320, 390, 768, 1440 and 4K in Hebrew/English and every theme.

## Release gates

1. No feature is described as complete from UI presence alone.
2. Every mutation requires a server-side role test and an audit record.
3. Every screen requires loading, empty, error, permission, stale-data, and success states.
4. Every release must pass Python tests, React build, container startup, mobile smoke tests, and migration tests.
5. Changelog entries must reference only acceptance-tested behavior.
