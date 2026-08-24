# HOMEii Network Monitor 6.3.0 - Reliability and Product Audit

Audit date: 2026-08-24

## Executive assessment

HOMEii has a strong product direction, a useful monitoring model, a modern React interface and a capable Home Assistant integration. It is not yet production-grade monitoring software. The primary gap is not the number of features; it is deterministic behavior, security enforcement, automated verification and operational recovery.

Current overall readiness: **5.8/10**

The product is appropriate for controlled home and lab use. It should not yet be treated as the sole source of truth for critical network availability.

## 6.3.1 remediation status

The 6.3.1 stabilization work resolves the most immediate defects found by this audit: duplicate monitoring logic, incorrect transition alerts, import-time worker startup, accidental repeated startup scans, missing worker health, missing SQLite integrity controls, unprotected mutation routes, unpinned Python packages, missing behavioral tests, missing changelog and the retired 5.x UI source. The original score above is intentionally retained as the pre-remediation baseline.

SQLite remains the correct database for a single-instance Home Assistant app. It now uses WAL, foreign keys, busy timeouts, query indexes, integrity readiness checks, consistent online backup and automatic pre-migration backup. PostgreSQL becomes justified only if HOMEii introduces multiple writers/nodes, remote shared storage, or sustained write volume beyond a local appliance workload.

Remaining release risks are the open read-only integration API without a revocable token, legacy mutation-by-GET compatibility routes, limited test depth, the monolithic backend module, the monolithic frontend bundle and the absence of a container build test in CI.

## Scorecard

| Area | Score | Assessment |
| --- | ---: | --- |
| Product concept | 8.5/10 | Clear value and strong Home Assistant fit. |
| Network discovery | 6.5/10 | Useful multi-source discovery, but ICMP/ARP behavior and identity confidence need formalization. |
| Availability monitoring | 5.0/10 | Background monitoring works, but duplicate logic and a notification-state bug undermine trust. |
| Data model and history | 6.0/10 | SQLite WAL, migrations and retention exist; integrity, backup and aggregation need work. |
| Alerts | 5.0/10 | Good concepts, but event generation is not currently deterministic in every transition. |
| Backend architecture | 4.5/10 | A 3,700-line module mixes API, workers, scanning, auth, storage and tools. |
| API security | 3.5/10 | Web login exists, but most legacy API routes remain unauthenticated and mutations use GET. |
| Home Assistant integration | 6.5/10 | Config Flow, coordinator, devices, entities and diagnostics exist; tests and lifecycle features are missing. |
| Web UI and UX | 7.0/10 | Strong visual direction; oversized components, duplicate legacy UI and incomplete accessibility remain. |
| Mobile stability | 6.0/10 | Incremental rendering reduces crashes; bundle size and large monolithic renders remain risks. |
| Packaging and releases | 4.5/10 | Versioning and CI build exist; dependencies are not pinned and release verification is weak. |
| Automated tests | 1.5/10 | CI compiles and builds only; behavior is largely untested. |
| Observability and support | 4.5/10 | Logs and diagnostics exist; health, readiness, metrics and support bundles are incomplete. |
| Documentation | 5.5/10 | README and examples exist; operator guide, limitations and recovery runbook are missing. |

## P0 - Must fix before calling the product reliable

### 1. Fix monitoring state-transition notifications

`monitor_one_safe` only assigns `post_action` inside the branch that first changes an online device to unstable. The nested offline and online branches can therefore never execute in that location. A device can change database state without the expected alert or recovery workflow.

Required change:

- Implement one authoritative state machine for `new`, `online`, `offline`, `unstable`, `quarantined` and `maintenance`.
- Persist the transition and its reason in one transaction.
- Emit the event and alert from the committed transition result.
- Add tests for every state pair, thresholds, maintenance, muted alerts and recovery.

Acceptance criterion: 100% of simulated transitions produce exactly one expected history record and no duplicate or missing alert.

### 2. Remove duplicate monitoring implementations

Both `monitor_one` and `monitor_one_safe` implement similar but different behavior. Only one must remain. Parallel implementations guarantee behavioral drift and make fixes difficult to verify.

Required change:

- Extract `ProbeResult`, `DeviceState`, `MonitoringPolicy` and `TransitionResult` models.
- Keep network I/O outside the database lock.
- Apply a single state-transition function inside a short transaction.

### 3. Start workers exactly once

Background workers are started during module import and again in the FastAPI startup event. The in-process thread guard reduces duplication in one process, but import-time side effects are unsafe for tests, reloads and multi-worker deployments.

Required change:

- Replace deprecated `@app.on_event` startup with FastAPI lifespan management.
- Start and stop workers only inside lifespan.
- Add cooperative cancellation and graceful shutdown.
- Enforce a single application worker or introduce a database-backed leader lease.

Acceptance criterion: repeated imports and application restarts never create duplicate monitor cycles.

### 4. Enforce authorization on the API

The React UI is gated by login, but most monitoring and mutation routes remain callable without a session. A user on the network can potentially scan, alter, quarantine or approve devices without using the UI.

Required change:

- Create authenticated read and write scopes.
- Require `admin` for settings, users, reconciliation, network tools and destructive actions.
- Require `admin` or `user` for device edits and alert acknowledgement.
- Permit `viewer` read-only endpoints only.
- Give the Home Assistant integration a revocable API token and reauthentication flow.
- Rate-limit login and diagnostic tools.
- Restrict Ingress traffic according to Home Assistant's proxy model, not headers alone.

Acceptance criterion: an unauthenticated request cannot read private inventory or mutate any data; every role has server-side authorization tests.

### 5. Replace mutation-by-GET routes

Routes such as scan, accept, remove, restore, update, toggle and save settings use GET. GET can be prefetched, cached, repeated or triggered by crawlers and violates HTTP semantics.

Required change:

- `POST` for actions, `PATCH` for edits, `DELETE` for destructive operations.
- Validate bodies with Pydantic models.
- Return consistent error objects and status codes.
- Keep temporary compatibility shims with deprecation logs for one release only.

### 6. Build a real automated test suite

Current CI only compiles Python and builds React. It does not verify scanning, migrations, auth, history, API behavior or Home Assistant entities.

Minimum required suites:

- Unit tests for probing policy and state transitions.
- SQLite migration tests starting from representative 5.x and 6.x databases.
- API tests for authentication, authorization, validation and concurrency.
- Worker tests with deterministic time and mocked probes.
- Home Assistant Config Flow, coordinator, entity and service tests.
- React component tests for role navigation, forms and empty/error/loading states.
- Playwright desktop, mobile and Ingress-path smoke tests.
- Container startup and health-check test on `amd64` and `aarch64`.

Release gate: no release with failing tests; target at least 80% backend coverage initially and 95% for the integration.

## P1 - Required for production readiness

### Packaging and reproducible builds

- Replace `ghcr.io/home-assistant/base:latest` with the supported architecture-aware `BUILD_FROM` pattern and pinned release inputs.
- Pin Python dependencies with hashes or a lock file.
- Keep `npm ci`, add dependency audit and license checks.
- Build and test the exact container artifact in CI.
- Add container health and readiness checks.
- Publish signed release notes and checksums.

### Database reliability

- Keep WAL and busy timeout, but add `foreign_keys=ON` for every connection.
- Add indexes based on measured history and alert queries.
- Run startup integrity checks and expose the result in diagnostics.
- Add online backup, restore verification and automatic pre-migration backup.
- Add migration rollback guidance and schema compatibility tests.
- Aggregate old minute-level samples into hourly/daily rollups before pruning.

### Monitoring accuracy

- Separate discovery from availability monitoring.
- Define confidence per protocol: ICMP, ARP/neighbour table, TCP service, DNS and optional agent.
- Never label a device offline based on one protocol when its configured profile expects another.
- Add per-device maintenance windows, debounce, hysteresis and configurable recovery confirmation.
- Record probe latency, protocol, result, failure reason and scheduler delay.
- Detect scheduler lag and report stale monitoring rather than displaying old data as current.
- Use MAC as the durable identity where available; IP should be an address, not the primary identity.

### Alert reliability

- Deduplicate open alerts by device, type and incident.
- Model incidents with opened, acknowledged, muted, resolved and reopened timestamps.
- Track notification delivery attempts and failures.
- Add escalation policies and quiet hours.
- Ensure maintenance suppresses notifications without destroying history.
- Provide a test notification button and delivery health panel.

### Operational observability

- Add `/health/live` and `/health/ready`.
- Expose worker last cycle, duration, queue size, probe errors, stale-device count and database health.
- Use structured JSON logging with correlation and incident IDs.
- Add a redacted support bundle containing configuration, versions, worker health and recent errors.
- Display “monitoring stale” prominently when workers miss their service-level objective.

## P2 - Product and UX modernization

### Remove the legacy UI source

The project previously contained React in `ui/` and a second large application in `web/index.html`. The legacy editable Web application was removed during the 6.3.1 stabilization cycle so React is now the only interface source.

Required change:

- Keep only generated React assets in the image.
- Keep editable interface logic exclusively in `ui/`.
- Put all branding assets under one source directory.

### Split the frontend

`App.jsx` contains most screens and behavior in one approximately 50 KB file. The production JavaScript bundle is about 648 KB and Vite warns about chunk size.

Required change:

- Route-level lazy loading for Dashboard, Viewer, Devices, History, Tools and Settings.
- Feature folders with components, hooks and API schemas.
- Virtualized device lists for hundreds or thousands of devices.
- Abort stale requests and prevent overlapping refresh cycles.
- WebSocket or Server-Sent Events for live state instead of full polling refreshes.

### Consistent product states

Every screen and form must define:

- Loading skeleton.
- Empty state with one clear action.
- Permission-denied state.
- Recoverable error with retry.
- Offline/stale-data state.
- Success confirmation for mutations.

### Light theme

The current light theme still needs a measured contrast pass rather than more color experimentation.

- Meet WCAG AA contrast for text, controls and chart labels.
- Use opaque chart surfaces and stronger axes in light mode.
- Test Hebrew and English at 320, 390, 768, 1440 and 4K widths.
- Avoid font sizes below 12 px for operational data.

### Scrolling

Visual scrollbars are hidden globally as requested while wheel, touch and keyboard scrolling remain available. Hidden scrollbars reduce discoverability, so long screens should still use internal pagination, sticky section navigation and visible “more” affordances.

### User workspaces

- Admin: configuration, users, tools, reconciliation and all editing.
- User: dashboards, devices, alerts and permitted operational actions.
- Viewer: read-only dashboards, categories and incidents.
- Persist per-user language, theme, dashboard layout and viewer filters.
- Add session list, forced logout, password change and audit log.
- Add kiosk/edge display token with expiry and revocation instead of a permanent unrestricted link.

## Home Assistant integration gap analysis

Present strengths:

- UI Config Flow.
- DataUpdateCoordinator.
- Unique entity IDs and entity names.
- Devices, sensors, binary sensors, buttons and diagnostics.
- Service actions registered during integration setup.

Required upgrades:

- Store runtime objects in `ConfigEntry.runtime_data`.
- Add full Config Flow test coverage.
- Add reconfigure and reauthentication flows.
- Mark entities unavailable when the add-on API is stale or unreachable.
- Log unavailable and recovered once per incident.
- Translate entity names, icons and exceptions using current HA patterns.
- Add Repairs issues for unreachable add-on, invalid token and incompatible API version.
- Redact URL, IP, MAC, names and tokens from diagnostics as appropriate.
- Document update frequency, supported entities, limitations, troubleshooting and removal.
- Add dynamic-device and stale-device lifecycle tests.

These items align with the current Home Assistant Integration Quality Scale. Bronze is the first target; Silver should be the release target for a dependable custom integration.

## Recommended delivery plan

### Phase A - Reliability baseline

Duration target: 1 release cycle.

- Fix the transition bug.
- Remove duplicate monitor logic.
- Add lifespan-managed workers.
- Introduce Pydantic API models and authenticated methods.
- Add backend unit/API/migration tests.
- Add health/readiness endpoints.

Exit gate: seven days of accelerated simulation without missed or duplicate incidents.

### Phase B - Secure Home Assistant contract

- Version the API under `/api/v1`.
- Add integration API tokens and reauth.
- Enforce roles server-side.
- Add integration tests and HA Repairs.
- Maintain one-release compatibility adapters for old services.

Exit gate: legacy routes can be disabled without losing any integration feature.

### Phase C - Data confidence and observability

- Durable device identity.
- Protocol-aware profiles.
- Incident model and notification delivery tracking.
- Database backup, restore and integrity UI.
- Worker health and monitoring-stale alerts.

Exit gate: every displayed status can explain when, how and why it was determined.

### Phase D - Premium UX

- Remove legacy Web UI.
- Split and lazy-load React routes.
- Add virtualized device rendering and live event streaming.
- Complete light-theme and accessibility audit.
- Add role-specific dashboards and kiosk provisioning.

Exit gate: automated visual and interaction tests pass on mobile, desktop, Ingress and PWA.

### Phase E - Release engineering

- Reproducible multi-architecture images.
- Dependency and security scanning.
- Signed tags and generated release notes.
- Upgrade, rollback and disaster-recovery runbooks.
- Beta and stable release channels.

## Definition of trustworthy

HOMEii should only be described as dependable when all of the following are true:

1. A status transition is deterministic and fully tested.
2. A stopped or delayed monitor is visible as stale, never silently healthy.
3. All private data and mutations require server-side authorization.
4. Upgrades preserve data and are tested from every supported schema.
5. Backup and restore are verified, not merely available.
6. The integration reports API failure as unavailable and guides recovery.
7. The same release artifact passes desktop, mobile, Ingress and architecture tests.
8. Every release has a changelog, rollback path and known-limitations section.

## Immediate recommendation

Do not add agents, SNMP, traffic analytics or more network tools in the next release. First complete Phase A and Phase B. Adding more inputs before the monitoring state machine, API contract and test suite are stable increases the failure surface and makes the product harder to trust.
