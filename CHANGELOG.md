# Changelog

## 6.3.1

- Added the missing Home Assistant add-on changelog.
- Hid visual scrollbars while preserving wheel, touch and keyboard scrolling.
- Replaced the duplicate settings sidebar with compact in-page tabs and moved sign-out into the account menu.
- Added a full reliability, security, architecture and UX audit.
- Removed the retired HOMEii 5 HTML/CSS interface while retaining one-time data migration support.
- Replaced import-time worker startup with a managed FastAPI lifespan and graceful shutdown.
- Unified automatic device-state transitions so background monitoring, history and alerts agree.
- Added worker-stall detection, liveness/readiness endpoints and Home Assistant Supervisor watchdog support.
- Hardened SQLite with WAL, foreign keys, busy timeouts, operational indexes, integrity checks and pre-migration backups.
- Added authenticated role enforcement for all settings, diagnostics, imports, exports and device-changing actions.
- Added an administrator-only consistent SQLite backup download endpoint.
- Added reliability tests and exact Python dependency versions to CI and container builds.
- Improved Home Assistant coordinator concurrency, reconfiguration and redacted diagnostics.

## 6.3.0

- Added protected Web UI login and first-run administrator setup.
- Added administrator, user and viewer roles with account management.
- Added an edge-to-edge, read-only viewer workspace for control-room displays.
- Improved Home Assistant Ingress identity handling without requiring a second login.
- Reduced mobile device-page memory pressure with incremental card rendering.
- Reworked device forms and dialogs for full-screen mobile and near-full-screen desktop use.
- Improved device tiles, responsive typography and light-theme contrast.
- Preserved existing devices, settings, history, alerts and integration entities through additive database migration.

## 6.2.1

- Added administrator inventory reconciliation.
- Added automatic quarantine recovery for devices that become reachable again.
- Added discovery settings and clearer network-tool result summaries.

## 6.2.0

- Added the HOMEii 6 operational dashboard and history experience.
- Added improved device discovery, quarantine and network-management workflows.
- Added updated Home Assistant entities, cards and diagnostics.

## 6.1.0

- Redesigned the primary operational experience and navigation.
- Added premium HOMEii branding and responsive monitoring views.

## 6.0.1

- Corrected HOMEii branding across the add-on, browser assets and PWA.

## 6.0.0

- Migrated the main interface to React 19 and Vite.
- Added the Granite design system, professional charts and unified icon language.
- Added additive database migrations that retain HOMEii 5.x monitoring data.
