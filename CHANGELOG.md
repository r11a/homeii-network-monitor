# Changelog

## 7.1.4

- Fixed a Control Room render crash when more than four disconnected devices are present.
- Added a protected recovery screen with retry and sign-out controls so restricted users can never be trapped on a blank screen.

## 7.1.3

- Fixed the empty black screen that could appear after signing in with a Control account or an edge-to-edge Viewer account.
- Added explicit read authorization for the complete Control-room data set and reduced limited-role bootstrap requests to the data required by that screen.
- Resolved conflicting edge-to-edge layout rules and made the branded account, theme, logout and user-switch bar persist above the Control room.
- Added a deterministic Viewer route fallback so restricted accounts cannot resolve to an unavailable page.

## 7.1.2

- Reorganized the Control room around a clear operational hierarchy: fleet status and categories first, priority outages next, followed by the live health timeline.
- Offline devices are ordered by urgency and outage duration, shown in a four-column grid, and initially limited to the four highest-priority incidents.
- Added an inline show-more/show-less control for larger outage queues and reduced chart and journal density to keep the primary view within one screen where possible.

## 7.1.1

- Added an administrator-only operational reset with a pre-reset database backup, acknowledgement, exact confirmation phrase, administrator credential verification and final confirmation.
- Reset removes devices, availability history, alerts, events and traffic samples while preserving users, permissions, networks, labels and system settings.
- Extended duplicate prevention to explicit device names in addition to IP and MAC identities across manual onboarding, CSV import, Kuma import and device approval.
- Generic discovery names such as `Device 123` are intentionally excluded from name collision checks so legitimate automatic discovery remains reliable.

## 7.1.0

- Added a dedicated, admin-only Uptime Kuma JSON backup importer with a safe preview and explicit confirmation step.
- Import now maps unique ping and port monitor IPs to HOMEii devices, maps Kuma tags to categories and tags, and preserves scan cadence as a HOMEii scan profile.
- Existing HOMEii devices are never overwritten; duplicate Kuma monitors are merged and groups, unsupported monitors, notification settings and secrets are ignored.
- Added localized import summaries for new, existing, duplicate and unsupported records, plus audit and system-log entries for committed imports.

## 7.0.6

- Expanded the Control-room health timeline to the full content width and reduced its height.
- Added a persistent theme switcher to the Control-room top bar for Granite, Navy, and Light modes.

## 7.0.5

- Rebuilt Control-room offline-device tiles around a large, untruncated device name.
- Reduced each tile to device name, category, and the exact disconnection date and time.
- Replaced diagnostic copy with a clean visual urgency rail.

## 7.0.4

- Fixed logout visibility for viewer accounts configured for the edge-to-edge Control room.
- Control-room identity actions now follow the active display mode instead of relying on the role name.

## 7.0.3

- Added an always-visible logout and user-switch button to the Control room header.
- Kept the logout icon visible in the mobile edge-to-edge layout.

## 7.0.2

- Moved Control-room branding and account switching into the persistent application shell.
- Ensured the edge-to-edge header remains visible independently of live-data rendering.

## 7.0.1

- Fixed Control room data loading for the restricted `control` role.
- Made secondary dashboard data resilient so one optional API failure no longer clears the live view.
- Added HOMEii branding and a secure user-switch action to the edge-to-edge Control room.

## 7.0.0

- Rebuilt the product hierarchy around three immediate questions: what is offline now, what requires attention, and how health changes over time.
- Replaced the duplicated dashboard hero, KPI, fleet, event and alert surfaces with a focused operational overview.
- Introduced the V7 clarity design system for consistent spacing, typography, controls, panels, forms, modals and responsive behavior.
- Simplified everyday screens for non-technical users while preserving advanced network and administration capabilities in contextual details and Settings.
- Standardized actions: one primary action, one contextual secondary action and an overflow menu for advanced or destructive operations.
- Reworked light-theme contrast and mobile layouts, including horizontal overflow protection and visually hidden scrollbars.

## 6.9.0

- Added the read-only `Control` role, locked to an edge-to-edge command-center experience while preserving command-center navigation for existing roles.
- Rebuilt the disconnected-device queue as clear operational tiles sorted by outage duration and a continuous urgency scale from 0 to 6.
- Expanded the control-room category section with live available-versus-total counts, 24-hour health and drill-down access.
- Enforced route-level UI isolation so Control accounts cannot open other application screens through direct URLs.

## 6.8.3

- Added a dashboard list and inventory filter for devices that joined recently, based on their persisted first-seen timestamp.
- Connected device cards to 24 hourly availability points and exposed whether the timeline is backed by recorded history or the current-state estimate.
- Added a visible, status-colored fallback for devices that do not yet have historical status samples instead of rendering an unexplained empty strip.

## 6.8.2

- Hardened external Cloudflare authentication by honoring the real forwarded client IP, HTTPS proxy chains and explicit browser credentials.
- Added administrator user deletion with protection for the primary account, current session and last active administrator.

## 6.8.1

- Connected every device inventory response to its real 24-hour availability timeline so health strips update from recorded status history.
- Added admin-only single and bulk device deletion with identity tombstones to prevent deleted devices from being rediscovered immediately.
- Added inline creation of shared colored categories and tags from device onboarding and device editing.

## 6.8.0

- Replaced embedded user and device creation forms with focused, responsive onboarding dialogs.
- Added manual-device identity preflight, immediate reachability feedback, category assignment, shared tags and scan-profile selection.
- Added grouped device administration with inline name, category and tag editing plus review and bulk acceptance of newly discovered devices.
- Added persistent alert rules using trigger, condition and action definitions, including offline, critical, unstable, recovery and new-device triggers.
- Added a filterable audit console for user, device, test, alert and administrative activity.
- Added automatic and manual database backups with configurable retention and `/data` or Home Assistant `/share` storage.
- Expanded the reusable category and tag icon library and retained system-wide colors and labels.
- Upgraded the database schema to version 10 with an automatic pre-migration backup while preserving all 5.x/6.x data.
- Removed obsolete presentation and alert controls from General settings and consolidated them into their correct workspaces.

## 6.7.0

- Rebuilt the device editor as a responsive, theme-aware workspace with live health, availability, disconnect and last-check context.
- Connected device categories and tags to the shared system label library and enabled creating reusable colored tags directly from the editor.
- Added manual-device identity preflight and conflict reporting for duplicate IP and MAC addresses.
- Preserved managed-device identity and metadata when a known MAC address moves to a new IP.
- Reworked inventory reconciliation so reachable unmanaged devices remain reviewable while unreachable unmanaged noise is removed instead of filling quarantine.
- Added identity regression tests for duplicate detection and safe IP migration.

## 6.6.1

- Fixed startup migration from 5.x databases by adding missing device columns before creating indexes that depend on them.
- Added a real legacy-schema migration regression test that verifies existing device data and pre-upgrade backups are preserved.

## 6.6.0

- Replaced the nested settings page with a dedicated full-screen administration workspace and one right-side navigation system.
- Added a continuous device-onboarding workspace with immediate reachability feedback, category, scan profile and critical-device controls.
- Added Uptime Kuma-inspired category and tag management with editable names, colors and icons.
- Propagated category visual identity into command-center cards and preserved device assignments during category changes.
- Restructured the device editor footer and category detail surfaces into consistent product panels.
- Added a release-truth requirements matrix so partial capabilities are no longer described as complete.

## 6.5.1

- Rebuilt settings into a consistent, compact administrative workspace across desktop and mobile.
- Redesigned network tools as a visual diagnostics workbench with contextual targets, assessments, metrics and per-tool charts.
- Fixed recycled devices being rediscovered after permanent deletion by retaining invisible discovery tombstones.
- Added an administrator inventory cleanup that suppresses offline records and duplicate MAC identities while retaining the most reliable record.

## 6.5.0

- Rebuilt the command center around live fleet health, prioritized outages, unacknowledged incidents, operator acknowledgement and a dynamic event journal.
- Added a real rolling 24-hour health timeline instead of calculating future hours in the current calendar day.
- Made category availability scores prominent and added clear available-versus-total counts.
- Limited audible alerts to new device disconnects and added a prominent device-detail disconnect toast.
- Corrected device-tile health score overflow and connected the score to measured 24-hour availability.
- Corrected mobile history layout containment so charts and navigation cannot shift or split the page.
- Added control-room typography and responsive layouts for mobile, desktop and large wall displays.
- Kept alert acknowledgement permission-aware for administrators and explicitly authorized operators.

## 6.4.0

- Moved direct Web access to port `8383`; the external console requires a HOMEii username and password while Home Assistant Ingress continues to use the authenticated HA identity.
- Added category and tag definitions, device cloning, category checks, alert acknowledgement, audit logging and administrator operations.
- Added recycle-bin lifecycle management for long-offline devices and automatic rotating SQLite backups.
- Expanded dashboard health visualization, incident presentation and operational controls.
- Added category and device health drill-downs with real 24-hour availability, disconnect rankings, last-check timestamps and on-demand checks.
- Standardized the entire interface on bundled Heebo typography with accessible mobile sizing and corrected contrast tokens for light and dark themes.
- Expanded audit coverage to user actions, manual checks, category checks and automatic device state changes.

## 6.3.2

- Split the oversized application entry point into dedicated API, configuration, security, state-machine, and runtime modules while retaining the existing ASGI entry point.
- Added a professional device inventory with card/table views, search, sorting, filters, and administrator-only manual device creation.
- Redesigned device cards around operational state, health, identity, network assignment, scan profile, and real 24-hour availability data.
- Added a lightweight server-sent event stream so device and alert changes refresh the interface immediately without overlapping refresh requests.
- Improved mobile device inventory layout and stopped presenting missing availability history as synthetic 100% uptime.

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
