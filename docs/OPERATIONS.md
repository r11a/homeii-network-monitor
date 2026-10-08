# Operational workspace

## Navigation and workflow

- **Overview:** latest device counts, critical attention, prioritized issues and category distribution. Selecting a device opens its existing editor; selecting a category filters inventory. Personal dashboard preferences remain available in the expandable section.
- **Control center:** keeps the existing per-user layouts, category visibility and density controls. Categories and disconnected devices occupy the main display. Freshness is shown independently from device state.
- **Devices:** existing rapid add flow remains available from inventory and settings. Add sends a probe and saves the device to its category, then clears the form for the next device. An unreachable device is still saved for monitoring.
- **History:** day, week, month and longer windows show the full selected period, subject to retention. A failed request does not substitute another period's report.
- **Reports:** period, category and name/IP filters apply to the table, counts and CSV export. CSV includes the time window and calculation method, uses UTF-8 with BOM, and neutralizes spreadsheet formula prefixes. Tables are paginated at 20 rows.
- **Settings / Users:** account search, role descriptions, last sign-in, activation, role changes and password reset. Mutations show errors and avoid duplicate submissions. Password, role and alert-permission changes revoke existing sessions; disabling an account also revokes them. Primary administrator protections remain in place.
- **Settings / Audit log:** server-recorded actions, actors and outcomes; searchable across the latest 500 records. Legacy administrative GET actions are recorded as well as POST/PATCH/DELETE requests. Passwords and request bodies are not included.
- **Settings / System:** worker heartbeat, lifecycle count and most recent error are visible alongside database status.

The 7.5 Aura interface keeps navigation in a floating dock on desktop and a menu on mobile. Device names open the existing editor. The monitoring column distinguishes permanently retained devices (approved or manually added), discovered devices and suspended monitoring; a discovered device can still be probed according to discovery settings. Long inventories scroll inside the table and load 48 rows at a time. Recent devices and the personal dashboard expand on demand.

## Reading monitoring status

Device status and monitoring health are different signals. The banner distinguishes current data, initial loading, a failed server connection, expired refresh data and degraded workers. A failed connection preserves the last known inventory with an explicit warning. A green device from an old snapshot is not proof that it is still reachable.

Client data becomes stale after the greater of 45 seconds or twice the configured refresh period plus 15 seconds. The server independently evaluates worker heartbeats. This cannot detect a crashed display/browser: an external watchdog is needed if the display itself must be supervised.

## History and availability

The database stores **state transitions**, not every raw ping result. Availability is a duration-weighted estimate within the portion of the selected window supported by retained state history. Online is weighted at 100%, offline at 0%, and the existing unstable/new states at 50%. Unknown states are excluded. Reports do not invent data before device creation, the first available transition, or the configured retention boundary. Without sufficient evidence, availability is null and the UI displays an em dash.

History coverage is the portion of the requested device-time window supported by this state reconstruction. It does **not** prove that probes ran continuously. Monitoring-engine downtime between transitions cannot be reliably reconstructed from the existing schema. The reports are therefore not SLA evidence, packet loss statistics, service-level checks or proof that a security camera is recording. Current inventory defines report membership; deleted, ignored or quarantined devices are not included.

Newly added or imported devices without history receive an initial state record on the next qualifying monitoring probe, even when their status does not change. Until then, their current reachability can be shown while historical availability remains unknown.

## Security and deployment limits

At the owner's explicit request, the existing local Home Assistant integration is preserved: **GET `/api/ha/dashboard` remains available without authentication and exposes inventory/status data**. This is a known exception, not an authenticated integration. Do not expose this endpoint or the application port directly to untrusted networks. An authenticated integration is a separate migration.

The application also trusts Home Assistant ingress identity headers. A trusted ingress/reverse proxy must prevent clients from supplying those headers and must be the only path to any externally reachable instance. Direct exposure can permit impersonation. Use TLS at the trusted access point; the application does not itself provide encrypted transport simply because it has a login screen.

The local audit database is editable by a server administrator and is not a tamper-proof audit trail. Redundant monitoring, independent alert delivery, centralized logs, recovery drills, load testing at the intended device count, and a deployment-specific security review are still required before treating this installation as an operationally assured security system. This UI update does not claim certification, high availability or commercial SLA compliance.

## Validation

Run `npm run build` and `npm test` in `ui`, plus `python -m pytest tests -q` at the project root. Regression coverage includes consecutive device entry, report errors and late responses, unknown/partial history, full report windows, CSV safety, user protections and session revocation. Browser verification uses an isolated database; test devices and simulated worker state must never be interpreted as production measurements.
