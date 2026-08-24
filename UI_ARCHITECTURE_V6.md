# HOMEii UI Architecture 6.0

## Principles

- React owns rendering and interaction; FastAPI remains the monitoring authority.
- API response fields and device identifiers remain backward compatible.
- Status colors are semantic: green online, red offline, amber unstable, blue new.
- Lucide React is the only interface icon library.
- Typography is bundled for reliable Hebrew and English rendering in Ingress.
- Components use centralized CSS tokens for color, spacing, borders and elevation.

## Application areas

- Overview: health summary, SLA chart, attention queue and events.
- Command Center: dynamic category health and 24-hour availability.
- Devices: responsive asset cards, filters and device controls.
- Alerts: incident-oriented list and resolution workflow.
- History: availability and disconnect analytics.
- Network Tools: ping, trace, ports, DNS and speed diagnostics.
- Settings: language, theme, refresh, retention and system status.

## Data migration

Version 6 does not replace the database. `init_db()` applies additive migrations using
`CREATE TABLE IF NOT EXISTS`, guarded column additions and the `schema_migrations` table.
The migration is safe to run repeatedly and does not rewrite historical rows.
