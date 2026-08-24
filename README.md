<p align="center">
  <img src="docs/brand/homeii-logo-premium.png" alt="HOMEii Network Monitor logo" width="210">
</p>
<h1 align="center">HOMEii Network Monitor</h1>
<p align="center"><strong>Premium network intelligence for Home Assistant</strong></p>

## 6.1 product experience

- Three focused workspaces: administrator, user and control-room/NOC.
- Drill-down category monitoring with live device availability.
- Historical intelligence with real retention data, incident rankings and date ranges.
- Visual network diagnostics for ping, trace, DNS, ports, speed and free addresses.
- Functional device control with scan profiles, operational flags and ping feedback.
- Rebuilt responsive settings and high-contrast Granite/Porcelain themes.

<p align="center"><strong>Network intelligence built natively for Home Assistant.</strong><br>Discover, classify and monitor every device with real-time alerts, historical availability and a premium NOC interface.</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-6.3.2-c47a3b?style=for-the-badge">
  <img alt="Home Assistant" src="https://img.shields.io/badge/Home%20Assistant-Add--on%20%2B%20Integration-41BDF5?style=for-the-badge&logo=homeassistant&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/UI-React%2019-27e6a4?style=for-the-badge&logo=react&logoColor=07110d">
  <img alt="License" src="https://img.shields.io/github/license/r11a/homeii-network-monitor?style=for-the-badge&color=ffb52e">
</p>

## HOMEii 6

Version 6 combines a React 19 control plane with the proven FastAPI scanner, SQLite history engine and native Home Assistant entities. The granite design system is responsive, bilingual and built for daily administration and always-on wall displays.

| Capability | Included |
| --- | --- |
| Network discovery | Multiple CIDR networks, automatic and manual scans |
| Device intelligence | Vendor, hostname, category, critical and quarantine states |
| Reliability | Background monitoring, scan profiles and 24-hour availability |
| Incident workflow | New, offline, unstable and recovery alerts |
| NOC interface | Live KPIs, category health, history and semantic charts |
| Diagnostics | Ping, traceroute, DNS, ports and internet speed tests |
| Home Assistant | Sensors, binary sensors, buttons, services and diagnostics |
| Languages | Full RTL Hebrew and English support |

## Architecture

```text
Home Assistant
├── HOMEii Add-on
│   ├── FastAPI monitoring engine
│   ├── SQLite devices, events and history
│   └── React 19 + Vite premium web interface
└── HOMEii Integration
    ├── Counter and list entities
    ├── Per-device availability
    └── Scan and control services
```

The backend remains the monitoring authority. React consumes the existing API, so upgrading the interface does not replace or reset the scanner database.

## Install The Add-on

1. Open **Settings > Add-ons > Add-on Store** in Home Assistant.
2. Add `https://github.com/r11a/homeii-network-monitor` as a custom repository.
3. Install **HOMEii Network Monitor**.
4. Start the add-on and open its Web UI or Ingress panel.

On the first direct Web UI visit, HOMEii asks you to create the primary administrator. Later visits require a username and password. Home Assistant Ingress uses the authenticated Home Assistant user and currently opens with the administrator workspace, without a second login.

Administrators can create `admin`, `user` and `viewer` accounts under **Settings > Users**. Viewer accounts can be locked to an edge-to-edge, read-only control-room display.

## Install The Integration

1. Copy `custom_components/homeii_network_monitor` to `/config/custom_components/`.
2. Restart Home Assistant.
3. Open **Settings > Devices & services > Add integration**.
4. Search for **HOMEii Network Monitor** and enter the add-on URL.

Ready-made cards and dashboards are available in [`examples/home_assistant`](examples/home_assistant/README.md).

## Upgrade From 5.x

The database remains at `/data/homeii/homeii.db`. On startup, 6.3.2 applies additive, idempotent migrations and records schema version `7` in `schema_migrations`. Devices, settings, alerts, events, traffic samples and historical availability are retained.

Back up the add-on before a major upgrade as a normal operational precaution. No destructive migration is performed by HOMEii 6.

## Development

```powershell
cd ui
npm install
npm run dev
npm run build
cd ..
python -m compileall app custom_components
```

Read the [UI architecture](UI_ARCHITECTURE_V6.md), [reliability audit](docs/AUDIT_6.3.0.md) and [contribution guide](CONTRIBUTING.md) for implementation details.

## API

Primary endpoints include `/api/status`, `/api/devices`, `/api/alerts`, `/api/events`, `/api/settings`, `/api/history/summary`, `/api/ha/entities` and `/api/ha/diagnostics`.

## Security

Network diagnostics can reach local infrastructure and should only be exposed through trusted Home Assistant access. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

HOMEii Network Monitor is available under the [MIT License](LICENSE).

<p align="center"><img src="docs/brand/homeii-logo-premium.png" width="84" alt="HOMEii mark"><br><sub>Designed and maintained by HOMEii.</sub></p>
