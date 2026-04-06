# HOMEii Network Monitor

HOMEii Network Monitor for Home Assistant.

This repository now contains two layers:

- A Home Assistant addon that scans local networks, stores device state, and exposes a web UI.
- A custom Home Assistant integration scaffold in `custom_components/homeii_network_monitor` that can consume the addon API and expose entities inside HA.

## Current focus

- Better multi-network management
- Better vendor detection from MAC addresses
- HA-ready API payloads for counters, availability, and diagnostics
- Cleaner UI behavior for refresh and dashboard density

## Addon API

The addon exposes these useful endpoints:

- `/api/status`
- `/api/devices`
- `/api/alerts`
- `/api/events`
- `/api/settings`
- `/api/ha/summary`
- `/api/ha/entities`
- `/api/ha/diagnostics`

## Home Assistant integration scaffold

The custom integration currently includes:

- Summary sensors for totals, online, offline, new, critical, pinned, and open alerts
- Availability binary sensors per discovered device
- Diagnostics support
- Config flow with URL and refresh interval

## Next recommended steps

1. Install the addon and confirm the API is reachable from Home Assistant.
2. Copy `custom_components/homeii_network_monitor` into your HA config directory.
3. Add the integration from the Home Assistant UI and point it to the addon URL.
4. Use the created sensors and binary sensors in Lovelace dashboard cards.

## Roadmap

- Add richer per-device entities and device registry metadata
- Expose HA services for scan, approve, ignore, pin, and critical actions
- Add Lovelace card examples or a dedicated dashboard package
- Continue splitting addon backend/frontend into cleaner modules
