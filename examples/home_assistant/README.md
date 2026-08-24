# HOMEii Network Monitor for Home Assistant

This folder contains ready-to-use examples for Home Assistant dashboards and custom Lovelace cards.

## What you get from the integration

After copying `custom_components/homeii_network_monitor` into Home Assistant and restarting, the integration exposes:

- Summary sensors such as:
  - `sensor.homeii_network_monitor_connected_devices`
  - `sensor.homeii_network_monitor_disconnected_devices`
  - `sensor.homeii_network_monitor_unstable_devices`
  - `sensor.homeii_network_monitor_new_devices`
  - `sensor.homeii_network_monitor_open_alerts`
- Detail sensors with ready-made lists inside their attributes:
  - `sensor.homeii_network_monitor_disconnected_devices_details`
  - `sensor.homeii_network_monitor_unstable_devices_details`
  - `sensor.homeii_network_monitor_new_devices_details`
  - `sensor.homeii_network_monitor_open_alerts_details`
  - `sensor.homeii_network_monitor_category_summary`
  - `sensor.homeii_network_monitor_network_summary`
- Per-device binary sensors:
  - availability
  - unstable
  - new
  - critical
  - pinned
- Action buttons:
  - scan now
  - refresh data
  - accept all new devices

## Detail sensor attributes

The detail sensors expose useful attributes:

- `count`
- `items`
- `names`
- `ips`
- `summary`

Example:

- `sensor.homeii_network_monitor_disconnected_devices_details`
  - `state`: number of disconnected devices
  - `attributes.items`: full objects with name, IP, category, vendor, last_seen, etc.

## Dashboard example

Use `dashboard_cards.yaml` as a starting point for a Lovelace dashboard or a manual card stack.
Some entity IDs may need slight adjustment depending on your exact entity names in Home Assistant.

## Custom cards

The `cards/` folder contains custom Lovelace cards:

- `homeii-overview-card.js`
- `homeii-device-list-card.js`
- `homeii-category-health-card.js`
- `homeii-dynamic-board-card.js`
- `homeii-category-board-card.js`

### Manual install

1. Copy the files from `cards/` into:
   - `/config/www/homeii/`
2. Add Lovelace resources:
   - `/local/homeii/homeii-overview-card.js`
   - `/local/homeii/homeii-device-list-card.js`
   - `/local/homeii/homeii-category-health-card.js`
   - `/local/homeii/homeii-dynamic-board-card.js`
   - `/local/homeii/homeii-category-board-card.js`
3. Add the cards manually or start from `custom_card_dashboard.yaml`

### Included custom card example

Use `custom_card_dashboard.yaml` as a starting point for a dedicated HOMEii dashboard using the custom cards.
Use `dynamic_board_card.yaml` for a single dynamic card with clickable counters and a filtered device list.
Use `category_board_card.yaml` for a dynamic category board with clickable category cards and category device lists.
