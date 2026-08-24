# HOMEii Home Assistant Blueprints

Copy these files into:

`/config/blueprints/automation/homeii/`

Then in Home Assistant:

1. Go to `Settings > Automations & Scenes > Blueprints`
2. Import or reload the blueprints
3. Create automations from the HOMEii blueprints

Included blueprints:

- `homeii_device_change_notifications.yaml`
  - Notifies when devices go offline, come back online, become unstable, or are newly discovered.
- `homeii_open_alert_notifications.yaml`
  - Notifies when new HOMEii alerts are opened.

Recommended entity inputs:

- `sensor.homeii_network_monitor_disconnected_devices_details`
- `sensor.homeii_network_monitor_unstable_devices_details`
- `sensor.homeii_network_monitor_new_devices_details`
- `sensor.homeii_network_monitor_open_alerts_details`

Tip:

Use a notification action sequence such as `notify.mobile_app_<your_phone>` or any action chain you prefer.
