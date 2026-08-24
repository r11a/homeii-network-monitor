# HOMEii Network Monitor Roadmap v5

## Vision

Build HOMEii Network Monitor into a polished Home Assistant-first product:

- Reliable enough to trust device down/up detection
- Clear enough to understand network state in seconds
- Modern enough to feel like a real product, not only an addon
- Structured enough to support HA entities, services, dashboards, and long-term maintenance

## Product Pillars

1. Reliability
- Accurate detection for down, back online, unstable, and new devices
- Low false positives
- Stable database behavior and clear diagnostics

2. Clean UX
- Fast, readable screens with strong visual hierarchy
- Light and dark themes with the same quality level
- Fewer clicks for common actions

3. HA-Native Experience
- Integration, entities, services, notifications, diagnostics
- Lovelace cards and viewer screens designed for Home Assistant users

4. Data Portability
- Import/export for devices and settings
- Easy backup, restore, and migration

## Phase 1: Core Stability

Goal: make the engine trustworthy before adding more product surface.

### Deliverables
- Harden online/offline detection thresholds
- Add explicit recovery logic for "back online"
- Improve unstable-device detection
- Clear alert rules for:
  - new device
  - device offline
  - device back online
  - unstable device
- System health block:
  - last successful scan
  - target IP count
  - monitored networks count
  - DB status
  - last error

### Success criteria
- User can trust state changes without noisy false alerts
- Alerts clearly explain what happened and when
- Scans report what they actually tried to scan

## Phase 2: UI Redesign

Goal: turn the current UI into a clean, premium monitoring interface.

### Deliverables
- True light theme
- Refined dark theme
- New dashboard layout with stronger KPI cards
- Better device cards and cleaner table styling
- Stronger status colors and iconography
- Cleaner settings screens with grouped sections

### UX rules
- No clutter
- No duplicate controls
- Status must be readable from distance
- Important events should stand out immediately

## Phase 3: Live Viewer

Goal: add a read-only screen for real-time awareness.

### Deliverables
- Viewer page with no editing controls
- Real-time list of:
  - offline devices
  - devices back online
  - unstable devices
  - new devices
- Activity feed / timeline
- Wall-display friendly layout

### Use cases
- Tablet on wall
- Fast glance inside HA
- Family-safe or viewer-only access

## Phase 4: Data Management

Goal: make the product operationally comfortable.

### Deliverables
- Export devices to CSV/Excel
- Import devices from CSV/Excel
- Export settings to JSON
- Import settings from JSON
- Backup/restore workflow

### Import fields
- display name
- category
- notes
- assigned network
- tags
- critical / pinned flags

## Phase 5: Home Assistant Integration

Goal: make the product feel native inside Home Assistant.

### Deliverables
- Complete custom integration
- Counter sensors:
  - total
  - online
  - offline
  - new
  - unstable
  - critical
- Per-device availability entities by choice
- HA services:
  - scan
  - approve
  - ignore
  - pin
  - mark critical
- Diagnostics payloads
- Better config flow

## Phase 6: Lovelace Product Layer

Goal: create an end-user dashboard experience inside HA.

### Deliverables
- Lovelace card set:
  - overview card
  - offline devices card
  - new devices card
  - unstable devices card
  - recent activity card
- Optional example dashboard package
- Viewer-oriented dashboard composition

## Phase 7: Hardening and Release

Goal: prepare for stable public use.

### Deliverables
- Smoke tests
- Better logging and diagnostics
- Edge-case handling for large networks
- Clear release notes
- Version discipline and upgrade flow

## Priority Order

1. Stability and alert trust
2. Light/dark redesign
3. Viewer page
4. Import/export
5. Full HA integration
6. Lovelace cards

## Immediate Next Sprint

1. Restore a true light theme
2. Redesign dashboard KPIs and summary areas
3. Improve alert semantics for offline / back online / unstable / new
4. Add a first Viewer page shell
