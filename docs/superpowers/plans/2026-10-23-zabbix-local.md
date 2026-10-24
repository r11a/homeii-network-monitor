# HOMEii 8 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. User authorized implementation and repository publication; do not add approval checkpoints.

**Goal:** ship a reversible local Zabbix workspace with graphical operation and offline deployment support.
**Architecture:** existing FastAPI authentication + isolated Zabbix adapter + dedicated React workspace; Zabbix/PostgreSQL in a local Compose stack. Existing legacy UI/data remain accessible to admins.
**Tech Stack:** Python stdlib HTTP, FastAPI, React, CSS, Docker Compose, Zabbix 7.0 LTS.
**Spec:** docs/superpowers/specs/2026-10-23-zabbix-local-design.md

## Global Constraints
- Preserve legacy SQLite and routes; no secrets in responses or settings exports.
- No Internet required at runtime; offline installation requires prepared images.
- No green status without fresh measurement; stable IDs use hostid.
- No claim of 5,000-device validation without actual load run.

## Review Focus
- Expired credentials/engine downtime retain explicit stale state, never invented recovery.
- Duplicate IPs and host address changes do not create alternate monitored identities silently.
- Missing/disabled/unsupported probes and partial history show unknown/coverage.
- Viewer permissions cannot mutate or read credentials; bootstrap endpoints remain admin-only.
- Discovery/host creation is bounded, serialized and repeatable; failed writes are not silently retried.

## Tasks
- [ ] Backup source + refs, remote tag; baseline suites. Work in dedicated branch in current checkout (existing dependencies, no concurrent edits).
- [ ] Adapter tests RED, then API client, atomic private config, cached snapshots, measured histories, discovery and host actions. Real HTTP fixture covers protocol/errors and limits.
- [ ] Authenticated endpoints + role tests; engine mode disables legacy scanning only after successful setup. Existing data backup before activation.
- [ ] React form/workspace tests RED; implement clear setup, control/inventory/events, detail/history, discovery and editing. Run UI suite/build.
- [ ] Offline Compose/bootstrap/launcher, HA stable-ID cards and bridge, version/docs, deployment validation workflow.
- [ ] Full suites, fresh independent review, fixes, commit/push branch and PR; attach PR. Keep main unchanged until verified integration.

## Execution record
- Final review fixes: ingress identity is accepted only from the Supervisor peer, with proxy-header rewriting disabled; deterministic engine host names enforce concurrent create uniqueness; open dialogs use the latest inventory and refresh history; HA token support, open-event normalization and stable entity IDs added. Ingress/duplicate/dialog regressions observed RED then GREEN. Local suite: 60 backend + 52 UI; production build passed. HA runtime integration still requires on-site validation.
- Ruling: user requested a testable single add-on; replace Compose with bundled Linux services. Publish separate beta slug and port on the feature branch, leaving main and existing data untouched. Native HA installation/cards and full IT tooling remain preview limitations documented in DOCS.md.
- Current local validation: 59 backend tests, 51 UI tests and production build passed before final review. Linux CI caught missing PCRE selection; explicitly selected PCRE2.
- Final review: fix untrusted ingress headers, live dialog state, concurrent host uniqueness, and authenticated HA payload/client compatibility. Regression tests reproduce ingress and concurrency issues and the stale dialog before fixes.
- Backup verified: .repo-history/pre-zabbix-20261023; remote backup/pre-zabbix-2026-10-23 at 14308030123d55831933cf4c0d93f3038b7556a1.
- UI baseline: 47 passed. Backend baseline initially blocked by missing Python dependencies; install isolated test dependencies.
- No live server exists. Deliver bundled local deployment, not merely a URL configuration page. Docker not installed on this workstation.
