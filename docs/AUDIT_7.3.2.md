# UI stability audit — 7.3.2

## Root cause

The Add device dialog inside Settings referenced `manualResult`, a state variable belonging to the separate inventory component. The invalid reference was only evaluated when opening the dialog. Vite compiled the code successfully, but rendering the dialog threw a ReferenceError. Settings also sat outside the application page error boundary.

## Fixes

- Use the Settings device component's own operation result and keep its form mounted after successful additions.
- Permit direct Add without a prerequisite Ping. One POST validates identity, performs the ping and saves the category, critical flag, scan profile and tags together. Remove the preflight/update/second-ping chain.
- Keep input on validation/conflict errors; clear fields and focus IP after success, including saved-but-unreachable devices. Prevent duplicate submissions and closing while pending.
- Preserve normalized IPv6 addresses when storing tags; reject invalid options before probing or writing.
- Wrap Settings in the existing page error boundary.
- Run undefined-variable and undefined-JSX checks as part of every production build. Run component tests in CI and include the lint config in the Docker build stage.

## Verification coverage

29 component regression tests cover all six main pages, all eleven Settings sections, user/viewer/control roles, both add-device entry points with two consecutive additions and validation failures, customization/category visibility, uncategorized detail, device details and cloning, category editing, user/rule dialogs, Settings during delayed initial data and Settings navigation. Mocked API responses isolate rendering and interaction behavior.

32 backend tests cover state transitions and previous reliability behavior, plus atomic manual-entry options, normalized IPv6 tags and validation before probing. Real browser checks use a separate loopback-only database and include the previously failing Settings dialog and consecutive additions. Production build includes lint; the existing bundle-size warning remains.

No production database, network configuration, credentials or Home Assistant installation is changed by the local audit. Full Docker/HA deployment and long-running network behavior are not claimed by these checks. Unrelated local Home Assistant integration edits remain outside this release.
