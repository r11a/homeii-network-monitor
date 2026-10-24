# Engine workspace completion
Goal: restore useful operations around the Zabbix inventory without a second monitoring source.
- Extend existing engine with host metadata editing, pause/resume and period reports.
- Add reports, diagnostics and user/audit navigation using existing components where valid.
- Keep backups explicit about PostgreSQL versus legacy SQLite; rely on HA full addon backup.
- Verify API permissions, engine contracts, UI tests and production build; publish beta.
Deferred: arbitrary remote server commands and untested enterprise-scale claims.
