# Contributing

1. Fork the repository and create a focused branch from `main`.
2. Preserve API compatibility and existing SQLite migrations.
3. Use Lucide React icons and the semantic tokens in `ui/src/styles.css`.
4. Run `npm run build` inside `ui` and `python -m compileall app custom_components`.
5. Describe behavior changes, migration impact and verification in the pull request.

Do not commit databases, logs, generated UI bundles or Home Assistant secrets.
