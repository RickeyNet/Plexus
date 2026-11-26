# Contributing to Plexus

Thanks for helping improve Plexus. Bug reports, documentation fixes, tests, and code changes are welcome. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Search [open issues](https://github.com/RickeyNet/Plexus/issues) and [pull requests](https://github.com/RickeyNet/Plexus/pulls) for related work. For a new feature or a large change, open an issue first so we can agree on scope.
- Use the [issue templates](https://github.com/RickeyNet/Plexus/issues/new/choose) for bugs and feature requests. Report suspected vulnerabilities privately by following the [security policy](SECURITY.md).
- Use synthetic or redacted examples. Do not commit `.env`, keys, tokens, database dumps, or real device configurations.

## Develop and test

1. Fork the repository and create a branch from `main`.
2. Follow [DEVSETUP.md](DEVSETUP.md) for Python 3.14 and PostgreSQL 16. Frontend work also needs Node.js 26.
3. Follow the repository conventions in [AGENTS.md](AGENTS.md) and, for React work, [FRONTEND_STYLE.md](FRONTEND_STYLE.md). Reuse existing helpers, add regression tests for behavior changes, and update affected documentation. For vendor changes, update fixtures, the vendor guide, and the [monitoring coverage matrix](docs/vendor-monitoring-coverage.md) as applicable.
4. Run the applicable checks from [CI](.github/workflows/ci.yml) and record what you ran. For Python, run `ruff check .`, `mypy netcontrol templates`, and relevant `pytest` targets. Set `PLEXUS_TEST_PG_URL` to a disposable database ending in `_test`; the suite drops and recreates it. For frontend changes, run `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` from `netcontrol/static/frontend/`. For documentation changes, run `python tools/build_wiki.py --check`.

## Open a pull request

Target `main` and keep the change focused. Explain what changed and why, link the relevant issue, and list exact verification commands and results. Include sanitized screenshots for visible UI changes. Call out migrations, new settings, or upgrade and rollback considerations when applicable. If you could not run a check, say which one and why.
