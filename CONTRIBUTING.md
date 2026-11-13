# Contributing to Argus

> Argus is proprietary software (see [`LICENSE`](LICENSE)). Contributions are accepted only by prior
> written agreement with the copyright holder. This guide documents the workflow for those authorised
> to work on the codebase.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e . --no-deps
pre-commit install          # ruff, formatting, mypy and secret checks before every commit
```

## Quality gates (all enforced in CI)

Tool versions are pinned in `requirements-dev.txt` so local runs, pre-commit and CI agree.

```bash
ruff check argus tests      # lint, incl. bandit security rules
ruff format argus tests     # formatting
mypy argus                  # static types
pytest --cov=argus          # tests; fails below 85 % coverage
```

Tests never touch the internet: collectors are exercised with recorded-style API
responses (`tests/test_modules_offline.py`), and network behaviour against local servers.

## Changing the database schema

1. Edit the ORM models in `argus/storage/db.py`.
2. Generate a migration and **review it** (autogenerate is a draft, not gospel):

   ```bash
   python - <<'PY'
   from alembic import command
   from sqlalchemy import create_engine
   from argus.storage.migrate import alembic_config
   with create_engine("sqlite:///scratch.db").begin() as conn:
       command.upgrade(alembic_config(conn), "head")
       command.revision(alembic_config(conn), message="describe the change", autogenerate=True, rev_id="0002")
   PY
   ```

3. `tests/test_migrations.py` fails if models and migrations ever disagree.

Migrations run automatically when the server starts.

## Writing a collector module

Subclass `argus.modules.base.BaseModule`, implement `run()` as an async generator yielding
`Entity` and `Relation` objects, use the provided `session` (`HttpClient`: retries, rate limits
and the SSRF guard come for free), call `self.report_error()` / `self.report_ok()` for non-HTTP
sources, and add a parsing test with recorded responses.

## Releasing

1. Bump `__version__` in `argus/__init__.py` (the single source of truth).
2. Add a `## [x.y.z]` section to `CHANGELOG.md`.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The release workflow verifies the tag matches the version, runs the tests, publishes the wheel
and sdist as a GitHub release (notes taken from the changelog) and pushes
`ghcr.io/<owner>/argus:X.Y.Z` to the GitHub Container Registry.

## Reporting security issues

Please follow [`SECURITY.md`](SECURITY.md) — never open a public issue for a vulnerability.
