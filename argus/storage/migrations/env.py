"""Alembic environment.

Migrations run programmatically from :func:`argus.storage.migrate.upgrade_database`,
which hands us an open connection via ``config.attributes["connection"]``. Running
``alembic`` from the command line also works (it builds a connection from the URL).
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from argus.storage.db import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,  # SQLite cannot ALTER most things; batch mode rebuilds tables safely
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    _configure(connection)
else:  # pragma: no cover - CLI usage with a synchronous driver URL
    engine = engine_from_config(
        config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with engine.connect() as conn:
        _configure(conn)
