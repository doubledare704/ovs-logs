"""Local DuckDB connection management for OVS-Log."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ovs_logs.config import settings as _cfg
from ovs_logs.config.settings import Settings


class Database:
    """Manages a local DuckDB connection for persistent or in-memory sessions.

    Use as a context manager to obtain a connection that is automatically closed:

        with Database(":memory:") as conn:
            conn.execute("...")

    For persistent storage, the default path is ``.ovs_logs/ovs_logs.db``.

    Note: Calling ``connect()`` manually and *then* entering the context
    manager is safe — the context manager will **not** close a connection
    that was opened externally, since ``__exit__`` only closes when
    ``__enter__`` created the connection.
    """

    def __init__(self, path: str | Path | None = None, *, db_settings: Settings | None = None) -> None:
        if path is None:
            cfg = db_settings or _cfg.settings
            path = Path(cfg.database.path)
        self._path = path
        self._connection: duckdb.DuckDBPyConnection | None = None
        self._managed_by_enter: bool = False

    def __enter__(self) -> duckdb.DuckDBPyConnection:
        # Only mark as managed if no external connection exists — a manual
        # connect() call before entering the context means the caller owns
        # the lifecycle and __exit__ must not close it.
        if self._connection is None:
            self._managed_by_enter = True
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        if self._managed_by_enter:
            self.close()
            self._managed_by_enter = False

    @property
    def path(self) -> str | Path:
        return self._path

    def connect(self) -> duckdb.DuckDBPyConnection:
        """Open (or reuse) a DuckDB connection.

        Calling this method manually outside a ``with`` block is supported.
        Connections opened this way will **not** be closed when the context
        manager exits (if you later wrap usage in ``with``).
        """
        if self._connection is not None:
            return self._connection

        if self._path == ":memory:":
            self._connection = duckdb.connect(database=":memory:")
        else:
            p = Path(self._path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._connection = duckdb.connect(database=str(p))

        return self._connection

    def close(self) -> None:
        """Close the active connection if one is open.

        Also resets the ``_managed_by_enter`` flag so that a subsequent
        ``__enter__`` → ``connect()`` → ``__exit__`` cycle works correctly.
        """
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        self._managed_by_enter = False
