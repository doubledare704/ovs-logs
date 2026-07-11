"""Local DuckDB connection management for OVS-Log."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ovs_logs.config.settings import Settings, settings


class Database:
    """Manages a local DuckDB connection for persistent or in-memory sessions.

    Use as a context manager to obtain a connection that is automatically closed:

        with Database(":memory:") as conn:
            conn.execute("...")

    For persistent storage, the default path is ``.ovs_logs/ovs_logs.db``.
    """

    def __init__(self, path: str | Path | None = None, *, db_settings: Settings | None = None) -> None:
        if path is None:
            cfg = db_settings or settings
            path = Path(cfg.database.path)
        self._path = path
        self._connection: duckdb.DuckDBPyConnection | None = None

    def __enter__(self) -> duckdb.DuckDBPyConnection:
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

    @property
    def path(self) -> str | Path:
        return self._path

    def connect(self) -> duckdb.DuckDBPyConnection:
        """Open (or reuse) a DuckDB connection."""
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
        """Close the active connection if one is open."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
