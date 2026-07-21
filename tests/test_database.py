"""Tests for the Database context manager and connection lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest

from ovs_logs.config.settings import Settings, settings as _default_settings
from ovs_logs.core.database import (
    ALLOWLIST_TABLE,
    Database,
    _ensure_allowlist_table,
    insert_allowlisted_indicator,
    is_allowlisted,
)

# ---------------------------------------------------------------------------
# In-memory sessions
# ---------------------------------------------------------------------------


class TestInMemory:
    """Tests for ``Database(\":memory:\")`` sessions."""

    def test_connect_returns_duckdb_connection(self) -> None:
        db = Database(":memory:")
        conn = db.connect()
        try:
            assert isinstance(conn, duckdb.DuckDBPyConnection)
        finally:
            conn.close()

    def test_connect_is_idempotent(self) -> None:
        db = Database(":memory:")
        conn1 = db.connect()
        conn2 = db.connect()
        try:
            assert conn1 is conn2
        finally:
            conn1.close()

    def test_context_manager_returns_connection(self) -> None:
        with Database(":memory:") as conn:
            result = conn.execute("SELECT 1 AS x").fetchone()
            assert result is not None
            assert result[0] == 1

    def test_context_manager_closes_on_exit(self) -> None:
        db = Database(":memory:")
        with db as conn:
            conn.execute("CREATE TABLE test (x INTEGER)")
        with pytest.raises(duckdb.Error):
            conn.execute("SELECT 1")

    def test_path_property(self) -> None:
        db = Database(":memory:")
        assert db.path == ":memory:"

    def test_execute_query(self) -> None:
        db = Database(":memory:")
        conn = db.connect()
        try:
            conn.execute("CREATE TABLE t (v INTEGER)")
            conn.execute("INSERT INTO t VALUES (10), (20), (30)")
            row = conn.execute("SELECT SUM(v) FROM t").fetchone()
            assert row is not None
            assert row[0] == 60
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# File-based sessions
# ---------------------------------------------------------------------------


class TestFileBased:
    """Tests for persistent file-based database sessions."""

    def test_creates_database_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        with Database(db_path) as conn:
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.execute("INSERT INTO t VALUES (1)")
        assert db_path.exists()

    def test_data_persists_across_sessions(self, tmp_path: Path) -> None:
        db_path = tmp_path / "persist.db"
        with Database(db_path) as conn:
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.execute("INSERT INTO t VALUES (42)")
        with Database(db_path) as conn:
            row = conn.execute("SELECT x FROM t").fetchone()
            assert row is not None
            assert row[0] == 42

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c" / "deep.db"
        with Database(nested) as conn:
            conn.execute("SELECT 1")
        assert nested.exists()

    def test_path_property(self, tmp_path: Path) -> None:
        db_path = tmp_path / "custom.db"
        db = Database(db_path)
        assert db.path == db_path

    def test_write_then_read_round_trip(self, tmp_path: Path) -> None:
        db_path = tmp_path / "roundtrip.db"
        with Database(db_path) as conn:
            conn.execute("CREATE TABLE events (ts TIMESTAMP, ip VARCHAR)")
            conn.execute("INSERT INTO events VALUES (CURRENT_TIMESTAMP, '1.2.3.4')")
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            assert row is not None
            assert row[0] == 1


# ---------------------------------------------------------------------------
# Settings dependency injection
# ---------------------------------------------------------------------------


class TestSettingsInjection:
    """Tests for the ``db_settings`` parameter."""

    def test_db_settings_overrides_default_path(self, tmp_path: Path) -> None:
        """When no path is given, ``db_settings.database.path`` is used."""
        expected = tmp_path / "injected" / "ovs_logs.db"
        custom_db = _default_settings.database.__class__(path=str(expected))
        custom_settings = Settings(
            abuseipdb=_default_settings.abuseipdb,
            llm=_default_settings.llm,
            thresholds=_default_settings.thresholds,
            database=custom_db,
            text_parse=_default_settings.text_parse,
            threat_lists=_default_settings.threat_lists,
        )
        db = Database(db_settings=custom_settings)
        assert db.path == expected

    def test_explicit_path_overrides_db_settings(self, tmp_path: Path) -> None:
        """An explicit ``path`` argument takes precedence over ``db_settings``."""
        explicit = tmp_path / "explicit.db"
        wrong = tmp_path / "wrong.db"
        custom_db = _default_settings.database.__class__(path=str(wrong))
        custom_settings = Settings(
            abuseipdb=_default_settings.abuseipdb,
            llm=_default_settings.llm,
            thresholds=_default_settings.thresholds,
            database=custom_db,
            text_parse=_default_settings.text_parse,
            threat_lists=_default_settings.threat_lists,
        )
        db = Database(explicit, db_settings=custom_settings)
        assert db.path == explicit

    def test_no_path_no_settings_falls_back_to_global(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When neither path nor db_settings are given, ``settings.database.path`` is used."""
        custom_db = _default_settings.database.__class__(path=":memory:")
        custom_settings = Settings(
            abuseipdb=_default_settings.abuseipdb,
            llm=_default_settings.llm,
            thresholds=_default_settings.thresholds,
            database=custom_db,
            text_parse=_default_settings.text_parse,
            threat_lists=_default_settings.threat_lists,
        )
        monkeypatch.setattr("ovs_logs.config.settings.settings", custom_settings)
        db = Database()
        assert str(db.path) == ":memory:"
        with db as conn:
            result = conn.execute("SELECT 1").fetchone()
            assert result is not None


# ---------------------------------------------------------------------------
# Connection lifecycle: manual connect + context manager interactions
# ---------------------------------------------------------------------------


class TestConnectionLifecycle:
    """Tests for the mixed-mode pattern (manual ``connect()`` + ``with``)."""

    def test_manual_connect_then_context_reuses_same_connection(self) -> None:
        db = Database(":memory:")
        conn_manual = db.connect()
        try:
            with db as conn:
                assert conn is conn_manual
        finally:
            conn_manual.close()

    def test_manual_connect_survives_context_exit(self) -> None:
        """A connection opened via ``connect()`` is **not** closed by ``__exit__``."""
        db = Database(":memory:")
        conn_manual = db.connect()
        with db:
            pass
        # Connection should still be usable after context exits
        conn_manual.execute("SELECT 1")
        conn_manual.close()

    def test_close_resets_managed_flag(self) -> None:
        """After ``close()``, a subsequent context manager creates a fresh managed connection."""
        db = Database(":memory:")
        conn1 = db.connect()
        db.close()
        with db as conn2:
            assert conn2 is not conn1
            conn2.execute("SELECT 1")

    def test_double_close_is_idempotent(self) -> None:
        db = Database(":memory:")
        db.connect()
        db.close()
        db.close()  # should not raise

    def test_context_manager_twice(self) -> None:
        """Using the same Database instance in two ``with`` blocks works."""
        db = Database(":memory:")
        with db as conn1:
            conn1.execute("CREATE TABLE t (x INTEGER)")
            conn1.execute("INSERT INTO t VALUES (1)")
        with db as conn2:
            # In-memory — data is lost after close, but the connection itself works
            conn2.execute("SELECT 1")

    def test_execute_after_close_reconnects(self) -> None:
        """Calling ``connect()`` again after ``close()`` returns a new connection."""
        db = Database(":memory:")
        conn1 = db.connect()
        db.close()
        conn2 = db.connect()
        assert conn2 is not conn1
        conn2.execute("SELECT 1")
        conn2.close()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error scenarios."""

    def test_invalid_path_raises_on_connect(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "nonexistent" / "subdir" / "test.db")
        # Parent directory is created, so connecting to a nested path works
        with db as conn:
            assert conn is not None


# ---------------------------------------------------------------------------
# Allowlisted indicators
# ---------------------------------------------------------------------------


class TestAllowlistedIndicators:
    """Tests for the ``allowlisted_indicators`` table and helpers."""

    def test_allowlist_table_created_idempotently(self) -> None:
        with Database(":memory:") as conn:
            _ensure_allowlist_table(conn)
            _ensure_allowlist_table(conn)  # second call must not raise

    def test_insert_and_query_allowlisted_indicator(self) -> None:
        with Database(":memory:") as conn:
            _ensure_allowlist_table(conn)
            insert_allowlisted_indicator(
                conn,
                id="test-uuid",
                indicator="10.0.0.1",
                indicator_type="ip",
                description="Internal DNS server",
                metadata={"source": "admin"},
            )
            table = ALLOWLIST_TABLE
            row = conn.execute(
                f'SELECT "id", "indicator", "indicator_type", "description", "metadata" FROM "{table}"'
            ).fetchone()
            assert row is not None
            assert row[0] == "test-uuid"
            assert row[1] == "10.0.0.1"
            assert row[2] == "ip"
            assert row[3] == "Internal DNS server"
            assert json.loads(row[4]) == {"source": "admin"}

    def test_is_allowlisted_true(self) -> None:
        with Database(":memory:") as conn:
            _ensure_allowlist_table(conn)
            insert_allowlisted_indicator(
                conn,
                id="uuid-1",
                indicator="1.2.3.4",
                indicator_type="ip",
            )
            assert is_allowlisted(conn, "1.2.3.4") is True
            assert is_allowlisted(conn, "1.2.3.4", "ip") is True

    def test_is_allowlisted_false(self) -> None:
        with Database(":memory:") as conn:
            _ensure_allowlist_table(conn)
            assert is_allowlisted(conn, "5.6.7.8") is False
            assert is_allowlisted(conn, "5.6.7.8", "ip") is False

    def test_is_allowlisted_true_with_type_scope(self) -> None:
        """Entry of type 'ip' should not match a query for type 'hostname'."""
        with Database(":memory:") as conn:
            _ensure_allowlist_table(conn)
            insert_allowlisted_indicator(
                conn,
                id="uuid-2",
                indicator="10.0.0.1",
                indicator_type="ip",
            )
            assert is_allowlisted(conn, "10.0.0.1", "hostname") is False
            assert is_allowlisted(conn, "10.0.0.1", "ip") is True
