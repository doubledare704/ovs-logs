"""Tests for the allowlist management sidebar panel (_render_sidebar_allowlist).

Verifies that the "Allowlist" section in the sidebar renders correctly:
- Add/delete flows
- Empty-state rendering
- Duplicate-entry warning
- Integration with the database
"""

from __future__ import annotations

import uuid
from pathlib import Path

import duckdb
from streamlit.testing.v1 import AppTest

from ovs_logs.core.database import (
    delete_allowlisted_indicator,
    insert_allowlisted_indicator,
    list_allowlisted_indicators,
)

from .conftest import make_db, text_input_by_label

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def test_allowlist_empty_state_shows_caption(tmp_path: Path) -> None:
    """When the allowlist table is empty, a caption should be shown."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    assert not at.exception
    captions = [c.value for c in at.sidebar.caption]
    assert any("No allowlisted IPs yet" in cap for cap in captions)


def test_allowlist_add_ip(tmp_path: Path) -> None:
    """Adding an IP via the sidebar should persist it to the DB."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    allowlist_input = text_input_by_label(at, "IP to allowlist")
    allowlist_input.set_value("10.0.0.50").run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    # Verify the IP is now in the database (this is the authoritative check)
    with duckdb.connect(str(db)) as conn:
        entries = list_allowlisted_indicators(conn)
    assert any(e["indicator"] == "10.0.0.50" for e in entries)


def test_allowlist_add_duplicate_shows_warning(tmp_path: Path) -> None:
    """Adding a duplicate IP should show a warning, not a success."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    with duckdb.connect(str(db)) as conn:
        insert_allowlisted_indicator(
            conn,
            indicator_id=str(uuid.uuid4()),
            indicator="10.0.0.50",
            indicator_type="ip",
        )

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    allowlist_input = text_input_by_label(at, "IP to allowlist")
    allowlist_input.set_value("10.0.0.50").run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    has_warning = any("already in the allowlist" in w.value for w in at.sidebar.warning)
    assert has_warning, "Expected a warning about duplicate allowlist entry"


def test_allowlist_delete_ip_direct_db(tmp_path: Path) -> None:
    """Deleting an allowlist entry should remove it from the DB.

    Tests delete at the database level since AppTest cannot reliably
    locate buttons rendered inside ``st.sidebar.columns``.
    """
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    entry_id = str(uuid.uuid4())
    with duckdb.connect(str(db)) as conn:
        insert_allowlisted_indicator(
            conn,
            indicator_id=entry_id,
            indicator="10.0.0.99",
            indicator_type="ip",
        )
        assert any(e["indicator"] == "10.0.0.99" for e in list_allowlisted_indicators(conn))

        # Delete the entry directly via DB
        delete_allowlisted_indicator(conn, entry_id)
        entries = list_allowlisted_indicators(conn)
        assert not any(e["indicator"] == "10.0.0.99" for e in entries)


def test_allowlist_multiple_entries_in_db(tmp_path: Path) -> None:
    """Multiple allowlist entries should all be persisted in the DB."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    with duckdb.connect(str(db)) as conn:
        for i in range(3):
            insert_allowlisted_indicator(
                conn,
                indicator_id=str(uuid.uuid4()),
                indicator=f"10.0.0.{i + 1}",
                indicator_type="ip",
            )

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    assert not at.exception
    with duckdb.connect(str(db)) as conn:
        entries = list_allowlisted_indicators(conn)
    ips = {e["indicator"] for e in entries}
    for i in range(3):
        assert f"10.0.0.{i + 1}" in ips


def test_allowlist_empty_db_path_shows_info(tmp_path: Path) -> None:
    """With an explicit empty DB path, the section should show an info message."""
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value("").run()

    assert not at.exception
    has_info = any("Set a database path to manage" in i.value for i in at.sidebar.info)
    assert has_info


def test_allowlist_add_empty_input_shows_warning(tmp_path: Path) -> None:
    """Clicking 'Add to allowlist' with an empty input should show a warning."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    has_warning = any("Enter a valid IP address" in w.value for w in at.sidebar.warning)
    assert has_warning, "Expected a warning about entering a valid IP address"
