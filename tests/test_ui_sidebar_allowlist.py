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

from ovs_logs.core.database import (
    insert_allowlisted_indicator,
    list_allowlisted_indicators,
)

from .conftest import launch_app, make_db, text_input_by_label

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def test_allowlist_empty_state_shows_caption(tmp_path: Path) -> None:
    """When the allowlist table is empty, a caption should be shown."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = launch_app(APP_PATH, db)

    assert not at.exception
    captions = [c.value for c in at.sidebar.caption]
    assert any("No allowlisted IPs yet" in cap for cap in captions)


def test_allowlist_add_ip(tmp_path: Path) -> None:
    """Adding an IP via the sidebar should persist it to the DB."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = launch_app(APP_PATH, db)

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

    at = launch_app(APP_PATH, db)

    allowlist_input = text_input_by_label(at, "IP to allowlist")
    allowlist_input.set_value("10.0.0.50").run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    has_warning = any("already in the allowlist" in w.value for w in at.sidebar.warning)
    assert has_warning, "Expected a warning about duplicate allowlist entry"


def test_allowlist_delete_ip_direct_db(tmp_path: Path) -> None:
    """Deleting an allowlist entry should remove it via the sidebar control."""
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

    at = launch_app(APP_PATH, db)

    delete_key = f"allowlist_delete_{entry_id}"
    at.sidebar.button(key=delete_key).click().run()

    assert not at.exception
    with duckdb.connect(str(db)) as conn:
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

    at = launch_app(APP_PATH, db)

    assert not at.exception
    with duckdb.connect(str(db)) as conn:
        entries = list_allowlisted_indicators(conn)
    ips = {e["indicator"] for e in entries}
    for i in range(3):
        assert f"10.0.0.{i + 1}" in ips


def test_allowlist_empty_db_path_shows_info(tmp_path: Path) -> None:
    """With an explicit empty DB path, the section should show an info message."""
    at = launch_app(APP_PATH, "")

    assert not at.exception
    has_info = any("Set a database path to manage" in i.value for i in at.sidebar.info)
    assert has_info


def test_allowlist_add_empty_input_shows_warning(tmp_path: Path) -> None:
    """Clicking 'Add to allowlist' with an empty input should show a warning."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = launch_app(APP_PATH, db)

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    has_warning = any("Enter a valid IP address" in w.value for w in at.sidebar.warning)
    assert has_warning, "Expected a warning about entering a valid IP address"


def test_allowlist_add_malformed_ip_shows_warning(tmp_path: Path) -> None:
    """Submitting a non-IP value should show a warning and not persist."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = launch_app(APP_PATH, db)

    allowlist_input = text_input_by_label(at, "IP to allowlist")
    allowlist_input.set_value("not-an-ip").run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    has_warning = any("Enter a valid IP address" in w.value for w in at.sidebar.warning)
    assert has_warning, "Expected a warning for malformed IP input"

    with duckdb.connect(str(db)) as conn:
        entries = list_allowlisted_indicators(conn)
    assert not entries, "Malformed IP should not be persisted"


def test_allowlist_add_ipv6_normalized(tmp_path: Path) -> None:
    """An IPv6 address with surrounding whitespace should be stored in canonical form."""
    db = make_db(tmp_path, [("events", "SELECT 1 AS id")])

    at = launch_app(APP_PATH, db)

    allowlist_input = text_input_by_label(at, "IP to allowlist")
    allowlist_input.set_value("  2001:db8::1  ").run()

    add_btn = next(btn for btn in at.sidebar.button if btn.label == "Add to allowlist")
    add_btn.click().run()

    assert not at.exception
    with duckdb.connect(str(db)) as conn:
        entries = list_allowlisted_indicators(conn)
    stored = {e["indicator"] for e in entries}
    assert "2001:db8::1" in stored, "Expected canonical IPv6 address to be persisted"
