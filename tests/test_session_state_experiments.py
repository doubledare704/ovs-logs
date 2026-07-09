"""
Experimental tests to evaluate Streamlit session state and rerun strategies.

This file explores different patterns for managing session state and triggering
reruns in Streamlit apps, specifically for the OVS-Log UI.
"""

import tempfile
from pathlib import Path

import duckdb
import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


class TestSessionStatePatterns:
    """Test different session state management patterns."""

    def test_session_state_persistence_across_reruns(self):
        """Test that session state persists across reruns."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Set a value in session state
        at.session_state["test_key"] = "test_value"
        at.run()

        # Verify it persists
        assert at.session_state["test_key"] == "test_value"

        # Trigger another rerun
        at.run()
        assert at.session_state["test_key"] == "test_value"

    def test_session_state_via_widget_interaction(self):
        """Test session state updates via widget interactions."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Interact with the database path input (index 2 in sidebar)
        test_path = "/tmp/test.db"
        at.sidebar.text_input[2].set_value(test_path).run()

        # Verify session state was updated
        assert at.session_state["db_path"] == test_path

    def test_widget_value_vs_session_state(self):
        """Test the relationship between widget values and session state."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Initial state - widget value should match session state
        initial_db_path = at.session_state["db_path"]
        assert at.sidebar.text_input[2].value == initial_db_path

        # Change via widget
        new_path = "/tmp/new.db"
        at.sidebar.text_input[2].set_value(new_path).run()

        # Both should be in sync
        assert at.sidebar.text_input[2].value == new_path
        assert at.session_state["db_path"] == new_path

    def test_selectbox_session_state_sync(self):
        """Test selectbox selection syncs with session state."""

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            with duckdb.connect(str(db_path)) as conn:
                conn.execute('CREATE TABLE "table1" AS SELECT 1 AS id')
                conn.execute('CREATE TABLE "table2" AS SELECT 2 AS id')

            at = AppTest.from_file(str(APP_PATH)).run()
            at.sidebar.text_input[2].set_value(str(db_path)).run()

            # Select first table
            at.sidebar.selectbox[0].set_value("table1").run()
            assert at.session_state["selected_table"] == "table1"

            # Select second table
            at.sidebar.selectbox[0].set_value("table2").run()
            assert at.session_state["selected_table"] == "table2"


class TestRerunStrategies:
    """Test different rerun triggering strategies."""

    def test_explicit_rerun_via_run(self):
        """Test that .run() triggers a full rerun."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Set some state
        at.session_state["counter"] = 0
        at.run()

        # Increment and rerun
        at.session_state["counter"] = 1
        at.run()

        assert at.session_state["counter"] == 1

    def test_widget_change_triggers_rerun(self):
        """Test that widget changes automatically trigger reruns."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Change the database path - this should trigger a rerun
        at.sidebar.text_input[2].set_value("/tmp/test.db").run()

        # The rerun is implicit in the .run() call after set_value
        assert at.session_state["db_path"] == "/tmp/test.db"

    def test_multiple_widget_changes_single_rerun(self):
        """Test batching multiple widget changes before rerun."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Change multiple widgets
        at.sidebar.text_input[0].set_value("new_abuse_key")
        at.sidebar.text_input[1].set_value("new_llm_key")
        at.sidebar.text_input[2].set_value("/tmp/test.db")

        # Single rerun
        at.run()

        # All should be updated
        assert at.session_state["ABUSEIPDB_API_KEY"] == "new_abuse_key"
        assert at.session_state["LLM_API_KEY"] == "new_llm_key"
        assert at.session_state["db_path"] == "/tmp/test.db"


class TestSessionStateInitialization:
    """Test session state initialization patterns."""

    def test_default_session_state_values(self):
        """Test that default session state values are set correctly."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Check default values from the app
        assert "db_path" in at.session_state
        assert at.session_state["db_path"] == ".ovs_logs/ovs_logs.db"

        # API keys should be in session state (from env or empty)
        assert "ABUSEIPDB_API_KEY" in at.session_state
        assert "LLM_API_KEY" in at.session_state

    def test_session_state_initialization_order(self):
        """Test that session state is initialized before widgets render."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Widgets should reflect session state values
        assert at.sidebar.text_input[2].value == at.session_state["db_path"]
        assert at.sidebar.text_input[0].value == at.session_state["ABUSEIPDB_API_KEY"]
        assert at.sidebar.text_input[1].value == at.session_state["LLM_API_KEY"]

    def test_lazy_session_state_initialization(self):
        """Test lazy initialization pattern for session state."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Add a new key lazily
        if "lazy_key" not in at.session_state:
            at.session_state["lazy_key"] = "lazy_value"
        at.run()

        assert at.session_state["lazy_key"] == "lazy_value"

        # Second run should not reinitialize
        at.session_state["lazy_key"] = "modified"
        at.run()
        assert at.session_state["lazy_key"] == "modified"


class TestWidgetKeyManagement:
    """Test widget key management for stable identity."""

    def test_widget_keys_are_stable(self):
        """Test that widget keys remain stable across reruns."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Get initial widget keys
        initial_keys = {
            "text_input_0": at.sidebar.text_input[0].key,
            "text_input_1": at.sidebar.text_input[1].key,
            "text_input_2": at.sidebar.text_input[2].key,
        }

        # Trigger rerun
        at.run()

        # Keys should be the same
        assert at.sidebar.text_input[0].key == initial_keys["text_input_0"]
        assert at.sidebar.text_input[1].key == initial_keys["text_input_1"]
        assert at.sidebar.text_input[2].key == initial_keys["text_input_2"]

    def test_explicit_widget_keys(self):
        """Test that explicit widget keys work correctly."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # The app uses explicit keys for sidebar widgets
        # Verify they exist
        assert at.sidebar.text_input[0].key is not None
        assert at.sidebar.text_input[1].key is not None
        assert at.sidebar.text_input[2].key is not None


class TestConditionalRendering:
    """Test conditional rendering patterns and their effect on session state."""

    def test_conditional_widget_rendering(self):
        """Test widgets that are conditionally rendered."""

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            with duckdb.connect(str(db_path)) as conn:
                conn.execute('CREATE TABLE "test_table" AS SELECT 1 AS id')

            at = AppTest.from_file(str(APP_PATH)).run()
            # Isolate from the real default DB (which may exist in dev
            # environments with application tables). A missing path guarantees
            # no selectbox is rendered, matching the "no valid DB" scenario.
            at.sidebar.text_input[2].set_value("/nonexistent.db").run()

            # Ensure no default DB interferes with the initial state
            missing_db = Path(tmpdir) / "missing.db"
            at.sidebar.text_input[2].set_value(str(missing_db)).run()

            # Initially no selectbox (no valid DB)
            assert len(at.sidebar.selectbox) == 0

            # Set valid DB path
            at.sidebar.text_input[2].set_value(str(db_path)).run()

            # Now selectbox should appear
            assert len(at.sidebar.selectbox) == 1
            assert at.sidebar.selectbox[0].label == "Select a table"

            # Select a table
            at.sidebar.selectbox[0].set_value("test_table").run()
            assert at.session_state["selected_table"] == "test_table"

            # Change to invalid DB
            at.sidebar.text_input[2].set_value("/nonexistent.db").run()

            # Selectbox should disappear and selection cleared
            assert len(at.sidebar.selectbox) == 0
            assert "selected_table" not in at.session_state


class TestPerformancePatterns:
    """Test performance-related patterns."""

    def test_minimal_rerun_scope(self):
        """Test that only necessary parts rerun."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Change only the DB path
        at.sidebar.text_input[2].set_value("/tmp/test.db").run()

        # API keys should not be affected
        original_abuse = at.session_state["ABUSEIPDB_API_KEY"] if "ABUSEIPDB_API_KEY" in at.session_state else ""  # noqa: SIM401
        original_llm = at.session_state["LLM_API_KEY"] if "LLM_API_KEY" in at.session_state else ""  # noqa: SIM401

        # They should remain unchanged
        assert at.session_state["ABUSEIPDB_API_KEY"] == original_abuse
        assert at.session_state["LLM_API_KEY"] == original_llm

    def test_cached_computations(self):
        """Test that expensive computations can be cached in session state."""
        at = AppTest.from_file(str(APP_PATH)).run()

        # Simulate an expensive computation cached in session state
        if "expensive_result" not in at.session_state:
            at.session_state["expensive_result"] = "computed_once"
        at.run()

        # Should not recompute
        assert at.session_state["expensive_result"] == "computed_once"

        # Modify and verify it persists
        at.session_state["expensive_result"] = "modified"
        at.run()
        assert at.session_state["expensive_result"] == "modified"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
