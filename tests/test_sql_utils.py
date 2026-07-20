"""Tests for shared SQL identifier helpers in ``core/sql_utils.py``."""

from __future__ import annotations

from pathlib import Path

import pytest

from ovs_logs.core.sql_utils import (
    quote_identifier,
    resolve_table_name,
    sanitize_table_name,
    timestamp_cast_expression,
)
from ovs_logs.core.validation import LogFile

# ---------------------------------------------------------------------------
# quote_identifier
# ---------------------------------------------------------------------------


class TestQuoteIdentifier:
    """Tests for ``quote_identifier()``."""

    @pytest.mark.parametrize(
        ("identifier", "expected"),
        [
            ("events", '"events"'),
            ("raw_2026_01", '"raw_2026_01"'),
            ("_internal", '"_internal"'),
            ("a", '"a"'),
            ("z_123", '"z_123"'),
        ],
    )
    def test_valid_identifiers(self, identifier: str, expected: str) -> None:
        assert quote_identifier(identifier) == expected

    @pytest.mark.parametrize(
        ("identifier",),
        [
            ("",),
            ("1starts_with_digit",),
            ("has space",),
            ("has-dash",),
            ("has.dot",),
            ("has/ slash",),
            ("has\\backslash",),
            ("has🚀emoji",),
            ("SELECT * FROM users",),
            ("null\x00byte",),
        ],
    )
    def test_invalid_identifiers_raise(self, identifier: str) -> None:
        with pytest.raises(ValueError, match="Invalid SQL identifier"):
            quote_identifier(identifier)

    def test_double_quote_inside_escaped(self) -> None:
        """Double quotes inside the identifier are escaped according to
        DuckDB's convention (``\"\"``)."""
        # Note: identifiers with internal quotes don't match _IDENTIFIER_RE
        # so they'll raise ValueError. The escaping logic is defense-in-depth.
        with pytest.raises(ValueError):
            quote_identifier('quote"inside')


# ---------------------------------------------------------------------------
# sanitize_table_name
# ---------------------------------------------------------------------------


class TestSanitizeTableName:
    """Tests for ``sanitize_table_name()``."""

    @pytest.mark.parametrize(
        ("input_name", "expected"),
        [
            ("events", "events"),
            ("raw_2026", "raw_2026"),
            ("access.log", "access_log"),
            ("my-file", "my_file"),
            ("file name with spaces", "file_name_with_spaces"),
            ("special!@#chars", "special___chars"),
            ("dotted.path.name", "dotted_path_name"),
        ],
    )
    def test_sanitization(self, input_name: str, expected: str) -> None:
        assert sanitize_table_name(input_name) == expected

    @pytest.mark.parametrize(
        ("input_name", "expected"),
        [
            ("123abc", "_123abc"),
            ("0leading_digit", "_0leading_digit"),
            ("9", "_9"),
        ],
    )
    def test_leading_digit_prepends_underscore(self, input_name: str, expected: str) -> None:
        assert sanitize_table_name(input_name) == expected

    def test_empty_string(self) -> None:
        assert sanitize_table_name("") == "_"

    def test_all_special_chars(self) -> None:
        assert sanitize_table_name("!!!") == "___"


# ---------------------------------------------------------------------------
# resolve_table_name
# ---------------------------------------------------------------------------


class TestResolveTableName:
    """Tests for ``resolve_table_name()``."""

    def test_explicit_table_name_is_sanitized(self) -> None:
        log_file = LogFile(path=Path("test.log"), format="log", needs_conversion=False)
        assert resolve_table_name(log_file, "my-custom-name") == "my_custom_name"

    def test_explicit_name_with_special_chars(self) -> None:
        log_file = LogFile(path=Path("test.log"), format="log", needs_conversion=False)
        assert resolve_table_name(log_file, "bad name!!!") == "bad_name___"

    def test_auto_generated_format(self) -> None:
        log_file = LogFile(path=Path("access.log"), format="log", needs_conversion=False)
        result: str = resolve_table_name(log_file, None)
        assert result.startswith("raw_log_access_")
        assert len(result) > len("raw_log_access_")

    def test_auto_generated_csv(self) -> None:
        log_file = LogFile(path=Path("data.csv"), format="csv", needs_conversion=False)
        result: str = resolve_table_name(log_file, None)
        assert result.startswith("raw_csv_data_")

    def test_auto_generated_json(self) -> None:
        log_file = LogFile(path=Path("/tmp/events.json"), format="json", needs_conversion=False)
        result: str = resolve_table_name(log_file, None)
        assert result.startswith("raw_json_events_")

    def test_auto_generated_evtx(self) -> None:
        log_file = LogFile(path=Path("Security.evtx"), format="evtx", needs_conversion=True)
        result: str = resolve_table_name(log_file, None)
        assert result.startswith("raw_evtx_Security_")

    def test_hex_suffix_differs_each_call(self) -> None:
        log_file = LogFile(path=Path("test.log"), format="log", needs_conversion=False)
        names = {resolve_table_name(log_file, None) for _ in range(10)}
        assert len(names) == 10  # Every call produces a unique name

    def test_stem_with_special_chars_is_sanitized(self) -> None:
        log_file = LogFile(path=Path("my file (1).log"), format="log", needs_conversion=False)
        result: str = resolve_table_name(log_file, None)
        assert result.startswith("raw_log_my_file__1__")


# ---------------------------------------------------------------------------
# timestamp_cast_expression
# ---------------------------------------------------------------------------


class TestTimestampCastExpression:
    """Tests for ``timestamp_cast_expression()``."""

    def test_valid_identifier(self) -> None:
        expr = timestamp_cast_expression("event_ts")
        assert isinstance(expr, str)
        assert len(expr) > 0
        # The column name should be quoted inside the expression
        assert '"event_ts"' in expr

    def test_includes_cast_patterns(self) -> None:
        expr = timestamp_cast_expression("ts")
        assert "try_strptime" in expr
        assert "AT TIME ZONE 'UTC'" in expr
        assert "to_timestamp" in expr
        assert "::TIMESTAMP" in expr

    def test_quotes_column_name(self) -> None:
        expr = timestamp_cast_expression("my_column")
        assert '"my_column"' in expr

    def test_raises_on_invalid_identifier(self) -> None:
        with pytest.raises(ValueError, match="Invalid SQL identifier"):
            timestamp_cast_expression("123invalid")
