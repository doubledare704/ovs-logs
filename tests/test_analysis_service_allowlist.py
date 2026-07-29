"""Tests for allowlist filtering in AnalysisService.

Verifies that :meth:`AnalysisService.run_analysis` and
:meth:`AnalysisService._pipeline` drop indicators whose IP appears in the
``allowlisted_indicators`` table, while keeping non-allowlisted and
non-IP-based indicators.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import duckdb
import pytest
from pytest_mock.plugin import MockerFixture

from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.database import insert_allowlisted_indicator, is_allowlisted
from ovs_logs.services.analysis_service import AnalysisConfig, AnalysisService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_top_talker(source_ip: str, event_count: int = 150) -> SuspiciousIndicator:
    """Return a ``top_talkers`` indicator for the given source IP."""
    return SuspiciousIndicator(
        type="top_talkers",
        severity="Medium",
        description=f"IP {source_ip} generated {event_count} events",
        evidence={"source_ip": source_ip, "event_count": event_count},
    )


def _make_error_spike(source_ip: str, status_code: int = 404, error_count: int = 10) -> SuspiciousIndicator:
    """Return an ``error_spikes`` indicator for the given source IP."""
    return SuspiciousIndicator(
        type="error_spikes",
        severity="Low",
        description=f"IP {source_ip} returned HTTP {status_code} {error_count} times",
        evidence={"source_ip": source_ip, "status_code": status_code, "error_count": error_count},
    )


def _make_long_tail(
    destination_ip: str,
    process_name: str = "cmd.exe",
    connection_count: int = 1,
    total_connections: int = 50,
) -> SuspiciousIndicator:
    """Return a ``long_tail_analysis`` indicator for the given destination IP."""
    return SuspiciousIndicator(
        type="long_tail_analysis",
        severity="High",
        description=f"Process '{process_name}' made {connection_count} connection(s) to {destination_ip}",
        evidence={
            "process_name": process_name,
            "destination_ip": destination_ip,
            "connection_count": connection_count,
            "total_connections": total_connections,
        },
    )


def _make_event_distribution(event_type: str = "GET", event_count: int = 50) -> SuspiciousIndicator:
    """Return an ``event_distribution`` indicator (no IP field — always passes)."""
    return SuspiciousIndicator(
        type="event_distribution",
        severity="Low",
        description=f"Event type '{event_type}' occurred {event_count} times",
        evidence={"event_type": event_type, "event_count": event_count},
    )


def _make_source_ip_sequence(source_ip: str) -> SuspiciousIndicator:
    """Return a ``source_ip_sequence`` indicator for the given source IP."""
    return SuspiciousIndicator(
        type="source_ip_sequence",
        severity="Medium",
        description=f"IP {source_ip} appeared in a suspicious sequence",
        evidence={"source_ip": source_ip},
    )


def _config(db: duckdb.DuckDBPyConnection) -> AnalysisConfig:
    """Return a minimal ``AnalysisConfig`` pointing at an in-memory database."""
    return AnalysisConfig(
        db_path=Path(":memory:"),
        table="events",
    )


def _service(db: duckdb.DuckDBPyConnection) -> AnalysisService:
    """Return an ``AnalysisService`` with ``_run_analysis`` patched."""
    return AnalysisService(_config(db))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAllowlistFiltering:
    """Tests for the ``_filter_allowlisted`` method via ``run_analysis``."""

    def test_allowlisted_ip_filtered_from_indicators(self, db: duckdb.DuckDBPyConnection) -> None:
        """Indicator with an allowlisted source_ip must be removed."""
        insert_allowlisted_indicator(db, indicator_id="uuid-ft-1", indicator="1.2.3.4", indicator_type="ip")
        assert is_allowlisted(db, "1.2.3.4", "ip") is True

        service = _service(db)
        mock_indicators = [
            _make_top_talker("1.2.3.4"),
            _make_top_talker("5.6.7.8"),
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].evidence.get("source_ip") == "5.6.7.8"

    def test_non_allowlisted_ip_preserved(self, db: duckdb.DuckDBPyConnection) -> None:
        """Non-allowlisted IPs must remain in the result."""
        insert_allowlisted_indicator(db, indicator_id="uuid-fnp-1", indicator="10.0.0.1", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_top_talker("192.168.1.1"),
            _make_error_spike("10.0.0.2"),
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 2
        ips = {ind.evidence.get("source_ip") for ind in result}
        assert ips == {"192.168.1.1", "10.0.0.2"}

    def test_long_tail_destination_ip_filtered(self, db: duckdb.DuckDBPyConnection) -> None:
        """Long-tail indicators should be matched on ``destination_ip``."""
        insert_allowlisted_indicator(db, indicator_id="uuid-lt-1", indicator="8.8.8.8", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_long_tail("8.8.8.8"),  # allowlisted
            _make_long_tail("1.1.1.1"),  # clean
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].evidence.get("destination_ip") == "1.1.1.1"

    def test_empty_allowlist_returns_all_indicators(self, db: duckdb.DuckDBPyConnection) -> None:
        """When the allowlist table is empty, no indicators are dropped."""
        service = _service(db)
        mock_indicators = [
            _make_top_talker("1.2.3.4"),
            _make_error_spike("5.6.7.8"),
            _make_long_tail("8.8.8.8"),
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 3

    def test_non_ip_indicators_pass_through(self, db: duckdb.DuckDBPyConnection) -> None:
        """Indicators without IP fields (e.g. ``event_distribution``) must not be filtered."""
        insert_allowlisted_indicator(db, indicator_id="uuid-ni-1", indicator="1.2.3.4", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_event_distribution(),
            _make_top_talker("1.2.3.4"),  # this one gets filtered
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].type == "event_distribution"

    def test_filter_logs_dropped_count(self, db: duckdb.DuckDBPyConnection, caplog: pytest.LogCaptureFixture) -> None:
        """Debug log must contain the count of dropped indicators."""
        insert_allowlisted_indicator(db, indicator_id="uuid-log-1", indicator="1.2.3.4", indicator_type="ip")
        insert_allowlisted_indicator(db, indicator_id="uuid-log-2", indicator="5.6.7.8", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_top_talker("1.2.3.4"),
            _make_top_talker("5.6.7.8"),
            _make_error_spike("9.9.9.9"),
        ]

        caplog.set_level(logging.DEBUG)

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].evidence.get("source_ip") == "9.9.9.9"
        assert "Dropped 2 allowlisted indicators from 3 total" in caplog.text

    def test_none_indicators_returns_none(self, db: duckdb.DuckDBPyConnection) -> None:
        """When ``_run_analysis`` returns ``None``, ``run_analysis`` must also return ``None``."""
        service = _service(db)

        with patch.object(service, "_run_analysis", return_value=None):
            result = service.run_analysis(db)

        assert result is None

    def test_pipeline_filters_allowlisted(self, db: duckdb.DuckDBPyConnection) -> None:
        """The ``_pipeline`` method must also apply allowlist filtering."""
        insert_allowlisted_indicator(db, indicator_id="uuid-pl-1", indicator="1.2.3.4", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_top_talker("1.2.3.4"),
            _make_top_talker("5.6.7.8"),
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            indicators, report = service.run(db)

        assert indicators is not None
        assert len(indicators) == 1
        assert indicators[0].evidence.get("source_ip") == "5.6.7.8"
        assert report is None  # --llm not enabled

    def test_pipeline_all_filtered_skips_llm_synthesis(
        self, db: duckdb.DuckDBPyConnection, mocker: MockerFixture
    ) -> None:
        """When every indicator is allowlisted, ``_synthesize`` must not be called."""
        insert_allowlisted_indicator(db, indicator_id="uuid-all-1", indicator="1.2.3.4", indicator_type="ip")
        insert_allowlisted_indicator(db, indicator_id="uuid-all-2", indicator="5.6.7.8", indicator_type="ip")

        service = AnalysisService(
            AnalysisConfig(
                db_path=Path(":memory:"),
                table="events",
                llm=True,
                llm_api_key="fake-key",
            )
        )

        mock_indicators = [
            _make_top_talker("1.2.3.4"),
            _make_top_talker("5.6.7.8"),
        ]

        mocker.patch.object(service, "_run_analysis", return_value=mock_indicators)
        synth_mock = mocker.patch.object(service, "_synthesize")
        indicators, report = service.run(db)

        assert indicators == []
        assert report is None
        synth_mock.assert_not_called()

    def test_source_ip_sequence_allowlisted_filtered(self, db: duckdb.DuckDBPyConnection) -> None:
        """A ``source_ip_sequence`` indicator with an allowlisted source_ip must be dropped."""
        insert_allowlisted_indicator(db, indicator_id="uuid-sip-1", indicator="10.0.0.1", indicator_type="ip")

        service = _service(db)
        mock_indicators = [
            _make_source_ip_sequence("10.0.0.1"),
            _make_source_ip_sequence("192.168.1.1"),
        ]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].evidence.get("source_ip") == "192.168.1.1"
        assert result[0].type == "source_ip_sequence"

    def test_source_ip_sequence_non_allowlisted_preserved(self, db: duckdb.DuckDBPyConnection) -> None:
        """A ``source_ip_sequence`` indicator whose IP is not allowlisted must be kept."""
        service = _service(db)
        mock_indicators = [_make_source_ip_sequence("192.168.1.1")]

        with patch.object(service, "_run_analysis", return_value=mock_indicators):
            result = service.run_analysis(db)

        assert result is not None
        assert len(result) == 1
        assert result[0].type == "source_ip_sequence"
        assert result[0].evidence.get("source_ip") == "192.168.1.1"
