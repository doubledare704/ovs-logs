"""Tests for the analysis service orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import duckdb
import pytest

from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.services.analysis_service import AnalysisConfig, AnalysisService


def test_analysis_config_defaults() -> None:
    """AnalysisConfig can be constructed with required fields and sensible defaults."""
    config = AnalysisConfig(db_path=Path("/tmp/test.db"), table="events")
    assert config.db_path == Path("/tmp/test.db")
    assert config.table == "events"
    assert config.intel is False
    assert config.llm is False
    assert config.abuseipdb_api_key is None
    assert config.llm_api_key is None
    assert config.llm_endpoint is None
    assert config.llm_model is None
    assert config.output is None


def test_analysis_config_custom_values() -> None:
    """AnalysisConfig fields can all be set explicitly."""
    config = AnalysisConfig(
        db_path=Path("/tmp/custom.db"),
        table="firewall",
        intel=True,
        llm=True,
        abuseipdb_api_key="abc123",
        llm_api_key="sk-test",
        llm_endpoint="https://custom.endpoint",
        llm_model="gpt-4",
        output=Path("/tmp/report.json"),
    )
    assert config.db_path == Path("/tmp/custom.db")
    assert config.table == "firewall"
    assert config.intel is True
    assert config.llm is True
    assert config.abuseipdb_api_key == "abc123"
    assert config.llm_api_key == "sk-test"
    assert config.llm_endpoint == "https://custom.endpoint"
    assert config.llm_model == "gpt-4"
    assert config.output == Path("/tmp/report.json")


def test_run_with_explicit_connection_reuses_it(db: duckdb.DuckDBPyConnection) -> None:
    """When a connection is passed, run() reuses it without opening a new one."""
    config = AnalysisConfig(db_path=Path(":memory:"), table="events")
    service = AnalysisService(config)

    with patch.object(service, "_pipeline", return_value=([], None)) as mock_pipeline:
        result = service.run(connection=db)

    assert result == ([], None)
    mock_pipeline.assert_called_once_with(db)


def test_run_without_connection_opens_and_closes_db(tmp_path: Path) -> None:
    """When connection is None, run() opens and closes its own Database."""
    db_path = tmp_path / "test.duckdb"
    config = AnalysisConfig(db_path=db_path, table="events")
    service = AnalysisService(config)

    mock_conn = MagicMock(spec=duckdb.DuckDBPyConnection)
    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_conn
    mock_db.__exit__.return_value = None

    with (
        patch("ovs_logs.services.analysis_service.Database", return_value=mock_db) as mock_db_cls,
        patch.object(service, "_pipeline", return_value=([], None)) as mock_pipeline,
    ):
        result = service.run(connection=None)

    assert result == ([], None)
    mock_db_cls.assert_called_once_with(db_path)
    mock_db.__enter__.assert_called_once()
    mock_db.__exit__.assert_called_once()
    mock_pipeline.assert_called_once_with(mock_conn)


def test_run_analysis_returns_empty_list_when_no_analyzable_columns(
    db: duckdb.DuckDBPyConnection,
) -> None:
    """run_analysis returns empty list when the analysis engine finds no data."""
    config = AnalysisConfig(db_path=Path(":memory:"), table="events")
    service = AnalysisService(config)

    empty_results = {
        "top_talkers": [],
        "error_spikes": [],
        "event_distribution": [],
        "temporal_anomaly": [],
    }

    with patch("ovs_logs.services.analysis_service.AnalysisEngine") as MockEngine:
        mock_engine = MockEngine.return_value
        mock_engine.run_queries.return_value = empty_results

        result = service.run_analysis(db)

    assert result == []


def test_run_analysis_returns_indicators_when_finding_results(
    db: duckdb.DuckDBPyConnection,
) -> None:
    """run_analysis returns SuspiciousIndicator list when analysis finds results."""
    config = AnalysisConfig(db_path=Path(":memory:"), table="events")
    service = AnalysisService(config)

    results_with_data = {
        "top_talkers": [{"source_ip": "1.2.3.4", "event_count": 100}],
        "error_spikes": [],
        "event_distribution": [],
        "temporal_anomaly": [],
    }

    with patch("ovs_logs.services.analysis_service.AnalysisEngine") as MockEngine:
        mock_engine = MockEngine.return_value
        mock_engine.run_queries.return_value = results_with_data

        result = service.run_analysis(db)

    assert result is not None
    assert len(result) == 1
    assert result[0].type == "top_talkers"
    assert result[0].evidence["source_ip"] == "1.2.3.4"


def test_synthesize_report_skips_intel_when_enrich_intel_false(
    db: duckdb.DuckDBPyConnection,
) -> None:
    """synthesize_report skips intel enrichment when enrich_intel=False."""
    config = AnalysisConfig(
        db_path=Path(":memory:"),
        table="events",
        llm=True,
        llm_api_key="sk-test",
    )
    service = AnalysisService(config)

    indicator = SuspiciousIndicator(
        type="top_talkers",
        severity="Medium",
        description="IP 1.2.3.4 generated 100 events",
        evidence={"source_ip": "1.2.3.4", "event_count": 100},
    )

    with (
        patch.object(service, "_enrich_intel") as mock_enrich,
        patch.object(service, "_synthesize", return_value=(Mock(), "report-123")),
    ):
        report_id = service.synthesize_report(db, [indicator], enrich_intel=False)

    assert report_id == "report-123"
    mock_enrich.assert_not_called()


def test_synthesize_report_raises_value_error_when_no_api_key(
    db: duckdb.DuckDBPyConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """synthesize_report raises ValueError when LLM API key is missing."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    config = AnalysisConfig(
        db_path=Path(":memory:"),
        table="events",
        llm=True,
        llm_api_key=None,
    )
    service = AnalysisService(config)

    indicator = SuspiciousIndicator(
        type="top_talkers",
        severity="Medium",
        description="IP 1.2.3.4 generated 100 events",
        evidence={"source_ip": "1.2.3.4", "event_count": 100},
    )

    with pytest.raises(ValueError, match="LLM synthesis requires an API key"):
        service.synthesize_report(db, [indicator], enrich_intel=False)
