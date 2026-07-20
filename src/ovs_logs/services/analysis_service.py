"""Analysis service: orchestrates the full analysis pipeline.

Provides :class:`AnalysisService` which encapsulates:
- Running anomaly-detection SQL templates
- Processing raw results into structured indicators
- Enriching indicators with AbuseIPDB threat intelligence
- Synthesizing an LLM-generated incident report
- Persisting the report to DuckDB

Both the CLI (``cli/main.py``) and UI (``ui/``) call this service instead of
importing core components directly, keeping the presentation layer thin.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

from ovs_logs.config.settings import Settings, settings as _default_settings
from ovs_logs.core.analysis import AnalysisEngine, IndicatorProcessor
from ovs_logs.core.analysis.indicators import SuspiciousIndicator, extract_unique_ips
from ovs_logs.core.database import Database
from ovs_logs.core.llm import LLMSynthesizer, create_llm_provider
from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.report import IncidentReport
from ovs_logs.core.threat_intel import ThreatIntelClient, ThreatIntelError

logger = logging.getLogger(__name__)


@dataclass
class AnalysisConfig:
    """Configuration for a single analysis run.

    All *None* fields fall back to environment variables or core settings
    defaults when the service runs.
    """

    db_path: Path
    table: str
    intel: bool = False
    llm: bool = False
    abuseipdb_api_key: str | None = None
    llm_api_key: str | None = None
    llm_endpoint: str | None = None
    llm_model: str | None = None
    output: Path | None = None


class AnalysisService:
    """Orchestrates the full analysis pipeline.

    Accepts an optional ``settings`` object for dependency injection.  When
    omitted the global ``ovs_logs.config.settings.settings`` singleton is used.
    Tests may pass a custom ``Settings`` instance to avoid monkeypatching the
    global singleton.

    Usage::

        config = AnalysisConfig(db_path=db, table="events", llm=True)
        service = AnalysisService(config)
        report = service.run()
        if report:
            print(report.title)
    """

    def __init__(
        self,
        config: AnalysisConfig,
        *,
        settings: Settings | None = None,
    ) -> None:
        self.config = config
        self._settings = settings or _default_settings
        self._report_store = ReportStore()

    # ------------------------------------------------------------------
    # Public pipeline
    # ------------------------------------------------------------------

    def run(
        self,
        connection: duckdb.DuckDBPyConnection | None = None,
    ) -> tuple[list[SuspiciousIndicator] | None, IncidentReport | None]:
        """Execute the full analysis pipeline.

        Args:
            connection: An optional open DuckDB connection.  When *None* a new
                connection is opened (and closed) using ``self.config.db_path``.

        Returns:
            A ``(indicators, report)`` pair.  *indicators* is ``None`` when the
            table has no analyzable columns, and an empty list when analysis
            found nothing suspicious.  *report* is ``None`` when ``--llm`` was
            not enabled or when no indicators were found.
        """
        if connection is not None:
            return self._pipeline(connection)
        with Database(self.config.db_path) as conn:
            return self._pipeline(conn)

    def run_analysis(
        self,
        connection: duckdb.DuckDBPyConnection,
    ) -> list[SuspiciousIndicator] | None:
        """Run analysis queries and return processed indicators.

        This is a convenience method for callers that only need indicators
        without the full pipeline (e.g. the UI's analysis tab).
        """
        return self._run_analysis(connection)

    def synthesize_report(
        self,
        connection: duckdb.DuckDBPyConnection,
        indicators: list[SuspiciousIndicator],
        *,
        enrich_intel: bool = False,
    ) -> str:
        """Synthesize an incident report from pre-computed indicators.

        Unlike :meth:`run`, this method skips the analysis step and works
        directly with already-computed indicators (the common UI pattern).

        Returns:
            The ``report_id`` of the persisted report.
        """
        threat_intel = self._enrich_intel(indicators) if enrich_intel else None
        _, report_id = self._synthesize(connection, indicators, threat_intel)
        return report_id

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _pipeline(
        self,
        connection: duckdb.DuckDBPyConnection,
    ) -> tuple[list[SuspiciousIndicator] | None, IncidentReport | None]:
        """Run the full pipeline against an open connection."""
        indicators = self._run_analysis(connection)
        if not indicators:
            return indicators, None

        threat_intel = self._enrich_intel(indicators) if self.config.intel else None
        result = self._synthesize(connection, indicators, threat_intel) if self.config.llm else None
        report = result[0] if result else None
        return indicators, report

    def _run_analysis(
        self,
        connection: duckdb.DuckDBPyConnection,
    ) -> list[SuspiciousIndicator] | None:
        """Run SQL templates and shape raw results into indicators."""
        raw_results = AnalysisEngine().run_queries(connection, table_name=self.config.table)
        indicators = IndicatorProcessor(
            thresholds_settings=self._settings.thresholds,
        ).process(raw_results)
        return indicators

    def _enrich_intel(
        self,
        indicators: list[SuspiciousIndicator],
    ) -> dict[str, Any] | None:
        """Enrich indicators with AbuseIPDB reputation data.

        Enrichment is best-effort: failures are logged and return ``None``
        rather than propagating to the caller.
        """
        api_key = self.config.abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return None
        ips = extract_unique_ips(indicators)
        if not ips:
            return None
        try:
            client = ThreatIntelClient(
                api_key=api_key,
                abuseipdb_settings=self._settings.abuseipdb,
            )
            return client.lookup_many(ips)
        except ThreatIntelError:
            logger.warning("AbuseIPDB enrichment failed; continuing without intel.")
            return None

    def _synthesize(
        self,
        connection: duckdb.DuckDBPyConnection,
        indicators: list[SuspiciousIndicator],
        threat_intel: dict[str, Any] | None = None,
    ) -> tuple[IncidentReport, str]:
        """Generate an incident report via LLM, persist it, and return the result.

        Returns:
            A ``(report, report_id)`` tuple.
        """
        api_key = self.config.llm_api_key or os.getenv("LLM_API_KEY")
        if not api_key:
            raise ValueError(
                "LLM synthesis requires an API key (set --llm-api-key, LLM_API_KEY, or configure in the UI sidebar)"
            )
        provider = create_llm_provider(
            api_key=api_key,
            endpoint=self.config.llm_endpoint,
            model=self.config.llm_model,
            llm_settings=self._settings.llm,
        )
        report = LLMSynthesizer(provider).synthesize(indicators, threat_intel=threat_intel)
        report_id = self._report_store.save_report(connection, report, source_table=self.config.table)
        return report, report_id
