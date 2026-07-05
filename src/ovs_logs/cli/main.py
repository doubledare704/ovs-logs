"""Typer-based command-line interface for OVS-Log."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import duckdb
import typer
from rich.console import Console
from rich.table import Table

from ovs_logs import __version__
from ovs_logs.config.settings import settings
from ovs_logs.core.analysis import AnalysisEngine, IndicatorProcessor
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import (
    LoadResult,
    load_csv,
    load_evtx,
    load_json,
    load_text_log,
)
from ovs_logs.core.llm import LLMSynthesizer, OpenAICompatibleProvider
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.report import IncidentReport
from ovs_logs.core.text_parsing import parse_text_log
from ovs_logs.core.threat_intel import ThreatIntelClient
from ovs_logs.core.validation import SUPPORTED_FORMATS, LogFile, validate_log_file
from ovs_logs.ui import app as _app_module

app = typer.Typer(help="OVS-Log: local AI-powered log tracer and DFIR assistant")
console = Console()

ADAPTER_MAP: dict[str, Callable[..., LoadResult]] = {
    "csv": load_csv,
    "json": load_json,
    "evtx": load_evtx,
}


def _ingest_text_log_structured(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    try:
        return parse_text_log(log_file, connection, table_name=table_name)
    except ValueError:
        return load_text_log(log_file, connection, table_name=table_name)


ADAPTER_MAP["txt"] = _ingest_text_log_structured
ADAPTER_MAP["log"] = _ingest_text_log_structured


def _resolve_log_file(file: Path, file_type: str | None) -> LogFile:
    """Validate the file and optionally override the detected format."""
    log_file = validate_log_file(file)
    if file_type is None:
        return log_file

    normalized = file_type.lower()
    if normalized not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported type '{file_type}'. Supported: {', '.join(sorted(SUPPORTED_FORMATS))}")
    return LogFile(
        path=log_file.path,
        format=normalized,
        needs_conversion=(normalized == "evtx"),
    )


def _raise_no_adapter(fmt: str) -> None:
    raise ValueError(f"No ingestion adapter for format '{fmt}'")


def _raise_output_requires_llm() -> None:
    raise ValueError("--output requires --llm so a synthesized report is available")


def _raise_format_mismatch(rule_format: str, report_format: str) -> None:
    raise ValueError(
        f"Requested format '{rule_format}' does not match report mitigation format '{report_format}'"
    )


@app.command()
def ingest(
    file: Path = typer.Option(..., "--file", help="Path to the log file to ingest"),
    file_type: str | None = typer.Option(
        None, "--type", help="Override file type detection (csv, json, txt, log, evtx)"
    ),
    db: Path = typer.Option(Path(settings.database.path), "--db", help="DuckDB database path"),
    table: str | None = typer.Option(None, "--table", help="Destination raw table name (auto-generated if omitted)"),
) -> None:
    """Ingest a log file into DuckDB and normalize it into the events table."""
    try:
        with console.status("[bold green]Validating file..."):
            log_file = _resolve_log_file(file, file_type)

        adapter = ADAPTER_MAP.get(log_file.format)
        if adapter is None:
            _raise_no_adapter(log_file.format)

        with Database(db) as connection:
            with console.status("[bold green]Loading into DuckDB..."):
                load_result = adapter(log_file, connection, table_name=table)

            is_unstructured = len(load_result.schema) == 1 and load_result.schema[0][0] == "line"
            if not is_unstructured:
                with console.status("[bold green]Normalizing into events table..."):
                    NormalizationEngine().normalize_table(connection, load_result)

        console.print(f"[bold]Loaded[/bold] {load_result.row_count} rows into {load_result.table_name}")
        schema = ", ".join(name for name, _ in load_result.schema)
        console.print(f"[bold]Schema:[/bold] {schema}")
    except Exception as exc:
        exit_code = _classify_error(exc)
        raise typer.Exit(code=exit_code) from exc


def _classify_error(exc: Exception) -> int:
    """Map common CLI errors to specific exit codes and messages."""
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        console.print(f"[bold red]File error:[/bold red] {exc}")
        return 2
    if isinstance(exc, ValueError):
        console.print(f"[bold red]Validation error:[/bold red] {exc}")
        return 3
    if isinstance(exc, NotImplementedError):
        console.print(f"[bold red]Not supported:[/bold red] {exc}")
        return 4
    console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
    return 1


def _render_indicators(indicators: list[Any]) -> None:
    """Render a Rich table of suspicious indicators."""
    table = Table(title="Suspicious Indicators")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Evidence")

    for indicator in indicators:
        table.add_row(
            indicator.type,
            indicator.severity,
            indicator.description,
            str(indicator.evidence),
        )

    console.print(table)


def _extract_unique_ips(indicators: list[Any]) -> list[str]:
    """Collect unique source_ip values from indicator evidence."""
    ips: set[str] = set()
    for indicator in indicators:
        ip = indicator.evidence.get("source_ip")
        if isinstance(ip, str):
            ips.add(ip)
    return sorted(ips)


def _render_report(report: IncidentReport) -> None:
    """Render a synthesized incident report with Rich formatting."""
    console.print(f"[bold]Title:[/bold] {report.title}")
    console.print(f"[bold]Severity:[/bold] {report.severity}")
    console.print(f"[bold]Summary:[/bold] {report.summary}")

    if report.timeline:
        timeline_table = Table(title="Timeline")
        timeline_table.add_column("Timestamp")
        timeline_table.add_column("Description")
        for event in report.timeline:
            timeline_table.add_row(event.timestamp, event.description)
        console.print(timeline_table)

    if report.mitre_mappings:
        mitre_table = Table(title="MITRE Mappings")
        mitre_table.add_column("ID")
        mitre_table.add_column("Technique")
        mitre_table.add_column("Tactic")
        for mapping in report.mitre_mappings:
            mitre_table.add_row(mapping.technique_id, mapping.technique_name, mapping.tactic)
        console.print(mitre_table)


@app.command()
def analyze(  # noqa: PLR0913
    table: str = typer.Option(..., "--table", help="DuckDB table to analyze"),
    db: Path = typer.Option(Path(settings.database.path), "--db", help="DuckDB database path"),
    intel: bool = typer.Option(False, "--intel", help="Enable AbuseIPDB enrichment"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM synthesis"),
    abuseipdb_api_key: str | None = typer.Option(None, "--abuseipdb-api-key", help="AbuseIPDB API key"),
    llm_api_key: str | None = typer.Option(None, "--llm-api-key", help="LLM API key"),
    output: Path | None = typer.Option(None, "--output", help="Write JSON report to file"),
) -> None:
    """Analyze a DuckDB table to extract indicators and optionally synthesize a report."""
    try:
        with Database(db) as connection:
            with console.status("[bold green]Analyzing table..."):
                raw_results = AnalysisEngine().run_queries(connection, table_name=table)
                indicators = IndicatorProcessor().process(raw_results)

            if not indicators:
                console.print("[yellow]No suspicious indicators found.[/yellow]")
                return

            _render_indicators(indicators)

            threat_intel: dict[str, Any] | None = None
            if intel:
                with console.status("[bold green]Enriching with threat intelligence..."):
                    ips = _extract_unique_ips(indicators)
                    client = ThreatIntelClient(api_key=abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY"))
                    threat_intel = client.lookup_many(ips) if ips else {}

            report: IncidentReport | None = None
            if llm:
                with console.status("[bold green]Synthesizing incident report..."):
                    provider = OpenAICompatibleProvider(api_key=llm_api_key or os.getenv("LLM_API_KEY"))
                    report = LLMSynthesizer(provider).synthesize(indicators, threat_intel=threat_intel)
                report_id = ReportStore().save_report(connection, report)
                console.print(f"[bold]Report saved:[/bold] {report_id}")
                _render_report(report)

            if output:
                if report is None:
                    _raise_output_requires_llm()
                output.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
                console.print(f"[bold]Report written to:[/bold] {output}")
    except Exception as exc:
        exit_code = _classify_error(exc)
        raise typer.Exit(code=exit_code) from exc


@app.command()
def version() -> None:
    """Show the OVS-Log version."""
    console.print(f"OVS-Log {__version__}")


@app.command()
def ui(
    host: str = typer.Option("localhost", "--host", help="Streamlit server bind address"),
    port: int = typer.Option(8501, "--port", help="Streamlit server port"),
    headless: bool = typer.Option(
        False,
        "--headless/--no-headless",
        help="Run Streamlit without opening a browser (useful for remote servers).",
    ),
    extra_args: list[str] | None = typer.Argument(
        None,
        help="Additional arguments forwarded to `streamlit run` (use after `--`).",
    ),
) -> None:
    """Launch the OVS-Log Streamlit dashboard.

    Spawns `streamlit run` against the packaged `ovs_logs.ui.app` module so
    the command works the same from a source checkout and an installed wheel.
    The target is passed as a `.py` filesystem path resolved via the module's
    ``__file__`` attribute, which is what Streamlit's CLI accepts.
    """
    target = str(Path(_app_module.__file__).resolve())


    cmd: list[str] = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        target,
    ]
    if headless:
        cmd.extend(["--server.headless", "true"])
    cmd.extend(["--server.address", host, "--server.port", str(port)])
    if extra_args:
        cmd.extend(extra_args)

    exit_code = subprocess.call(cmd)
    if exit_code:
        raise typer.Exit(code=exit_code)


@app.command()
def export_rule(
    report_id: str = typer.Option(..., "--report-id", help="Report ID to export"),
    rule_format: str = typer.Option("sigma", "--format", help="Rule format, e.g. sigma"),
    db: Path = typer.Option(Path(settings.database.path), "--db", help="DuckDB database path"),
    output: Path = typer.Option(..., "--output", help="Write rule to file"),
) -> None:
    """Export a mitigation rule from a saved report.

    The report must have been synthesized with `--llm` during `analyze` so
    a `mitigation` artifact exists in the stored report.
    """
    try:
        with Database(db) as connection:
            report = ReportStore().get_report(connection, report_id)

        if report.mitigation.format.lower() != rule_format.lower():
            _raise_format_mismatch(rule_format, report.mitigation.format)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.mitigation.content, encoding="utf-8")
        console.print(f"[bold]Rule written to:[/bold] {output}")
    except Exception as exc:
        exit_code = _classify_error(exc)
        raise typer.Exit(code=exit_code) from exc


if __name__ == "__main__":
    app()
