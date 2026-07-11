"""Acceptance tests for the `export-rule` CLI command."""

from pathlib import Path

from typer.testing import CliRunner

from ovs_logs.cli.main import app
from ovs_logs.core.database import Database
from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.report import IncidentReport, MitigationArtifact

from .conftest import sample_report

runner = CliRunner()

EXIT_CODE_VALIDATION_ERROR = 3


def _sample_report_with_mitigation(fmt: str, content: str) -> IncidentReport:
    return IncidentReport(
        title="Generated artifact",
        summary="Auto-generated mitigation artifact",
        severity="Low",
        timeline=[],
        mitre_mappings=[],
        mitigation=MitigationArtifact(format=fmt, title="Generated", content=content),
        indicators=[],
        metadata={},
    )


def test_export_rule_success(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    with Database(db) as conn:
        report = sample_report()
        report_id = ReportStore().save_report(conn, report)

    out = tmp_path / "rule.yml"
    result = runner.invoke(
        app,
        [
            "export-rule",
            "--report-id",
            report_id,
            "--format",
            "sigma",
            "--db",
            str(db),
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.parent.exists()
    assert out.read_text(encoding="utf-8") == report.mitigation.content


def test_export_rule_format_mismatch(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    with Database(db) as conn:
        report = sample_report()
        report_id = ReportStore().save_report(conn, report)

    out = tmp_path / "rule.yml"
    result = runner.invoke(
        app,
        [
            "export-rule",
            "--report-id",
            report_id,
            "--format",
            "suricata",
            "--db",
            str(db),
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == EXIT_CODE_VALIDATION_ERROR
    assert "does not match report mitigation" in result.output
    assert not out.exists()


def test_export_rule_yara_l_and_spl_success(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    # YARA-L
    yara_content = 'rule suspicious { meta: author = "test" strings: $a = "malicious" condition: $a }'
    with Database(db) as conn:
        report_yara = _sample_report_with_mitigation("YARA-L", yara_content)
        yara_id = ReportStore().save_report(conn, report_yara)

    out_yara = tmp_path / "rule.yara"
    res_yara = runner.invoke(
        app,
        [
            "export-rule",
            "--report-id",
            yara_id,
            "--format",
            "yara-l",
            "--db",
            str(db),
            "--output",
            str(out_yara),
        ],
    )

    assert res_yara.exit_code == 0, res_yara.output
    assert out_yara.exists()
    assert out_yara.read_text(encoding="utf-8") == yara_content

    # SPL
    spl_content = "search index=main | stats count by source_ip"
    with Database(db) as conn:
        report_spl = _sample_report_with_mitigation("SPL", spl_content)
        spl_id = ReportStore().save_report(conn, report_spl)

    out_spl = tmp_path / "rule.spl"
    res_spl = runner.invoke(
        app,
        [
            "export-rule",
            "--report-id",
            spl_id,
            "--format",
            "spl",
            "--db",
            str(db),
            "--output",
            str(out_spl),
        ],
    )

    assert res_spl.exit_code == 0, res_spl.output
    assert out_spl.exists()
    assert out_spl.read_text(encoding="utf-8") == spl_content
