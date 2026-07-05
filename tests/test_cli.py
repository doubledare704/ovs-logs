"""Tests for the Typer CLI."""

from pathlib import Path
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from ovs_logs.cli.main import app

runner = CliRunner()

EXIT_CODE_SUCCESS = 0
EXIT_CODE_PARAM_ERROR = 2
EXIT_CODE_VALIDATION_ERROR = 3
EXIT_CODE_PROPAGATED_STREAMLIT = 42


def test_ingest_csv_success(tmp_path: Path) -> None:
    csv = tmp_path / "sample.csv"
    csv.write_text("timestamp,client_ip,status\n2024-01-01T00:00:00,1.2.3.4,200\n")
    db = tmp_path / "test.db"

    result = runner.invoke(
        app,
        [
            "ingest",
            "--file",
            str(csv),
            "--db",
            str(db),
            "--table",
            "raw_sample",
        ],
    )

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Loaded 1 rows" in result.output
    assert "raw_sample" in result.output
    assert "timestamp" in result.output


def test_ingest_missing_file() -> None:
    result = runner.invoke(app, ["ingest", "--file", "nonexistent.csv"])

    assert result.exit_code == EXIT_CODE_PARAM_ERROR
    assert "File error" in result.output


def test_ingest_unsupported_type(tmp_path: Path) -> None:
    csv = tmp_path / "sample.csv"
    csv.write_text("a\n1\n")

    result = runner.invoke(app, ["ingest", "--file", str(csv), "--type", "unknown"])

    assert result.exit_code == EXIT_CODE_VALIDATION_ERROR
    assert "Unsupported type" in result.output


def test_ingest_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_text("")

    result = runner.invoke(app, ["ingest", "--file", str(empty)])

    assert result.exit_code == EXIT_CODE_VALIDATION_ERROR
    assert "Validation error" in result.output


def test_ingest_evtx_success(tmp_path: Path, monkeypatch) -> None:
    evtx = tmp_path / "sample.evtx"
    evtx.write_bytes(b"EVT\x00...")
    db = tmp_path / "test.db"

    class FakeParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            return [
                {
                    "identifier": "1",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "data": '{"System":{"EventID":4624,"TimeCreated":{"SystemTime":"2024-01-01T00:00:00Z"}}'
                            ',"EventData":{"IpAddress":"1.2.3.4","TargetUserName":"alice"}}',
                }
            ]

    monkeypatch.setattr("ovs_logs.core.ingestion.adapters.PyEvtxParser", FakeParser)

    result = runner.invoke(app, ["ingest", "--file", str(evtx), "--type", "evtx", "--db", str(db)])

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Loaded 1 rows" in result.output


def test_ingest_log_structured_success(tmp_path: Path) -> None:
    access_log = tmp_path / "access.log"
    access_log.write_text(
        '192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '192.168.1.2 - - [01/Jan/2024:00:01:00 +0000] "POST /login HTTP/1.1" 404 567\n'
    )
    db = tmp_path / "test.db"

    result = runner.invoke(
        app,
        [
            "ingest",
            "--file",
            str(access_log),
            "--type",
            "log",
            "--db",
            str(db),
            "--table",
            "raw_access",
        ],
    )

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Loaded 2 rows" in result.output


def test_ingest_log_fallback_to_raw_on_no_matches(tmp_path: Path) -> None:
    ambiguous = tmp_path / "ambiguous.txt"
    ambiguous.write_text("This is just some random text.\nNothing here matches any pattern.\n")
    db = tmp_path / "test.db"

    result = runner.invoke(
        app,
        [
            "ingest",
            "--file",
            str(ambiguous),
            "--type",
            "txt",
            "--db",
            str(db),
            "--table",
            "raw_ambiguous",
        ],
    )

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Loaded 2 rows" in result.output


# -----------------------------------------------------------------------------
# Analyze command tests
# -----------------------------------------------------------------------------


def _write_events_csv(path: Path, rows: int) -> None:
    """Write a CSV with normalized event columns."""
    lines = [
        "event_timestamp,source_ip,event_type,status_code",
        "2024-01-01T00:00:00,1.2.3.4,GET,200",
        "2024-01-01T00:01:00,1.2.3.4,GET,200",
        "2024-01-01T00:02:00,1.2.3.4,POST,200",
        "2024-01-01T00:03:00,5.6.7.8,POST,404",
        "2024-01-01T00:04:00,1.2.3.4,GET,500",
    ]
    path.write_text("\n".join(lines[: rows + 1]) + "\n")


def _ingest_csv(csv: Path, db: Path) -> None:
    result = runner.invoke(
        app,
        [
            "ingest",
            "--file",
            str(csv),
            "--db",
            str(db),
            "--table",
            "raw_events",
        ],
    )
    assert result.exit_code == EXIT_CODE_SUCCESS, result.output


def test_analyze_csv_success(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    _write_events_csv(csv, rows=5)
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)

    result = runner.invoke(app, ["analyze", "--table", "events", "--db", str(db)])

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Suspicious Indicators" in result.output
    assert "top_talkers" in result.output


def test_analyze_no_indicators(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    csv.write_text("event_timestamp,source_ip,event_type,status_code\n")
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)

    result = runner.invoke(app, ["analyze", "--table", "events", "--db", str(db)])

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "No suspicious indicators found" in result.output


def test_analyze_with_intel_no_api_key(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    _write_events_csv(csv, rows=5)
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)

    result = runner.invoke(app, ["analyze", "--table", "events", "--db", str(db), "--intel"])

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Suspicious Indicators" in result.output


def test_analyze_missing_table(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    result = runner.invoke(app, ["analyze", "--table", "missing_table", "--db", str(db)])

    assert result.exit_code != 0
    assert "Unexpected error" in result.output


def test_analyze_output_requires_llm(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    _write_events_csv(csv, rows=5)
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            "--table",
            "events",
            "--db",
            str(db),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == EXIT_CODE_VALIDATION_ERROR
    assert "Validation error" in result.output


def test_analyze_with_llm_and_output(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    _write_events_csv(csv, rows=5)
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)
    output = tmp_path / "report.json"

    llm_response = """
    ```json
    {
      "title": "Brute-force login attempt",
      "summary": "Multiple failed logins from a single IP.",
      "severity": "High",
      "timeline": [
        {"timestamp": "2024-01-01T00:00:00", "description": "Failed login",
         "source_ip": "1.2.3.4", "event_type": "POST", "status_code": 401,
         "raw_message": null}
      ],
      "mitre_mappings": [
        {"technique_id": "T1110", "technique_name": "Brute Force",
         "tactic": "Credential Access",
         "description": "Repeated failed auth attempts."}
      ],
      "mitigation": {
        "format": "Sigma",
        "title": "Detect repeated failed logins",
        "content": "title: repeated failed logins"
      },
      "indicators": [
        {"type": "top_talkers", "severity": "High",
         "description": "IP 1.2.3.4 generated 250 events",
         "evidence": {"source_ip": "1.2.3.4", "event_count": 250}}
      ],
      "metadata": {"source_file": "auth.log"}
    }
    ```
    """

    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"choices": [{"message": {"content": llm_response}}]}

    with patch("ovs_logs.core.llm.requests.post", return_value=mock_response):
        result = runner.invoke(
            app,
            [
                "analyze",
                "--table",
                "events",
                "--db",
                str(db),
                "--llm",
                "--llm-api-key",
                "sk-test",
                "--output",
                str(output),
            ],
        )

    assert result.exit_code == EXIT_CODE_SUCCESS, result.output
    assert "Report saved" in result.output
    assert "Report written to" in result.output
    assert output.exists()


def test_analyze_invalid_abuseipdb_key(tmp_path: Path) -> None:
    csv = tmp_path / "events.csv"
    _write_events_csv(csv, rows=5)
    db = tmp_path / "test.db"
    _ingest_csv(csv, db)

    response = Mock()
    response.status_code = 401
    response.text = "Unauthorized"

    with patch("ovs_logs.core.threat_intel.requests.get", return_value=response):
        result = runner.invoke(
            app,
            [
                "analyze",
                "--table",
                "events",
                "--db",
                str(db),
                "--intel",
                "--abuseipdb-api-key",
                "bad-key",
            ],
        )

    assert result.exit_code != 0
    assert "AbuseIPDB lookup failed" in str(result.exception) or "Unexpected error" in result.output


def test_ui_spawns_streamlit_run(monkeypatch) -> None:
    monkeypatch.setattr("ovs_logs.cli.main.sys.executable", "/fake/python")
    with patch("ovs_logs.cli.main.subprocess.call", return_value=0) as mock_call:
        result = runner.invoke(app, ["ui", "--port", "9000"])

    assert result.exit_code == EXIT_CODE_SUCCESS
    cmd = mock_call.call_args[0][0]
    assert cmd[0] == "/fake/python"
    assert cmd[1:3] == ["-m", "streamlit"]
    assert cmd[3] == "run"
    # Target must be a resolved .py path, not the module dotted name
    assert cmd[4].endswith("app.py")
    assert "/" in cmd[4]
    assert "--server.port" in cmd and "9000" in cmd


def test_ui_headless_flag() -> None:
    with patch("ovs_logs.cli.main.subprocess.call", return_value=0) as mock_call:
        result = runner.invoke(app, ["ui", "--headless"])

    assert result.exit_code == EXIT_CODE_SUCCESS
    cmd = mock_call.call_args[0][0]
    assert "--server.headless" in cmd
    assert "true" in cmd


def test_ui_propagates_streamlit_exit_code() -> None:
    with patch("ovs_logs.cli.main.subprocess.call", return_value=42):
        result = runner.invoke(app, ["ui"])

    assert result.exit_code == EXIT_CODE_PROPAGATED_STREAMLIT
