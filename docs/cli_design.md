# OVS-Log Architecture & CLI Technical Design

This document details the backend pipeline, local data workflows, and Command Line Interface specs for **OVS-Log**.

## 1. High-Level Engine Pipeline

To minimize cloud costs and maintain data privacy for the SMB/MSSP target user, the entire extraction and ingestion process happens locally inside DuckDB before calling the LLM backend.

[Raw Log Files] ──> [ DuckDB Ingestion & SQL Filter ] ──> [ Aggregated Context ]
│
▼
[Streamlit UI/CLI] <── [ JSON/Structured Artifacts ] <── [ LLM Synthesis ]

## 2. Core CLI Interface Specs

The CLI is built using Python's `typer` library to provide human-friendly commands, clean error messages, and progress spinners. There are six commands available:

| Command | Description |
|---------|-------------|
| `ingest` | Ingest a log file into DuckDB and normalize it into the `events` table |
| `process` | Combined ingest + analyze: ingest and immediately analyze a log file |
| `analyze` | Analyze an existing DuckDB table (the `events` table or any raw table) |
| `export-rule` | Export a mitigation rule from a previously saved report |
| `version` | Show the OVS-Log version |
| `ui` | Launch the OVS-Log Streamlit dashboard |

### 2.1. Command: `ovs-log ingest`

Prepares, parses, and commits raw file streams directly into local DuckDB columnar tables without exhausting system memory.

**Usage:**

```bash
ovs-log ingest --file <path_to_logs> [--type csv|json|txt|log|evtx] [--db <path>] [--table <name>]
```

**Options:**

- `--file` (required): Path to the log file to ingest.
- `--type` (optional): Override file type detection. Supported values: `csv`, `json`, `txt`, `log`, `evtx`.
- `--db` (optional): DuckDB database path (defaults to `.ovs_logs/ovs_logs.db`).
- `--table` (optional): Destination raw table name (auto-generated if omitted).

**Behind the scenes:** The file is validated and routed to the appropriate ingestion adapter:

- CSV files → `read_csv_auto` with `all_varchar=true`
- JSON files → `read_json_auto`
- EVTX files → `PyEvtxParser` → temporary CSV → DuckDB
- Text/log files → `read_csv` single-column with `line` column

After raw ingestion, the `NormalizationEngine` maps raw columns to the unified `events` schema (`event_timestamp`, `source_ip`, `event_type`, `status_code`, `raw_message`) using flexible alias matching.

### 2.2. Command: `ovs-log process` (Combined Ingest + Analyze)

Ingests a log file and immediately runs the full analysis pipeline — extraction of suspicious indicators, optional AbuseIPDB enrichment, and optional LLM synthesis — in a single command.

**Usage:**

```bash
ovs-log process --file <path_to_logs> [--type csv|json|txt|log|evtx]
                [--db <path>] [--table <name>]
                [--intel] [--llm]
                [--abuseipdb-api-key <key>] [--llm-api-key <key>]
                [--output <path>]
```

**Options:**

- `--file` (required): Path to the log file to ingest and analyze.
- `--type` (optional): Override file type detection.
- `--db` (optional): DuckDB database path.
- `--table` (optional): Destination raw table name.
- `--intel` (flag): Enable AbuseIPDB IP reputation enrichment.
- `--llm` (flag): Enable LLM synthesis of an incident report.
- `--abuseipdb-api-key` (optional): AbuseIPDB API key (also read from `ABUSEIPDB_API_KEY` env var).
- `--llm-api-key` (optional): LLM API key (also read from `LLM_API_KEY` env var).
- `--output` (optional): Write the synthesized report as a JSON file.

### 2.3. Command: `ovs-log analyze` (The Flagship Operation)

Analyzes an existing DuckDB table (either the unified `events` table or a raw table) to extract statistical anomalies, optionally queries external reputation APIs, and returns the synthesized incident card.

**Usage:**

```bash
ovs-log analyze --table <table_name> [--db <path>]
                [--intel] [--llm]
                [--abuseipdb-api-key <key>] [--llm-api-key <key>]
                [--output <path>]
```

**Options:**

- `--table` (required): DuckDB table to analyze.
- `--db` (optional): DuckDB database path.
- `--intel` (flag): Enable AbuseIPDB enrichment.
- `--llm` (flag): Enable LLM synthesis of an incident report.
- `--abuseipdb-api-key` (optional): AbuseIPDB API key.
- `--llm-api-key` (optional): LLM API key.
- `--output` (optional): Write the synthesized report as a JSON file.

**Behind the scenes:** The analysis pipeline proceeds as follows:

1. **SQL Aggregation:** Registered SQL templates (top talkers, error spikes, event distribution, temporal anomalies) run against the target table. The `AnalysisEngine` auto-wraps raw tables in an alias-resolving subquery so normalized field names (`event_timestamp`, `source_ip`, etc.) resolve correctly regardless of the raw column names.
2. **Indicator Processing:** Raw query results are transformed into `SuspiciousIndicator` objects with severity levels derived from configurable thresholds.
3. **Threat Intelligence (optional):** Unique IPs are extracted and looked up via the `ThreatIntelClient` (AbuseIPDB). Results are cached in DuckDB.
4. **LLM Synthesis (optional):** Structured context (indicators + threat intel) is passed to the `LLMSynthesizer`, which generates an `IncidentReport` with a timeline, MITRE ATT&CK mappings, and a mitigation artifact.

**Sample DuckDB query pattern (Top Talkers) — an example of the templates the engine executes:**

```sql
SELECT
    source_ip,
    COUNT(*) as event_count,
    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
FROM events
GROUP BY source_ip
HAVING event_count > ?
ORDER BY event_count DESC
LIMIT ?
```

### 2.4. Command: `ovs-log export-rule`

Extracts the generated mitigation artifact from a previously saved report (the report must have been synthesized with `--llm` during `analyze` or `process`).

**Usage:**

```bash
ovs-log export-rule --report-id <uuid> --output <path>
                    [--format sigma|yara-l|spl]
                    [--db <path>]
```

**Options:**

- `--report-id` (required): UUID of the saved report.
- `--output` (required): File path to write the rule content.
- `--format` (optional): Expected rule format (default: `sigma`). Any string is accepted; it is not an enforced closed-set CLI choice. The value is compared against the stored mitigation's format and rejected only on mismatch. Currently supported formats are `sigma`, `yara-l`, and `spl`.
- `--db` (optional): DuckDB database path.

### 2.5. Command: `ovs-log version`

Displays the installed OVS-Log version.

**Usage:**

```bash
ovs-log version
```

### 2.6. Command: `ovs-log ui`

Launches the OVS-Log Streamlit dashboard.

**Usage:**

```bash
ovs-log ui [--host <address>] [--port <number>]
           [--headless] [-- <extra_streamlit_args>]
```

**Options:**

- `--host` (optional): Streamlit server bind address (default: `localhost`).
- `--port` (optional): Streamlit server port (default: `8501`).
- `--headless` (optional): Run without opening a browser (useful for remote servers).
- Extra arguments after `--` are forwarded to `streamlit run`.
