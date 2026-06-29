# OVS-Log

Local AI-powered log tracer and DFIR assistant.

OVS-Log ingests raw logs (CSV, JSON, text, EVTX) into a local DuckDB database, extracts suspicious indicators, optionally enriches them with AbuseIPDB reputation data, and synthesizes structured incident reports via an OpenAI-compatible LLM.

## Prerequisites

- Python 3.12 or newer
- An AbuseIPDB API key (optional, for threat-intel enrichment)
- An API key for an OpenAI-compatible LLM provider (optional, for report synthesis)

## Installation

### Runtime dependencies

Install the package in editable mode along with its runtime dependencies:

```bash
pip install -e .
```

This also registers the `ovs-log` CLI entry point.

### Development dependencies

Install the package with development extras:

```bash
pip install -e ".[dev]"
```

This installs `pytest` in addition to the runtime dependencies.

### Verify the installation

```bash
ovs-log version
```

## Configuration

OVS-Log uses a frozen `Settings` dataclass singleton in `src/ovs_logs/config/settings.py`. Defaults can be overridden via environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | — |
| `ABUSEIPDB_API_URL` | AbuseIPDB endpoint | `https://api.abuseipdb.com/api/v2/check` |
| `ABUSEIPDB_TIMEOUT` | AbuseIPDB request timeout (seconds) | `10` |
| `LLM_API_KEY` | LLM provider API key | — |
| `OVS_LOGS_LLM_API_URL` | OpenAI-compatible chat completions endpoint | `https://api.openai.com/v1/chat/completions` |
| `OVS_LOGS_LLM_MODEL` | LLM model name | `gpt-4o-mini` |
| `OVS_LOGS_DB_PATH` | DuckDB database path | `.ovs_logs/ovs_logs.db` |

API keys can also be supplied per-command with `--abuseipdb-api-key` and `--llm-api-key`.

## CLI Usage

### Ingest a log file

Load a log file into DuckDB and normalize it into the unified `events` table:

```bash
ovs-log ingest --file sample.csv
ovs-log ingest --file access.log --type log --db ./my.db
```

Supported formats: `csv`, `json`, `txt`, `log`. EVTX is accepted as a stub and will require conversion in a future release.

### Analyze ingested data

Extract indicators from a DuckDB table:

```bash
# Indicators only
ovs-log analyze --table events

# Indicators with threat-intel enrichment
ovs-log analyze --table events --intel

# Full pipeline: indicators + threat intel + LLM report + JSON export
ovs-log analyze --table events --intel --llm --output report.json
```

### Export a mitigation rule

After a report has been synthesized and saved (requires `--llm` during `analyze`), export a mitigation rule:

```bash
ovs-log export-rule --report-id <report-id> --format sigma --output rule.yml
```

## Running tests

Run the full test suite with `pytest`:

```bash
python -m pytest
```

To see verbose output:

```bash
python -m pytest -v
```
