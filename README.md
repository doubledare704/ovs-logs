# OVS-Log

Local AI-powered log tracer and DFIR assistant.

OVS-Log ingests raw logs (CSV, JSON, text, EVTX) into a local DuckDB database, extracts suspicious indicators, optionally enriches them with AbuseIPDB reputation data, and synthesizes structured incident reports via an OpenAI-compatible LLM.

## Prerequisites

- Python 3.12 or newer
- [UV](https://docs.astral.sh/uv/) (package manager and runner)
- An AbuseIPDB API key (optional, for threat-intel enrichment)
- An API key for an OpenAI-compatible LLM provider (optional, for report synthesis)

## Installation

### Runtime dependencies

Install the package in editable mode along with its runtime dependencies:

```bash
uv sync --frozen
```

This also registers the `ovs-log` CLI entry point.

### Development dependencies

Install the package with development extras:

```bash
uv sync --frozen --all-extras
```

This installs `pytest`, `ruff`, `pyrefly`, and `pre-commit` in addition to the runtime dependencies.

### Pre-commit hooks

Set up pre-commit hooks to automatically run linting and formatting on commit:

```bash
uv run pre-commit install
```

The hooks will run:

- **Ruff** - Fast Python linter and formatter (replaces flake8, isort, black, etc.)
- **Pyrefly** - Fast Python type checker
- **Basic checks** - Merge conflicts, debug statements, large files, YAML/TOML/JSON syntax, trailing whitespace, line endings
- **Gitleaks** - Secret scanning

Run manually on all files:

```bash
uv run pre-commit run --all-files
```

### Verify the installation

```bash
uv run ovs-log version
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
uv run ovs-log ingest --file sample.csv
uv run ovs-log ingest --file access.log --type log --db ./my.db
```

Supported formats: `csv`, `json`, `txt`, `log`, `evtx`.

### Ingest and analyze in one step

Ingest a log file and immediately run the full analysis pipeline (indicators, optional threat-intel enrichment, and optional LLM synthesis):

```bash
# Ingest + indicators only
uv run ovs-log process --file sample.csv

# Ingest + indicators + threat intel + LLM report
uv run ovs-log process --file access.log --intel --llm
```

### Analyze ingested data

Extract indicators from a DuckDB table:

```bash
# Indicators only
uv run ovs-log analyze --table events

# Indicators with threat-intel enrichment
uv run ovs-log analyze --table events --intel

# Full pipeline: indicators + threat intel + LLM report + JSON export
uv run ovs-log analyze --table events --intel --llm --output report.json
```

### Export a mitigation rule

After a report has been synthesized and saved (requires `--llm` during `analyze`), export a mitigation rule:

```bash
uv run ovs-log export-rule --report-id <report-id> --format sigma --output rule.yml
```

You can export other supported formats by specifying the `--format` option. Examples:

```bash
uv run ovs-log export-rule --report-id <report-id> --format yara-l --output rule.yara
uv run ovs-log export-rule --report-id <report-id> --format spl --output rule.spl
```

### Streamlit dashboard

Launch the interactive web UI to configure API keys, select a database, browse ingested tables, and visualize results:

```bash
uv run ovs-log ui
```

This opens `http://localhost:8501` by default. Common options:

```bash
# Custom port
uv run ovs-log ui --port 9000

# Headless mode (no browser popup, useful on remote servers)
uv run ovs-log ui --headless

# Bind to all interfaces so it's reachable from other machines
uv run ovs-log ui --host 0.0.0.0

# Forward any extra Streamlit flag after `--`
uv run ovs-log ui -- --server.enableCORS false
```

## Running tests

Run the full test suite with `pytest`:

```bash
uv run pytest
```

To see verbose output:

```bash
uv run pytest -v
```
