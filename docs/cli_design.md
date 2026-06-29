# OVS-Log Architecture & CLI Technical Design

This document details the backend pipeline, local data workflows, and Command Line Interface specs for **OVS-Log**.

## 1. High-Level Engine Pipeline

To minimize cloud costs and maintain data privacy for the SMB/MSSP target user, the entire extraction and ingestion process happens locally inside DuckDB before calling the LLM backend.

[Raw Log Files] ──> [ DuckDB Ingestion & SQL Filter ] ──> [ Aggregated Context ]
│
▼
[Streamlit UI/Cli] <── [ Markdown/Structured Artifacts ] <── [ LLM Synthesis ]

## 2. Core CLI Interface Specs
The CLI is built using Python's `typer` library to provide human-friendly commands, clean error messages, and progress spinners.

### 2.1. Command: `ovs-log ingest`
Prepares, parses, and commits raw file streams directly into local DuckDB columnar tables without exhausting system memory.
* **Usage:** `ovs-log ingest --file <path_to_logs> --type <nginx|apache|evtx|json>`
* **Behind the scenes:** Executes an automated DuckDB schema detection loop (`read_csv_auto` or `read_json_auto`).

### 2.2. Command: `ovs-log analyze` (The Flagship Operation)
Queries DuckDB for statistical anomalies, queries external reputation APIs, chunks the data, and returns the synthesized incident card.
* **Usage:** `ovs-log analyze --file <path_to_logs> --output <markdown|json>`
* **Parameters:** * `--threat-intel` (bool, default true): Toggles live enrichment calls via AbuseIPDB API keys.
* **Sample Core DuckDB Query (Anomalous IP Detection Pattern):**
  ```sql
  SELECT 
      client_ip, 
      COUNT(*) as request_count, 
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
      ROUND(error_count * 100.0 / request_count, 2) as error_rate,
      ARRAY_AGG(DISTINCT request_path) FILTER (WHERE status_code >= 400)[:5] as targeted_endpoints
  FROM read_csv_auto('web_access.log')
  GROUP BY client_ip
  HAVING request_count > 100 AND error_rate > 70.0
  ORDER BY error_count DESC;
  ```
  
### 2.3. Command: ovs-log export-rule
Extracts only the generated mitigation signatures out of the database local cache.

Usage: ovs-log export-rule --format sigma