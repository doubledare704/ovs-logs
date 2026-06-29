# OVS-Log Architecture Specification

This document defines the technical architecture of **OVS-Log** for the MVP. It expands on `docs/PRD.md`, `docs/cli_design.md`, and `docs/streamlit_ui.md`, and maps the implementation to the Linear backlog epics **OVD-5 through OVD-9**.

## 1. Design Principles

- **Local-first**: All parsing, aggregation, and enrichment states live in a local DuckDB instance.
- **Privacy-preserving**: Raw logs are never sent externally; only structured, aggregated context is passed to the optional LLM provider.
- **CLI/UI parity**: The Typer CLI and the Streamlit UI share the same engine, so behavior and outputs are identical.
- **Modular**: Ingestion, analysis, threat-intel, and LLM synthesis are independent services orchestrated by a thin workflow layer.

## 2. System Components

| Component           | Role                                                                       | Backlog       |
|---------------------|----------------------------------------------------------------------------|---------------|
| Ingestion Engine    | Reads CSV, JSON, TXT, LOG, and EVTX into DuckDB with schema detection      | OVD-5         |
| DuckDB Local Store  | Columnar analytical state and result cache                                 | OVD-5 / OVD-6 |
| Analyzer            | Runs SQL aggregation templates, orchestrates enrichment and LLM synthesis  | OVD-6         |
| Threat Intel Client | Queries AbuseIPDB for IP reputation and caches results locally             | OVD-6         |
| LLM Provider        | Generates incident timeline, MITRE ATT&CK mapping, and mitigation guidance | OVD-6         |
| Typer CLI           | `ingest`, `analyze`, and `export-rule` commands                            | OVD-7         |
| Streamlit UI        | Single-page upload, run, and 3-tab results view                            | OVD-8         |
| Packaging & Tests   | Entrypoints, automated tests, and BOTS v1 validation                       | OVD-9         |

## 3. Component Diagram

```mermaid
graph LR
    subgraph Inputs
        A1[CSV / JSON / TXT / LOG]
        A2[EVTX]
    end
    subgraph Interfaces
        B1[Typer CLI]
        B2[Streamlit UI]
    end
    subgraph Engine
        C1[Ingestion Engine]
        C2[DuckDB Local Store]
        C3[Analyzer Engine]
        C4[Threat Intel Client]
    end
    subgraph External
        E1[AbuseIPDB API]
        E2[LLM Provider API]
    end

    A1 -->|read_csv_auto / read_json_auto| C1
    A2 -->|EVTX converter| C1
    B1 -->|ovs-log ingest / analyze| C1
    B2 -->|upload / run| C1
    C1 -->|tables + cache| C2
    C2 -->|SQL aggregation| C3
    C3 -->|reputation lookup| C4
    C4 -->|HTTP / cache| E1
    C3 -->|synthesis prompt| E2
    C3 -->|JSON / Markdown report| B1
    C3 -->|render data| B2
```

## 4. Sequence Diagram: The "Analyze" Flow

```mermaid
sequenceDiagram
    actor U as User
    participant C as CLI / Streamlit UI
    participant I as Ingestion Engine
    participant D as DuckDB
    participant A as Analyzer
    participant T as Threat Intel Client
    participant L as LLM Provider

    U->>C: Trigger analyze (file + settings)
    C->>I: ingest(path, type)
    I->>D: CREATE / INSERT via read_*_auto
    D-->>I: schema + row count
    I-->>C: success / error
    C->>A: analyze(thresholds, format)
    A->>D: execute SQL aggregation templates
    D-->>A: suspicious indicators
    A->>T: enrich(indicators)
    T->>D: cache miss → store result
    T-->>A: reputation scores + context
    A->>A: build synthesis context
    A->>L: prompt with structured context
    L-->>A: incident report (timeline, MITRE, mitigation)
    A-->>C: report + rule artifact
    C-->>U: 3-tab UI or exported file
```

## 5. State Management

- **Analytical state**: Owned by DuckDB. Tables persist normalized events, aggregation results, threat-intel cache, and generated reports. This keeps the CLI stateless and the Streamlit UI resilient to refreshes.
- **Streamlit state**: `st.session_state` holds only lightweight UI state: the current upload metadata, the API key, chunk-size slider, and target format dropdown. Large payloads (raw log content, analysis results) are read from or written to DuckDB so that reruns do not reload the file from memory.
- **Threat-intel cache**: A small cache table in DuckDB prevents repeated API calls for the same indicator during a single session and lets the analyzer work offline when the API key is absent or rate-limited.

## 6. Mapping to Linear Backlog

| Epic  | Architectural Concern                                                    |
|-------|--------------------------------------------------------------------------|
| OVD-5 | Ingestion engine, DuckDB schema, and normalization of raw log formats    |
| OVD-6 | Analyzer, threat-intel client, LLM synthesis, and incident report schema |
| OVD-7 | Typer CLI command layer and output formatting                            |
| OVD-8 | Streamlit UI, session state, and 3-tab presentation                      |
| OVD-9 | Package entrypoints, automated tests, and BOTS v1 validation flow        |

## 7. Key Design Decisions

- DuckDB serves as both the storage layer and the analytical engine, eliminating the need for a separate database process.
- The LLM receives only structured aggregations (top IPs, endpoints, error rates, reputation context), not full raw logs, to minimize token usage and preserve privacy.
- The CLI and UI share the same `Analyzer` workflow, so a result validated in the dashboard can be reproduced identically from the command line.
- Threat-intel enrichment is optional; the engine degrades gracefully when the AbuseIPDB API key is missing or the service is unavailable.
