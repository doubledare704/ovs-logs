# Product Requirement Document (PRD)

**Project Name:** OVS-Log (Ovdiienko-Soroka Log Analysis)

**Document Version:** 1.2

**Status:** Approved for MVP Development

**Authors:** Oleksii Ovdiienko, Anastasiia Soroka

---

## 1. Introduction & Vision

### 1.1 The Pain Points

Modern security teams and system administrators in small companies (SMB/MSSP) face critical challenges:

* **Alert Fatigue:** Analysts drown in raw indicators of compromise (IOCs) lacking context.
* **Actionability Gap:** Threat intelligence or forensics reports often arrive as static text/PDFs, whereas technical teams need instant detection rules (Sigma/YARA).
* **Manual Log Analysis:** Investigating "what actually happened" involves complex, slow manual lookups across millions of log lines.

### 1.2. Product Vision

**OVS-Log** is an open-source, ultra-fast, local AI-powered log tracer and DFIR assistant built for small security teams. It ingests raw logs, correlates them instantly using an embedded columnar database, and uses an LLM acting as an automated analyst to generate an immediate timeline, MITRE ATT&CK mapping, and actionable defense rules.

---

## 2. Target Audience

* **Primary:** Tier 1/2 SOC Analysts, System Administrators in SMBs/MSSPs.
* **Secondary:** Security researchers, DFIR consultants need quick local triaging tools.

---

## 3. Technical Stack & Architecture

* **Analytical Engine:** DuckDB (In-memory/local columnar parsing for lightning-fast querying of Parquet, JSON, CSV, and EVTX formats without system overhead).
* **Backend/Language:** Python (FastAPI / Typer for CLI framework).
* **Frontend Layer:** Streamlit (Lightweight, local Python-driven web interface for rapid prototyping and interactive demos).
* **AI Core:** Lightweight LLM orchestration via API (serving as the automated analyst to parse DuckDB aggregations and compile the incident report).

---

## 4. MVP Architecture & Feature Scope

### 4.1. Core Engine (CLI Package)

The underlying engine runs entirely locally and handles the data pipeline:

* **Ingestion:** Parse raw, unreadable logs (e.g., CSV, JSON, Apache/Nginx logs, EVTX) directly into DuckDB.
* **Aggregation:** Extract suspicious indicators (top-hitting IPs, unique user-agents, anomalous HTTP status codes) via fast DuckDB SQL queries.
* **Enrichment:** Query basic open APIs (like AbuseIPDB) to pull malicious scores for extracted IPs.
* **AI Synthesis:** Pass the structured database aggregation to the LLM backend to construct the final incident profile.

### 4.2. Presentation Layer (Streamlit Web UI)

A clean, single-page local browser dashboard tailored for the expert verification demo:

* **Drag-and-Drop Uploader:** Simple area to upload raw incident log files (e.g., Splunk BOTS v1 datasets).
* **The "Analyze" Trigger:** A single execution button that initiates the backend DuckDB-to-LLM pipeline.
* **The Result Card (3-Tab Display):**
* **Tab 1: Interactive Incident Timeline:** A structured data table showing exactly when the attack started, escalating steps, and malicious actions.
* **Tab 2: Intelligence Mapping:** Clear visual markers mapping the activity to MITRE ATT&CK tactics alongside threat intelligence scores.
* **Tab 3: Mitigation Output:** A dedicated code-block interface providing a completely generated, ready-to-deploy **Sigma rule** for defense integration.



---

## 5. Validation Plan (The "Before / After" Expert Test)

To validate **OVS-Log** with industry experts (like Marat), a minimal evaluation script is established:

1. **Benchmark Dataset:** Raw web server and system logs from Splunk "Boss of the SOC" (BOTS v1) containing a real brute-force/web attack incident.
2. **The "Before" Scenario:** Show the expert a messy, unreadable raw log file containing over 5,000 lines.
3. **The "After" Scenario:** Run **OVS-Log**. Within 10 seconds, the Streamlit dashboard must render the complete, structured Incident Card mapping the attack path and displaying the copy-pasteable Sigma rule.

---
