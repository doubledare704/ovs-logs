# OVS-Log Streamlit Dashboard Interface Design

Streamlit serves as the presentation layer for high-impact visual proof of concept (the 10-second "Before vs After" expert demo). 

## 1. Scope Constraints for the MVP UI
* **Single-Page Application (SPA):** To maximize speed and avoid fragmentation, a multipage routing framework is omitted. Instead, state variables control a seamless top-to-bottom layout transition.
* **Theme Vibe:** Monospace text elements, dark code blocks, and crisp metrics containers to echo native security operations terminal styling.

## 2. Core Screen Elements & Layout Hierarchy

### 2.1. Hero Configuration Sidebar
* **API Configuration Section:** Secure fields inputting `AbuseIPDB_API_KEY` (utilizes `st.text_input(type="password")`).
* **Engine Settings Toggles:**
  * Chunk sizing sliders for processing configuration.
  * Dropdown selector for target formats: `[Sigma Rule, YARA-L, Splunk SPL]`.

### 2.2. Main Display Area: Step 1 — The Ingestion Hub
Before processing triggers, the layout centers strictly on ingestion:
* **The Drop-Zone (`st.file_uploader`):** Explicitly handles raw files (`.log`, `.json`, `.csv`, `.txt`).
* **The "Before" Perspective (`st.expander`):** Titled *"Raw Unstructured Payload View"*. Once a file drops, this populates the first 50 lines of unformatted string data. This explicitly shows the expert the "mess" before remediation.
* **Execution Trigger:** A high-contrast processing button (`st.button("Run OVS-Log Extraction Engine")`). Clicking fires an interactive loading spinner (`with st.spinner("DuckDB processing... Querying Threat Intel... Synthesizing Context...")`).

### 2.3. Main Display Area: Step 2 — The Result Card (The 3-Tab Presentation Container)
Once execution finishes, Step 1 layout collapses cleanly, yielding to an interactive 3-tab output module (`st.tabs(["📊 Attack Timeline", "🛡️ Threat Intelligence Mapping", "⚙️ Actionable Mitigation"])`).

#### Tab 1: 📊 Attack Timeline
* **High-Level Metric Callouts (`st.columns`):** Displays overall indicators:
  * Total Events Parsed (DuckDB count row).
  * High-Risk Anomalous Indicators identified.
  * Attacker Footprint Duration.
* **Chronological Event Matrix (`st.dataframe`):** A beautiful data grid populated directly by a Panda's translation of the DuckDB tracking query. Includes sorting on keys: `Timestamp`, `Attacker IP`, `Observed Tactic/Action`, `Impacted Endpoint`, `Response Status`.

#### Tab 2: 🛡️ Threat Intelligence Mapping
* **Reputation Cards:** Individual metrics breaking down geographical routing data, ASN telemetry, and public abuse confidence percentages pulled via backend enrichment loops.
* **MITRE ATT&CK Breakdown Block:** A markdown card compiling specific tactics mapped by the AI agent (e.g., *Initial Access via Exploit Public-Facing Application (T1190)*).

#### Tab 3: ⚙️ Actionable Mitigation
* **Actionable Gap Closure Container:** A clean, monospaced interactive terminal-like panel rendering the exact YAML-based rule ready to copy into production environments.
* **Implementation Component:** Uses `st.code(language="yaml")` alongside an asset clipboard option (`st.download_button`) to export the `.yml` block locally with a single click.