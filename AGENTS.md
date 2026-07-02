# OVS-Log Coding Standards & Agent Rules

This document defines the rules and principles for agentic coding in the **OVS-Log** project. All code modifications and new feature implementations must adhere to these guidelines.

## 1. Architectural Principles

### 1.1 Layered Architecture
Maintain a strict separation of concerns between layers:
- **Core Layer (`src/ovs_logs/core/`):** Pure business logic, data models, and database interactions. Must be independent of the presentation layer.
- **Service Layer (`src/ovs_logs/core/ingestion/`, etc.):** Orchestrates core components to perform high-level tasks.
- **CLI Layer (`src/ovs_logs/cli/`):** Typer-based command-line interface. Should be a thin wrapper around the Core/Service layers.
- **UI Layer (`src/ovs_logs/ui/`):** Streamlit-based web interface. Should focus on presentation and session state, calling the same Core/Service logic as the CLI.

### 1.2 SOLID Principles
- **Single Responsibility:** Each class and module should have one reason to change.
- **Open/Closed:** Entities should be open for extension but closed for modification.
- **Liskov Substitution:** Subtypes must be substitutable for their base types.
- **Interface Segregation:** Prefer many small, specific interfaces over one large, general-purpose one.
- **Dependency Inversion:** Depend on abstractions, not concretions. Use dependency injection where appropriate.

### 1.3 DRY, KISS, and YAGNI
- **DRY (Don't Repeat Yourself):** Abstract common logic into reusable functions or classes. Avoid duplicating the ingestion or analysis engine between CLI and UI.
- **KISS (Keep It Simple, Stupid):** Prefer simple, readable solutions over complex, "clever" ones.
- **YAGNI (You Ain't Gonna Need It):** Do not implement features or abstractions until they are actually needed.

## 2. Python Coding Standards

- **Python Version:** Target Python 3.12+.
- **Formatting:** Adhere to PEP 8. Use 4 spaces for indentation.
- **Type Hinting:** Mandatory for all function signatures and public class members. Use `from __future__ import annotations` for forward references.
- **Docstrings:** Use Google-style or ReStructuredText docstrings for all modules, classes, and public functions.
- **Error Handling:** Use specific exception types. Avoid broad `except Exception:` blocks unless logging and re-raising.
- **Data Structures:** Prefer `dataclasses` (with `frozen=True` where possible) for simple data containers.

## 3. Database & Ingestion Rules (DuckDB)

- **SQL Identifiers:** Always sanitize and quote table/column names using `"` to avoid SQL injection and handle special characters.
- **Auto-Detection:** Leverage DuckDB's `read_csv_auto` and `read_json_auto` for ingestion to minimize manual schema definition.
- **Performance:** Use DuckDB's columnar features. Prefer SQL aggregations over processing large datasets in Python memory.
- **State:** Analytical state belongs in DuckDB. Python should remain as stateless as possible.

## 4. Testing & Validation

- **Framework:** Use `uv run pytest`.
- **Coverage:** Every new feature must include unit tests. Fixes for bugs must include reproduction tests.
- **Mocking:** Use `pytest-mock` to isolate core logic from external APIs (e.g., AbuseIPDB, LLM providers).
- **Data Samples:** Use small, representative log samples for tests.
- **Streamlit UI tests:** Use Streamlit's built-in `AppTest`
  (`streamlit.testing.v1.AppTest`). See `docs/streamlit_testing.md` for the
  full OVS-Log patterns (sidebar widgets, session_state, env-var
  monkeypatching, Recent Tables filtering).

## 5. Documentation

- **Update Docs:** If a change affects the architecture or user interface, update the corresponding files in `docs/` (e.g., `architecture.md`, `PRD.md`).
- **Inline Comments:** Add comments for non-obvious logic, but prefer self-documenting code.

## 6. Git & Commits

- Be consistent with the [Git Flow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow) workflow.
- Use descriptive commit messages.
- Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for semantic versioning.
