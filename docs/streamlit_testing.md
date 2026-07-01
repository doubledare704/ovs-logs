# OVS-Log Streamlit UI Testing Guide

How to test the Streamlit dashboard in `src/ovs_logs/ui/`. Uses Streamlit's
built-in `AppTest` framework — **no extra dependency** beyond `streamlit`
itself (already in `pyproject.toml`) and `pytest` (dev dep).

Source: <https://docs.streamlit.io/develop/api-reference/app-testing>

## 1. Setup

`pyproject.toml` already declares:

```toml
dependencies = ["streamlit>=1.35.0", ...]
[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

`streamlit>=1.35` ships `streamlit.testing.v1.AppTest`. Add **no** new
dependency for UI tests.

UI test files live in `tests/` alongside the other test modules. Use the
naming convention `test_ui_<module>.py` (e.g. `tests/test_ui_app.py` for
`src/ovs_logs/ui/app.py`).

## 2. Core `AppTest` patterns

```python
from streamlit.testing.v1 import AppTest
from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"

at = AppTest.from_file(str(APP_PATH))
at.run()
assert not at.exception              # app did not raise
assert at.session_state["foo"] == 1  # session_state values
```

### 2.1 Sidebar widgets

Streamlit names sidebar widgets the same as main-area widgets; access them
through `at.sidebar`:

```python
at.sidebar.text_input[0].set_value("Jane").run()
at.sidebar.selectbox[0].set_value("beta").run()
assert at.sidebar.text_input[0].label == "AbuseIPDB API Key"
assert at.sidebar.text_input[0].value == "Jane"
```

Supported sidebar widgets: `button`, `checkbox`, `text_input`, `text_area`,
`number_input`, `selectbox`, `multiselect`, `radio`, `slider`,
`select_slider`, `toggle`, `date_input`, `time_input`, `color_picker`.

### 2.2 General widget interactions

Always chain `.run()` after an interaction to trigger a rerun:

```python
at.checkbox[0].check().run()         # .uncheck() is the inverse
at.text_input[0].set_value("x").run()
at.selectbox[0].set_value("Foo").run()
at.slider[0].set_value(3).run()
at.multiselect[0].select("baz").unselect("foo").run()
at.button[0].click().run()
```

### 2.3 Inspect widget properties

```python
assert at.selectbox[0].label == "Select a table"
assert at.selectbox[0].options == ["alpha", "beta"]   # cast to str internally
assert at.selectbox[0].index == 0
assert at.selectbox[0].disabled is False
assert at.selectbox[0].help == "..."                  # help text
```

### 2.4 Messages

`st.warning`, `st.error`, `st.info`, `st.success` are exposed as lists with a
`.value` string attribute:

```python
assert any("not found" in e.value for e in at.sidebar.error)
assert any("No application tables" in i.value for i in at.sidebar.info)
```

### 2.5 Session state

```python
at.session_state["db_path"] = "/tmp/foo.db"   # seed before .run()
assert at.session_state["selected_table"] == "beta"
```

### 2.6 Secrets and env vars

For secrets read via `st.secrets[...]`:

```python
at = AppTest.from_file(str(APP_PATH))
at.secrets["WORD"] = "Foobar"
at.run()
```

For values read via `os.getenv(...)` inside the page (the OVS-Log pattern for
`ABUSEIPDB_API_KEY`, `LLM_API_KEY`, `OVS_LOGS_DB_PATH`), use
`pytest.MonkeyPatch` **before** `at.run()`:

```python
monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key-123")
monkeypatch.delenv("OVS_LOGS_DB_PATH", raising=False)
at = AppTest.from_file(str(APP_PATH)).run()
```

## 3. OVS-Log–specific recipes

### 3.1 Build a temp DuckDB for navigator tests

```python
import duckdb
from pathlib import Path

def _make_db(tmp_path: Path, tables: list[tuple[str, str]]) -> Path:
    """Create a temp DuckDB with the given (name, SELECT-as-DDL) tables."""
    db = tmp_path / "ovs_logs.db"
    with duckdb.connect(str(db)) as conn:
        for name, ddl in tables:
            conn.execute(f'CREATE TABLE "{name}" AS {ddl}')
    return db
```

### 3.2 Verify "Recent Tables" filters system tables

The OVD-50 sidebar excludes `information_schema`, `pg_catalog`, and any
`sqlite_*` / `pg_*` prefixed names. Assert that explicitly:

```python
db = _make_db(
    tmp_path,
    [
        ("events_2026", "SELECT 1 AS id"),
        ("indicators", "SELECT 'a' AS ip"),
        ("sqlite_should_hide", "SELECT 1"),
    ],
)
at = AppTest.from_file(str(APP_PATH)).run()
at.sidebar.text_input[2].set_value(str(db)).run()
sb = at.sidebar.selectbox[0]
assert "events_2026" in sb.options
assert "sqlite_should_hide" not in sb.options
```

### 3.3 Verify the table list refreshes when the DB path changes

```python
at.sidebar.text_input[2].set_value(str(db_a)).run()
assert at.sidebar.selectbox[0].options == ["alpha"]
at.sidebar.text_input[2].set_value(str(db_b)).run()
assert at.sidebar.selectbox[0].options == ["beta"]
assert at.session_state["selected_table"] == "beta"
```

## 4. Pitfalls and caveats

1. **Default DB file may exist in dev environments.** The default
   `settings.database.path` is `.ovs_logs/ovs_logs.db`. If the file exists
   (e.g. from a prior `ovs-log` CLI run), the sidebar shows a `st.info`
   "No application tables found" message, **not** the missing-file
   `st.error`. Write tests that accept both outcomes, or override the path
   via `at.sidebar.text_input[2].set_value(...)`.

2. **`os.getenv` is evaluated inside the page.** `monkeypatch.setenv` must
   run **before** `AppTest.from_file(...).run()`.

3. **Streamlit widget `value=` is a literal default.** Don't pre-seed via
   module-level `os.getenv` calls at import time in a way AppTest can't
   reach; the env lookup needs to happen at widget-construction time so
   `monkeypatch.setenv` takes effect.

4. **Run tests serially.** Streamlit's testing harness shares module state.
   Avoid `pytest-xdist` for UI tests, or configure it to a single worker
   for those files.

5. **Fresh DB connections per rerun.** `app.py::_read_user_tables` opens a
   new read-only DuckDB connection on every rerun. This is intentional
   (avoids stale handles when the path changes) and works fine under
   AppTest.

## 5. Running the tests

```bash
uv run pytest tests/test_ui_app.py -v   # one file
uv run pytest -q                        # full suite
```
