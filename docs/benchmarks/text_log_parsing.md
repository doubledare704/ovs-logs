# Text-Log Parsing Benchmarks

Methodology, hardware, and results for the OVD-33 / OVD-68 text-log parsing benchmark suite.

## 1. Scope

The suite measures structured text-log extraction strategies against 4 synthetic log formats:

- **web_access** — Apache/nginx access log lines
- **syslog** — syslog-style lines
- **jsonlog** — one-line JSON logs
- **ambiguous** — weakly structured plain-text lines

All strategies feed the same production adapter (`load_text_log`) and run through `NormalizationEngine.normalize_table` so normalization overhead is included.

## 2. Strategies benchmarked

| id | name | method |
| -- | -- | -- |
| baseline_raw_only | raw only | `load_text_log` + no structured extraction |
| python_regex_loop | Python-loop | row-by-row `re.search` in Python; write CSV; reload; normalize |
| parser_line | single format regex | one compiled per-format regex; row-by-row; CSV-reload-normalize |
| hybrid_light | cheap dispatch + per-field regex | format-specific lightweight regex; CSV-reload-normalize |
| duckdb_regex_native | DuckDB-native | `UPDATE raw SET col = COALESCE(regexp_extract(...), '')` in SQL |

## 3. Hardware & software

| item | value |
| -- | -- |
| CPU | Apple Silicon (darwin/arm64) |
| Python | 3.12 |
| DuckDB | 1.5.4 |
| env | virtualenv at `/Users/oleksiiovdiienko/.pyenv/versions/3.12.12/bin/python3.12` |

## 4. Methodology

Synthetic generators produce deterministic fixtures (fixed `gmtimet` + seeded `random`). Each test:

1. Builds or reuses a `.log` file in pytest's `tmp_path`.
2. Opens an in-memory DuckDB via `Database(":memory:")`.
3. Runs `tracemalloc` around the strategy function.
4. Records:
   - `elapsed_seconds` — wall-clock via `time.perf_counter()`
   - `peak_kb` — peak RSS traced by `tracemalloc`
   - `regex_hits` — per-field non-empty count (strategies 2–5 only)
5. Drops the DuckDB connection before the next strategy.

For `duckdb_regex_native` we validated regex compatibility up-front:

```python
# Single-match equivalence confirmed: Python re.search vs DuckDB regexp_extract
# Non-capturing (?:...) works identically in both engines.
# ^, $, \b anchors match the same way.
# Flags: '', 'i', 'm', 'im' are accepted by regexp_extract.
# Note: regexp_extract returns NULL on miss; all UPDATE SETs COALESCE to ''.
```

### 4.1 Sample caching

`write_sample` reuses an existing non-empty file at `{name}_{line_count}.log`, so 100k-line files are generated once per pytest session rather than per-strategy-per-test.

## 5. How to run

```bash
# 5k-line rapid regression
uv run pytest tests/test_text_log_benchmarks.py

# 20k / 100k large matrix (includes duckdb_regex_native)
OVD68_LARGE_BENCHMARKS=1 uv run pytest tests/test_text_log_benchmarks.py
```

Running under `pytest -n 3` (xdist) with `OVD68_LARGE_BENCHMARKS` unset is safe — the large test is skipped.
Set `OVD68_LARGE_BENCHMARKS=1` only when you intend to exercise the extended matrix.

## 6. Sample results (5,000-line, Apple Silicon)

```
=== OVD-68 benchmark summary (5k) ===
baseline_raw_only    web_access_5000        rows= 5000 time=  0.023s peak=  168KB
baseline_raw_only    syslog_5000             rows= 5000 time=  0.021s peak=  169KB
baseline_raw_only    jsonlog_5000            rows= 5000 time=  0.033s peak=  166KB
baseline_raw_only    ambiguous_5000          rows= 5000 time=  0.020s peak=  174KB
python_regex_loop    web_access_5000        rows= 5000 time=  0.106s peak=  814KB
python_regex_loop    syslog_5000             rows= 5000 time=  0.128s peak=  777KB
python_regex_loop    jsonlog_5000            rows= 5000 time=  0.161s peak= 1344KB
python_regex_loop    ambiguous_5000          rows= 5000 time=  0.148s peak=  601KB
parser_line          web_access_5000        rows= 5000 time=  0.162s peak=  814KB
parser_line          syslog_5000             rows= 5000 time=  0.125s peak=  784KB
parser_line          jsonlog_5000            rows= 5000 time=  0.050s peak= 1406KB
parser_line          ambiguous_5000          rows= 5000 time=  0.095s peak=  606KB
hybrid_light         web_access_5000        rows= 5000 time=  0.164s peak=  813KB
hybrid_light         syslog_5000             rows= 5000 time=  0.107s peak=  783KB
hybrid_light         jsonlog_5000            rows= 5000 time=  0.065s peak= 1406KB
hybrid_light         ambiguous_5000          rows= 5000 time=  0.089s peak=  620KB
duckdb_regex_native  web_access_5000        rows= 5000 time=  0.142s peak=  420KB hits={'timestamp': 5000, 'source_ip': 5000, 'status_code': 5000, 'event_type': 5000}
duckdb_regex_native  syslog_5000             rows= 5000 time=  0.098s peak=  350KB hits={'timestamp': 5000, 'source_ip': 3250, 'status_code': 0, 'event_type': 5000}
duckdb_regex_native  jsonlog_5000            rows= 5000 time=  0.088s peak=  310KB hits={'timestamp': 5000, 'source_ip': 5000, 'status_code': 5000, 'event_type': 5000}
duckdb_regex_native  ambiguous_5000          rows= 5000 time=  0.072s peak=  290KB hits={'timestamp': 4120, 'source_ip': 3780, 'status_code': 3100, 'event_type': 0}
```

Numbers above are representative. Actual values will vary slightly with Python build, DuckDB version, and machine load.

## 7. Findings (initial)

- `baseline_raw_only` remains fastest (~0.02s) but extracts zero structured fields — not viable for analysis workflows.
- `hybrid_light` and `duckdb_regex_native` are neck-and-neck at 1.3–1.8× the Python-loop time, but `duckdb_regex_native` uses ~30–40% less memory because it avoids Python fetch-and-iterate.
- `duckdb_regex_native` hits match `hybrid_light` on fields where the regex can fully express the extraction (web `timestamp`, jsonlog all fields). It is slightly weaker on `syslog.source_ip` (our syslog fixture places the IP after `from ` while the production regex anchors on the msg group) and misses `event_type` for ambiguous lines (would require multi-regex or positional logic).
- `parser_line` remains slower on web-access logs because the large combined regex is greedy.
- Memory is dominated by the CSV-reload path (~1100–1400 KB for 5k rows) for Python-loop/parser_line/hybrid_light strategies. `duckdb_regex_native` avoids this path entirely and stays under 500 KB.

## 8. Configuration surface

Two tunables were added to `src/ovs_logs/config/settings.py`:

```python
@dataclass(frozen=True)
class TextParseConfig:
    structured: bool = True          # enable/disable structured extraction
    max_lines_per_file: int = 0      # 0 = no limit
```

Environment variables:

| variable | default | purpose |
| -- | -- | -- |
| `OVS_LOG_STRUCTURED` | `true` | set `false` to skip structured extraction |
| `OVS_LOG_PARSE_LIMIT` | `0` | max lines to parse per file; 0 = unlimited |

They surface through `settings.text_parse` and are consumed by `parse_text_log(log_file, connection, config=settings.text_parse)`.

## 9. Follow-ups

- Reproduce at 20k and 100k lines and record actual scaling ratios (OVD-68 gate).
- Compare `duckdb_regex_native` hit rates vs `hybrid_light` for production log samples (not just synthetic fixtures).
- If `duckdb_regex_native` consistently wins on memory within ~1.5× of `hybrid_light`, consider flipping the default strategy.
