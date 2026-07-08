"""Benchmark suite for large text-log parsing strategies (OVD-33 / OVD-68 spikes)."""

from __future__ import annotations

import contextlib
import datetime
import json
import logging
import os
import random
import re
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

import duckdb
import pytest

from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import LoadResult, load_text_log
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import validate_log_file

logger = logging.getLogger(__name__)

_AMBIGUOUS_TIMESTAMP_PROBABILITY = 0.3


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogSample:
    name: str
    path: Path
    format_hint: str


@dataclass(frozen=True)
class BenchmarkResult:
    strategy: str
    sample_name: str
    rows: int
    elapsed_seconds: float
    peak_kb: int
    regex_hits: dict[str, int] | None = None


# ---------------------------------------------------------------------------
# Synthetic sample generators
# ---------------------------------------------------------------------------


def _write_text(path: Path, content: str) -> LogSample:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return LogSample(name=path.stem, path=path, format_hint="log")


def generate_web_access_logs(line_count: int = 5000) -> str:
    """Generate Apache/nginx-style access log lines.

    Args:
        line_count: Number of log lines to produce.

    Returns:
        Newline-terminated log content suitable for ingestion tests.
    """
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    paths = ["/", "/api/v1/users", "/api/v1/auth/login", "/assets/main.js", "/health", "/api/v1/search", "/dashboard"]
    statuses = [200, 200, 200, 301, 400, 401, 403, 404, 500, 503]
    ips = [f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(50)]
    buf = StringIO()
    for i in range(line_count):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S %z", time.gmtime(1700000000 + i))
        ip = random.choice(ips)
        method = random.choice(methods)
        path_choice = random.choice(paths)
        status = random.choice(statuses)
        size = random.randint(100, 12000)
        buf.write(f'{ip} - - [{ts}] "{method} {path_choice} HTTP/1.1" {status} {size}\n')
    return buf.getvalue()


def generate_syslog_lines(line_count: int = 5000) -> str:
    """Generate syslog-style lines with embedded source IPs.

    Args:
        line_count: Number of log lines to produce.

    Returns:
        Newline-terminated log content suitable for ingestion tests.
    """
    facilities = ["systemd", "kernel", "sshd", "cron", "nginx", "app"]
    buf = StringIO()
    for i in range(line_count):
        month = time.strftime("%b", time.gmtime(1700000000 + i))
        day = random.randint(1, 28)
        ts = f"{month}  {day} 12:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"
        host = f"srv-{random.randint(1, 20):02d}"
        fac = random.choice(facilities)
        pid = random.randint(100, 9999)
        user = f"user{random.randint(1, 500)}"
        ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        port = random.randint(30000, 60000)
        event = random.choice(["Started", "Failed", "Accepted", "Closed", "Backup", "Error"])
        buf.write(f"{ts} {host} {fac}[{pid}]: {event} {user} {ip} port {port}\n")
    return buf.getvalue()


def generate_jsonlog_lines(line_count: int = 5000) -> str:
    """Generate one-line JSON log entries with a stable schema.

    Args:
        line_count: Number of JSON log lines to produce.

    Returns:
        Newline-terminated JSON-line content suitable for ingestion tests.
    """
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    components = ["auth", "ingest", "api", "worker", "scheduler"]
    buf = StringIO()
    for i in range(line_count):
        obj = {
            "ts": datetime.datetime.fromtimestamp(1700000000 + i, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": random.choice(levels),
            "component": random.choice(components),
            "msg": f"event sequence {i}",
            "src_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "status": random.choice([200, 201, 400, 401, 403, 404, 500, 502]),
            "duration_ms": random.randint(1, 2500),
        }
        buf.write(json.dumps(obj, separators=(",", ":")) + "\n")
    return buf.getvalue()


def generate_ambiguous_lines(line_count: int = 5000) -> str:
    """Lines with weak structure, used to exercise fallback paths.

    Args:
        line_count: Number of log lines to produce.

    Returns:
        Newline-terminated log content suitable for ingestion tests.
    """
    words = ["heartbeat", "cache-miss", "gc-pause", "retry", "timeout", "ok", "latency", "drop", "connect", "accept"]
    buf = StringIO()
    for i in range(line_count):
        w1 = random.choice(words)
        w2 = random.choice(words)
        marker = random.choice(["OK", "FAIL", "WARN", ""])
        if random.random() > _AMBIGUOUS_TIMESTAMP_PROBABILITY:
            ts = time.strftime("%H:%M:%S", time.gmtime(1700000000 + i))
            code = random.randint(0, 999)
            length = random.randint(10, 9000)
            buf.write(f"[{ts}] {w1}-{w2} {marker} code={code} len={length}\n")
        else:
            buf.write(f"{w1} {w2} {marker}\n")
    return buf.getvalue()


def write_sample(tmp_path: Path, name: str, generator: Callable[..., str], line_count: int = 5000) -> LogSample:
    path = tmp_path / f"{name}_{line_count}.log"
    if path.exists() and path.stat().st_size > 0:
        return LogSample(name=path.stem, path=path, format_hint="log")
    return _write_text(path, generator(line_count=line_count))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _measure(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float, int]:
    tracemalloc.start()
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, elapsed, max(peak, 0)


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _safe_unlink(path: Path) -> None:
    """Best-effort removal of a temporary file.

    On Windows a CSV opened by DuckDB's ``read_csv_auto`` may still be locked
    when the consuming query returns, so a direct ``unlink`` raises
    ``PermissionError``. Treat cleanup as best-effort so it does not mask the
    benchmark result with an unrelated I/O error.
    """
    with contextlib.suppress(OSError):
        path.unlink()


def _reload_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    quoted = _quote_identifier(table_name)
    row = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()
    row_count = int(row[0]) if row else 0
    schema_rows = connection.execute(f"DESCRIBE {quoted}").fetchall()
    schema = [(r[0], r[1]) for r in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def build_samples(tmp_path: Path, sizes: list[int] | None = None) -> dict[int, list[LogSample]]:
    """Build deterministic log samples for the requested sizes.

    Args:
        tmp_path: Pytest-provided scratch directory.
        sizes: Optional list of line counts to materialize. Defaults to ``[5000]``.

    Returns:
        Mapping of line count to the four canonical log samples.
    """
    if sizes is None:
        sizes = [5000]
    out: dict[int, list[LogSample]] = {}
    for size in sizes:
        out[size] = [
            write_sample(tmp_path, "web_access", generate_web_access_logs, size),
            write_sample(tmp_path, "syslog", generate_syslog_lines, size),
            write_sample(tmp_path, "jsonlog", generate_jsonlog_lines, size),
            write_sample(tmp_path, "ambiguous", generate_ambiguous_lines, size),
        ]
    return out


# ---------------------------------------------------------------------------
# Regex-based extraction helpers
# ---------------------------------------------------------------------------


def _extract_web(text: str) -> tuple[str, str, str, str]:
    ts = ip = status = event = ""
    m = _WEB_RE.search(text)
    if m:
        ts = m.group("ts") or ""
        ip = m.group("ip") or ""
        status = m.group("status") or ""
        event = "web"
    return ts, ip, status, event


def _extract_syslog(text: str) -> tuple[str, str, str, str]:
    ts = ip = status = event = ""
    m = _SYSLOG_RE.search(text)
    if m:
        ts = m.group("ts") or ""
        sm = _IP_RE.search(m.group("msg") or "")
        ip = sm.group("ip") if sm else ""
        event = m.group("proc") or ""
    return ts, ip, status, event


def _extract_jsonlog(text: str) -> tuple[str, str, str, str]:
    ts = ip = status = event = ""
    m = _JSON_LINE_RE.search(text)
    if m:
        ts = m.group("ts") or ""
    sm = _STATUS_RE.search(text)
    if sm:
        status = sm.group("status") or ""
    im = _IP_RE.search(text)
    if im:
        ip = im.group("ip") or ""
    event = "json"
    return ts, ip, status, event


def _extract_ambiguous(text: str) -> tuple[str, str, str, str]:
    ts = ip = status = event = ""
    im = _IP_RE.search(text)
    if im:
        ip = im.group("ip") or ""
    sm = _STATUS_RE.search(text)
    if sm:
        status = sm.group("status") or ""
    ts_match = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", text)
    ts = ts_match.group(1) if ts_match else ""
    event = "-".join(text.split()[:2])[:64]
    return ts, ip, status, event


_SAMPLE_REGEX_EXTRACTORS: dict[str, Callable[[str], tuple[str, str, str, str]]] = {
    "web": _extract_web,
    "syslog": _extract_syslog,
    "jsonlog": _extract_jsonlog,
    "ambiguous": _extract_ambiguous,
}


def _get_sample_extractor(sample_name: str) -> Callable[[str], tuple[str, str, str, str]]:
    for key in ("web", "syslog", "jsonlog", "ambiguous"):
        if sample_name.startswith(key):
            return _SAMPLE_REGEX_EXTRACTORS[key]
    return _SAMPLE_REGEX_EXTRACTORS["ambiguous"]


def _build_regex_csv(tmp: Path, raw: list[tuple[str, ...]], sample_name: str) -> dict[str, int]:
    counts = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}
    extract = _get_sample_extractor(sample_name)
    with tmp.open("w", encoding="utf-8") as f:
        f.write("timestamp,source_ip,status_code,event_type,raw_message\n")
        for (line,) in raw:
            text = line or ""
            ts, ip, status, event = extract(text)
            if ts:
                counts["timestamp"] += 1
            if ip:
                counts["source_ip"] += 1
            if status:
                counts["status_code"] += 1
            if event:
                counts["event_type"] += 1
            f.write(f"{ts},{ip},{status},{event},\n")
    return counts


def _build_hybrid_regex_set(sample_name: str) -> dict[str, re.Pattern[str] | None]:
    ts_re = ip_re = status_re = event_re = None
    if sample_name.startswith("web"):
        ts_re = re.compile(r"\[([^\]]+)\]")
        ip_re = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
        status_re = re.compile(r'"\s+(\d{3})\s+')
        event_re = re.compile(r'"(\w+)\s+\S+\s+HTTP')
    elif sample_name.startswith("syslog"):
        ts_re = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
        ip_re = re.compile(r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
        status_re = None
        event_re = re.compile(r"\s+(\w+?)(?:\[\d+\])?:")
    elif sample_name.startswith("jsonlog"):
        ts_re = re.compile(r'"ts"\s*:\s*"([^"]+)"')
        ip_re = re.compile(r'"src_ip"\s*:\s*"([^"]+)"')
        status_re = re.compile(r'"status"\s*:\s*(\d+)')
        event_re = re.compile(r'"component"\s*:\s*"([^"]+)"')
    else:
        ts_re = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")
        ip_re = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
        status_re = re.compile(r"code=(\d+)")
        event_re = None
    return {"timestamp": ts_re, "source_ip": ip_re, "status_code": status_re, "event_type": event_re}


def _extract_hybrid_fields(text: str, regexes: dict[str, re.Pattern[str] | None]) -> tuple[str, str, str, str]:
    ts = ip = status = event = ""
    if regexes["timestamp"]:
        m = regexes["timestamp"].search(text)
        if m:
            ts = m.group(1)
    if regexes["source_ip"]:
        m = regexes["source_ip"].search(text)
        if m:
            ip = m.group(1)
    if regexes["status_code"]:
        m = regexes["status_code"].search(text)
        if m:
            status = m.group(1)
    if regexes["event_type"]:
        m = regexes["event_type"].search(text)
        if m:
            event = m.group(1)
    return ts, ip, status, event


def _write_hybrid_csv(tmp: Path, raw_rows: list[tuple[str, ...]], sample_name: str) -> dict[str, int]:
    regexes = _build_hybrid_regex_set(sample_name)
    counts = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}
    with tmp.open("w", encoding="utf-8") as f:
        f.write("timestamp,source_ip,status_code,event_type,raw_message\n")
        for (line,) in raw_rows:
            text = line or ""
            ts, ip, status, event = _extract_hybrid_fields(text, regexes)
            if ts:
                counts["timestamp"] += 1
            if ip:
                counts["source_ip"] += 1
            if status:
                counts["status_code"] += 1
            if event:
                counts["event_type"] += 1
            f.write(f"{ts},{ip},{status},{event},\n")
    return counts


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------


_WEB_RE = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[^[]*\[(?P<ts>[^\]]+)\]\s+"[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\d+)',
    re.IGNORECASE,
)
_SYSLOG_RE = re.compile(
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.+)",
    re.IGNORECASE,
)
_JSON_LINE_RE = re.compile(r'"ts"\s*:\s*"(?P<ts>[^"]+)"', re.IGNORECASE)
_IP_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
_STATUS_RE = re.compile(r"\b(?P<status>(?:200|201|301|400|401|403|404|500|502|503))\b")


# ---------------------------------------------------------------------------
# Strategy 1: baseline (raw only)
# ---------------------------------------------------------------------------


def _baseline(sample: LogSample) -> BenchmarkResult:
    with Database(":memory:") as db:
        log = validate_log_file(sample.path)
        load_result, elapsed, peak = _measure(load_text_log, log, db)
        rows = load_result.row_count
    return BenchmarkResult(
        strategy="baseline_raw_only",
        sample_name=sample.name,
        rows=rows,
        elapsed_seconds=elapsed,
        peak_kb=round(peak / 1024),
    )


# ---------------------------------------------------------------------------
# Strategy 2: python_regex_loop
# ---------------------------------------------------------------------------


def _regex_python_loop(sample: LogSample) -> BenchmarkResult:
    hits = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}

    def _process(db_path: str) -> int:
        nonlocal hits
        with Database(db_path) as db:
            log = validate_log_file(sample.path)
            load_result = load_text_log(log, db, table_name="raw")
            rows = load_result.row_count
            raw = db.execute('SELECT line FROM "raw"').fetchall()
            tmp = Path(tempfile.mkstemp(suffix=".csv")[1])
            try:
                counts = _build_regex_csv(tmp, raw, sample.name)
                for key, value in counts.items():
                    hits[key] += value
                db.execute("DROP TABLE IF EXISTS raw")
                db.execute(
                    "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto("
                    "?, header=true, delim=',', all_varchar=true)",
                    [str(tmp)],
                )
                reloaded = _reload_result(db, "raw")
                NormalizationEngine().normalize_table(db, reloaded)
                return rows
            finally:
                _safe_unlink(tmp)

    rows, elapsed, peak = _measure(_process, ":memory:")
    return BenchmarkResult(
        strategy="python_regex_loop",
        sample_name=sample.name,
        rows=rows,
        elapsed_seconds=elapsed,
        peak_kb=round(peak / 1024),
        regex_hits=hits,
    )


# ---------------------------------------------------------------------------
# Strategy 3: parser_line (single format regex)
# ---------------------------------------------------------------------------


def _parser_based(sample: LogSample) -> BenchmarkResult:
    if sample.name.startswith("web"):
        pattern = re.compile(
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
            r"(?P<ident>\S+)\s+(?P<authuser>\S+)\s+"
            r'\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
            r"(?P<status>\d{3})\s+(?P<size>\d+)"
        )
    elif sample.name.startswith("syslog"):
        pattern = re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<msg>.+)$"
        )
    elif sample.name.startswith("jsonlog"):
        pattern = re.compile(r'^\{"ts":"(?P<ts>[^"]+)"')
    elif sample.name.startswith("ambiguous"):
        pattern = re.compile(
            r"^\[(?P<ts>\d{2}:\d{2}:\d{2})\]\s+"
            r"(?P<event>[^ ]+(?:-[^ ]+)?)\s+"
            r"(?P<status>WARN|FAIL|OK)?\s+"
            r"code=(?P<code>\d+)"
        )
    else:
        pattern = None

    hits = dict.fromkeys(["timestamp", "source_ip", "status_code", "event_type"], 0)

    def _process(db_conn: duckdb.DuckDBPyConnection) -> int:
        nonlocal hits
        log = validate_log_file(sample.path)
        load_result = load_text_log(log, db_conn, table_name="raw")
        rows = load_result.row_count
        if pattern is None:
            NormalizationEngine().normalize_table(db_conn, load_result)
            return rows
        data = db_conn.execute('SELECT line FROM "raw"').fetchall()
        tmp = Path(tempfile.mkstemp(suffix=".csv")[1])
        try:
            with tmp.open("w", encoding="utf-8") as f:
                f.write("timestamp,source_ip,status_code,event_type,raw_message\n")
                for (line,) in data:
                    text = line or ""
                    m = pattern.search(text)
                    ts = ip = status = event = ""
                    if m:
                        ts = m.group("ts") if "ts" in m.groupdict() else ""
                        ip = m.group("ip") if "ip" in m.groupdict() else ""
                        status = m.group("status") if "status" in m.groupdict() else ""
                        event = m.group("event") if "event" in m.groupdict() else ""
                    if ts:
                        hits["timestamp"] += 1
                    if ip:
                        hits["source_ip"] += 1
                    if status:
                        hits["status_code"] += 1
                    if event:
                        hits["event_type"] += 1
                    f.write(f"{ts},{ip},{status},{event},\n")
            db_conn.execute("DROP TABLE IF EXISTS raw")
            db_conn.execute(
                "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto("
                "?, header=true, delim=',', all_varchar=true)",
                [str(tmp)],
            )
            reloaded = _reload_result(db_conn, "raw")
            NormalizationEngine().normalize_table(db_conn, reloaded)
            return rows
        finally:
            _safe_unlink(tmp)

    with Database(":memory:") as db:
        rows, elapsed, peak = _measure(_process, db)
        return BenchmarkResult(
            strategy="parser_line",
            sample_name=sample.name,
            rows=rows,
            elapsed_seconds=elapsed,
            peak_kb=round(peak / 1024),
            regex_hits=hits,
        )


# ---------------------------------------------------------------------------
# Strategy 4: hybrid_light
# ---------------------------------------------------------------------------


def _hybrid(sample: LogSample) -> BenchmarkResult:
    hits = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}

    def _process(db_conn: duckdb.DuckDBPyConnection) -> int:
        nonlocal hits
        log = validate_log_file(sample.path)
        load_result = load_text_log(log, db_conn, table_name="raw")
        rows = load_result.row_count
        raw_rows = db_conn.execute('SELECT line FROM "raw"').fetchall()
        tmp = Path(tempfile.mkstemp(suffix=".csv")[1])
        try:
            counts = _write_hybrid_csv(tmp, raw_rows, sample.name)
            for key, value in counts.items():
                hits[key] += value
            db_conn.execute("DROP TABLE IF EXISTS raw")
            db_conn.execute(
                "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto("
                "?, header=true, delim=',', all_varchar=true)",
                [str(tmp)],
            )
            reloaded = _reload_result(db_conn, "raw")
            NormalizationEngine().normalize_table(db_conn, reloaded)
            return rows
        finally:
            _safe_unlink(tmp)

    with Database(":memory:") as db:
        rows, elapsed, peak = _measure(_process, db)
        return BenchmarkResult(
            strategy="hybrid_light",
            sample_name=sample.name,
            rows=rows,
            elapsed_seconds=elapsed,
            peak_kb=round(peak / 1024),
            regex_hits=hits,
        )


# ---------------------------------------------------------------------------
# Strategy 5: DuckDB-native regex via regexp_extract in SQL UPDATE
# ---------------------------------------------------------------------------


_DUCKDB_NATIVE_PATTERNS: dict[str, dict[str, tuple[str, str]]] = {
    "web": {
        "timestamp": (r"\[([^\]]+)\]", "i"),
        "source_ip": (r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ""),
        "status_code": (r'"\s+(\d{3})\s+', "i"),
        "event_type": (r'"(\w+)\s+\S+\s+HTTP', "i"),
    },
    "syslog": {
        "timestamp": (r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", "i"),
        "source_ip": (r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})", "i"),
        "event_type": (r"\s+(\w+?)(?:\[\d+\])?:", "i"),
    },
    "jsonlog": {
        "timestamp": (r'"ts"\s*:\s*"([^"]+)"', "i"),
        "source_ip": (r'"src_ip"\s*:\s*"([^"]+)"', "i"),
        "status_code": (r'"status"\s*:\s*(\d+)', "i"),
        "event_type": (r'"component"\s*:\s*"([^"]+)"', "i"),
    },
    "ambiguous": {
        "timestamp": (r"\[(\d{2}:\d{2}:\d{2})\]", ""),
        "source_ip": (r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ""),
        "status_code": (r"code=(\d+)", ""),
    },
}


def _duckdb_regex_native(sample: LogSample) -> BenchmarkResult:
    prefix = next(
        (key for key in ("web", "syslog", "jsonlog", "ambiguous") if sample.name.startswith(key)),
        "ambiguous",
    )
    patterns = _DUCKDB_NATIVE_PATTERNS.get(prefix, _DUCKDB_NATIVE_PATTERNS["ambiguous"])
    hits = dict.fromkeys(["timestamp", "source_ip", "status_code", "event_type"], 0)
    columns = ["timestamp", "source_ip", "status_code", "event_type"]
    raw_table = _quote_identifier("raw")

    def _process(conn: duckdb.DuckDBPyConnection) -> int:
        log = validate_log_file(sample.path)
        load_result = load_text_log(log, conn, table_name="raw")
        rows = load_result.row_count
        for col in columns:
            quoted_col = _quote_identifier(col)
            with contextlib.suppress(duckdb.BinderException):
                conn.execute(f"ALTER TABLE {raw_table} ADD COLUMN {quoted_col} VARCHAR")
        set_clauses = []
        for col, (_pat, _flags) in patterns.items():
            quoted_col = _quote_identifier(col)
            set_clauses.append(f"{quoted_col} = COALESCE(regexp_extract(line, ?, 1, ?), '')")
        params: list[str] = []
        for _col, (pat, flags) in patterns.items():
            params.extend([pat, flags])
        conn.execute(f"UPDATE {raw_table} SET {', '.join(set_clauses)}", params)
        count_exprs = ", ".join(f"COUNT_IF({_quote_identifier(col)} <> '')" for col in columns)
        counts = conn.execute(f"SELECT {count_exprs} FROM {raw_table}").fetchone()
        if counts is not None:
            for key, value in zip(columns, counts, strict=True):
                hits[key] = value or 0
        reloaded = _reload_result(conn, "raw")
        NormalizationEngine().normalize_table(conn, reloaded)
        return rows

    with Database(":memory:") as db:
        rows, elapsed, peak = _measure(_process, db)
        return BenchmarkResult(
            strategy="duckdb_regex_native",
            sample_name=sample.name,
            rows=rows,
            elapsed_seconds=elapsed,
            peak_kb=round(peak / 1024),
            regex_hits=hits,
        )


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------


def write_markdown_report(rows: list[dict], dest: Path) -> None:
    """Render a benchmark matrix to a Markdown report file.

    Args:
        rows: Strategy/sample result rows containing ``strategy``, ``sample``,
            ``rows``, ``elapsed_seconds``, and ``peak_kb`` keys.
        dest: Destination path for the report. Parent directories are created.
    """
    lines = [
        "# OVS-Log Text-Log Parsing Benchmark Report",
        "",
        "## Matrix",
        "",
        "| strategy | sample | rows | elapsed_s | peak_kb |",
        "| -- | -- | --: | --: | --: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['strategy']} | {row['sample']} | {row['rows']} | {row['elapsed_seconds']:.3f} | {row['peak_kb']} |"
        )
    lines += [
        "",
        "---",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC",
        "",
    ]
    report = "\n".join(lines)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n[report] Written to {dest}")


# ---------------------------------------------------------------------------
# Fixtures and tests
# ---------------------------------------------------------------------------


@pytest.fixture
def log_samples(tmp_path: Path) -> list[LogSample]:
    return build_samples(tmp_path, sizes=[5000])[5000]


@pytest.fixture
def large_log_samples(tmp_path: Path) -> dict[int, list[LogSample]]:
    return build_samples(tmp_path, sizes=[20_000, 100_000])


@pytest.mark.parametrize(
    "bench_fn",
    [_baseline, _regex_python_loop, _parser_based, _hybrid, _duckdb_regex_native],
    ids=lambda fn: fn.__name__.lstrip("_"),
)
def test_benchmark_strategies(
    bench_fn: Callable[[LogSample], BenchmarkResult],
    log_samples: list[LogSample],
) -> None:
    parsing_strategies = {_parser_based, _hybrid, _duckdb_regex_native}
    expected_rows = int(log_samples[0].name.rsplit("_", 1)[-1])
    for sample in log_samples:
        result = bench_fn(sample)
        suffix = f" | hits={result.regex_hits}" if result.regex_hits else ""
        logger.info(
            "%s | %s | rows=%d | %.3fs | %dKB%s",
            result.strategy,
            result.sample_name,
            result.rows,
            result.elapsed_seconds,
            result.peak_kb,
            suffix,
        )
        assert result.rows == expected_rows
        assert result.elapsed_seconds >= 0
        assert result.peak_kb >= 0
        if bench_fn in parsing_strategies:
            assert result.regex_hits is not None
            assert any(v > 0 for v in result.regex_hits.values()), (
                f"{result.strategy} produced no regex hits for {result.sample_name}"
            )


@pytest.mark.skipif(
    os.environ.get("OVD68_LARGE_BENCHMARKS", "").lower() not in ("1", "true", "yes"),
    reason="Set OVD68_LARGE_BENCHMARKS=1 to run 20k/100k benchmarks",
)
def test_benchmark_large(
    large_log_samples: dict[int, list[LogSample]],
    tmp_path: Path,
) -> None:
    strategies = [_baseline, _regex_python_loop, _parser_based, _hybrid, _duckdb_regex_native]
    rows: list[dict] = []
    for _size, samples in sorted(large_log_samples.items()):
        for bench_fn in strategies:
            for sample in samples:
                result = bench_fn(sample)
                rows.append(
                    {
                        "strategy": result.strategy,
                        "sample": result.sample_name,
                        "rows": result.rows,
                        "elapsed_seconds": result.elapsed_seconds,
                        "peak_kb": result.peak_kb,
                    }
                )
    report_path = tmp_path / "benchmark_large_report.md"
    write_markdown_report(rows, report_path)
    assert report_path.exists()
    assert report_path.read_text(encoding="utf-8").startswith("# OVS-Log Text-Log")


def test_report_summary(
    log_samples: list[LogSample],
    tmp_path: Path,
) -> None:
    strategies = [_baseline, _regex_python_loop, _parser_based, _hybrid, _duckdb_regex_native]
    rows: list[dict] = []
    for fn in strategies:
        for sample in log_samples:
            result = fn(sample)
            rows.append(
                {
                    "strategy": result.strategy,
                    "sample": result.sample_name,
                    "rows": result.rows,
                    "elapsed_seconds": result.elapsed_seconds,
                    "peak_kb": result.peak_kb,
                }
            )
    report_path = Path(tmp_path) / "benchmark_report.md"
    write_markdown_report(rows, report_path)
    assert rows
    assert report_path.exists()
    assert report_path.read_text(encoding="utf-8").startswith("# OVS-Log Text-Log")
