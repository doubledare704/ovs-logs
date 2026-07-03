"""Benchmark suite for large text-log parsing strategies (OVD-33 spike)."""

from __future__ import annotations

import logging
import random
import re
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

import duckdb
import pytest

from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import LoadResult, load_text_log
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import validate_log_file

logger = logging.getLogger(__name__)


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


def _write_text(path: Path, content: str) -> LogSample:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return LogSample(name=path.stem, path=path, format_hint="log")


def generate_web_access_logs(line_count: int = 5000) -> str:
    """Generate Apache/nginx-style access log lines."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    paths = ["/", "/api/v1/users", "/api/v1/auth/login", "/assets/main.js", "/health", "/api/v1/search", "/dashboard"]
    statuses = [200, 200, 200, 301, 400, 401, 403, 404, 500, 503]
    ips = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]
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
    """Generate syslog-style lines."""
    facilities = ["systemd", "kernel", "sshd", "cron", "nginx", "app"]
    buf = StringIO()
    for i in range(line_count):
        month = time.strftime("%b", time.gmtime(1700000000 + i))
        day = random.randint(1, 28)
        ts = f"{month}  {day} 12:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
        host = f"srv-{random.randint(1,20):02d}"
        fac = random.choice(facilities)
        pid = random.randint(100, 9999)
        user = f"user{random.randint(1, 500)}"
        ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        port = random.randint(30000, 60000)
        event = random.choice(["Started", "Failed", "Accepted", "Closed", "Backup", "Error"])
        buf.write(f"{ts} {host} {fac}[{pid}]: {event} {user} {ip} port {port}\n")
    return buf.getvalue()


def generate_jsonlog_lines(line_count: int = 5000) -> str:
    """Generate one-line JSON log entries."""
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    components = ["auth", "ingest", "api", "worker", "scheduler"]
    buf = StringIO()
    for i in range(line_count):
        obj = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime(1700000000 + i)),
            "level": random.choice(levels),
            "component": random.choice(components),
            "msg": f"event sequence {i}",
            "src_ip": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            "status": random.choice([200, 201, 400, 401, 403, 404, 500, 502]),
            "duration_ms": random.randint(1, 2500),
        }
        serialized = str(obj).replace("'", "\"")
        escaped = serialized.replace("\\", "\\\\")
        quoted = "\"" + escaped.replace("\"", "\\\"") + "\""
        buf.write(f"{quoted}\n")
    return buf.getvalue()


def generate_ambiguous_lines(line_count: int = 5000) -> str:
    """Lines with weak structure."""
    words = ["heartbeat", "cache-miss", "gc-pause", "retry", "timeout", "ok", "latency", "drop", "connect", "accept"]
    buf = StringIO()
    for i in range(line_count):
        w1 = random.choice(words)
        w2 = random.choice(words)
        marker = random.choice(["OK", "FAIL", "WARN", ""])
        if random.random() > 0.3:
            buf.write(f"[{time.strftime('%H:%M:%S', time.gmtime(1700000000 + i))}] {w1}-{w2} {marker} code={random.randint(0, 999)} len={random.randint(10, 9000)}\n")
        else:
            buf.write(f"{w1} {w2} {marker}\n")
    return buf.getvalue()


def write_sample(tmp_path: Path, name: str, generator, line_count: int = 5000) -> LogSample:
    path = tmp_path / f"{name}_{line_count}.log"
    if path.exists() and path.stat().st_size > 0:
        return LogSample(name=path.stem, path=path, format_hint="log")
    return _write_text(path, generator(line_count=line_count))


def _measure(fn, *args, **kwargs):
    tracemalloc.start()
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, elapsed, max(peak, 0)


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


_WEB_RE = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[^[]*\[(?P<ts>[^\]]+)\]\s+"[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\d+)', re.IGNORECASE)
_SYSLOG_RE = re.compile(r'(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.+)', re.IGNORECASE)
_JSON_LINE_RE = re.compile(r'"ts"\s*:\s*"(?P<ts>[^"]+)"', re.IGNORECASE)
_IP_RE = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})')
_STATUS_RE = re.compile(r'\b(?P<status>(?:200|201|301|400|401|403|404|500|502|503))\b')


def _regex_python_loop(sample: LogSample) -> BenchmarkResult:
    hits = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}
    rows = 0

    def _process(db_path: str) -> int:
        nonlocal rows, hits
        with Database(db_path) as db:
            log = validate_log_file(sample.path)
            load_result = load_text_log(log, db, table_name="raw")
            rows = load_result.row_count
            raw = db.execute('SELECT line FROM "raw"').fetchall()
            tmp = Path(tempfile.mkstemp(suffix=".csv")[1])
            try:
                with tmp.open("w", encoding="utf-8") as f:
                    f.write("timestamp,source_ip,status_code,event_type,raw_message\n")
                    for (line,) in raw:
                        text = line or ""
                        ts = ip = status = event = ""
                        if sample.name.startswith("web"):
                            m = _WEB_RE.search(text)
                            if m:
                                ts = m.group("ts") or ""
                                ip = m.group("ip") or ""
                                status = m.group("status") or ""
                                event = "web"
                        elif sample.name.startswith("syslog"):
                            m = _SYSLOG_RE.search(text)
                            if m:
                                ts = m.group("ts") or ""
                                sm = _IP_RE.search(m.group("msg") or "")
                                ip = sm.group("ip") if sm else ""
                                event = m.group("proc") or ""
                        elif sample.name.startswith("jsonlog"):
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
                        elif sample.name.startswith("ambiguous"):
                            im = _IP_RE.search(text)
                            if im:
                                ip = im.group("ip") or ""
                            sm = _STATUS_RE.search(text)
                            if sm:
                                status = sm.group("status") or ""
                            ts_match = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", text)
                            ts = ts_match.group(1) if ts_match else ""
                            event = "-".join(text.split()[:2])[:64]
                        else:
                            event = "unknown"
                        if ts:
                            hits["timestamp"] += 1
                        if ip:
                            hits["source_ip"] += 1
                        if status:
                            hits["status_code"] += 1
                        if event:
                            hits["event_type"] += 1
                        f.write(f"{ts},{ip},{status},{event},\n")
                db.execute("DROP TABLE IF EXISTS raw")
                db.execute(
                    "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
                    [str(tmp)],
                )
                reloaded = _reload_result(db, "raw")
                NormalizationEngine().normalize_table(db, reloaded)
                return rows
            finally:
                if tmp.exists():
                    tmp.unlink()

    _, elapsed, peak = _measure(_process, ":memory:")
    return BenchmarkResult(
        strategy="python_regex_loop",
        sample_name=sample.name,
        rows=rows,
        elapsed_seconds=elapsed,
        peak_kb=round(peak / 1024),
        regex_hits=hits,
    )


def _parser_based(sample: LogSample) -> BenchmarkResult:
    if sample.name.startswith("web"):
        pattern = re.compile(
            r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
            r'(?P<ident>\S+)\s+(?P<authuser>\S+)\s+'
            r'\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
            r'(?P<status>\d{3})\s+(?P<size>\d+)'
        )
    elif sample.name.startswith("syslog"):
        pattern = re.compile(
            r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<msg>.+)$'
        )
    elif sample.name.startswith("jsonlog"):
        pattern = re.compile(r'^\{"ts":"(?P<ts>[^"]+)"')
    elif sample.name.startswith("ambiguous"):
        pattern = re.compile(r'^\[(?P<ts>\d{2}:\d{2}:\d{2})\]\s+(?P<event>[^ ]+(?:-[^ ]+)?)\s+(?P<status>WARN|FAIL|OK)?\s+code=(?P<code>\d+)')
    else:
        pattern = None

    def _process(db_conn: duckdb.DuckDBPyConnection) -> int:
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
                    f.write(f"{ts},{ip},{status},{event},\n")
            db_conn.execute("DROP TABLE IF EXISTS raw")
            db_conn.execute(
                "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
                [str(tmp)],
            )
            reloaded = _reload_result(db_conn, "raw")
            NormalizationEngine().normalize_table(db_conn, reloaded)
            return rows
        finally:
            if tmp.exists():
                tmp.unlink()

    with Database(":memory:") as db:
        rows, elapsed, peak = _measure(_process, db)
        return BenchmarkResult(
            strategy="parser_line",
            sample_name=sample.name,
            rows=rows,
            elapsed_seconds=elapsed,
            peak_kb=round(peak / 1024),
        )


def _hybrid(sample: LogSample) -> BenchmarkResult:
    hits = {"timestamp": 0, "source_ip": 0, "status_code": 0, "event_type": 0}

    def _process(db_conn: duckdb.DuckDBPyConnection) -> int:
        nonlocal hits
        log = validate_log_file(sample.path)
        load_result = load_text_log(log, db_conn, table_name="raw")
        rows = load_result.row_count
        raw_rows = db_conn.execute('SELECT line FROM "raw"').fetchall()
        ts_re = ip_re = status_re = event_re = None
        if sample.name.startswith("web"):
            ts_re = re.compile(r"\[([^\]]+)\]")
            ip_re = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
            status_re = re.compile(r'"\s+(\d{3})\s+')
            event_re = re.compile(r'"(\w+)\s+\S+\s+HTTP')
        elif sample.name.startswith("syslog"):
            ts_re = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
            ip_re = re.compile(r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
            status_re = None
            event_re = re.compile(r"\s+(\w+?)(?:\[\d+\])?:")
        elif sample.name.startswith("jsonlog"):
            ts_re = re.compile(r'"ts"\s*:\s*"([^"]+)"')
            ip_re = re.compile(r'"src_ip"\s*:\s*"([^"]+)"')
            status_re = re.compile(r'"status"\s*:\s*(\d+)')
            event_re = re.compile(r'"component"\s*:\s*"([^"]+)"')
        else:
            ts_re = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")
            ip_re = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
            status_re = re.compile(r"code=(\d+)")
            event_re = None
        tmp = Path(tempfile.mkstemp(suffix=".csv")[1])
        try:
            with tmp.open("w", encoding="utf-8") as f:
                f.write("timestamp,source_ip,status_code,event_type,raw_message\n")
                for (line,) in raw_rows:
                    text = line or ""
                    ts = ip = status = event = ""
                    if ts_re:
                        m = ts_re.search(text)
                        if m:
                            ts = m.group(1)
                    if ip_re:
                        m = ip_re.search(text)
                        if m:
                            ip = m.group(1)
                    if status_re:
                        m = status_re.search(text)
                        if m:
                            status = m.group(1)
                    if event_re:
                        m = event_re.search(text)
                        if m:
                            event = m.group(1)
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
                "CREATE OR REPLACE TABLE raw AS SELECT * FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
                [str(tmp)],
            )
            reloaded = _reload_result(db_conn, "raw")
            NormalizationEngine().normalize_table(db_conn, reloaded)
            return rows
        finally:
            if tmp.exists():
                tmp.unlink()

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


def _reload_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    row_count = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
    schema_rows = connection.execute(f'DESCRIBE "{table_name}"').fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def build_samples(tmp_path: Path, size: int = 5000) -> list[LogSample]:
    return [
        write_sample(tmp_path, "web_access", generate_web_access_logs, size),
        write_sample(tmp_path, "syslog", generate_syslog_lines, size),
        write_sample(tmp_path, "jsonlog", generate_jsonlog_lines, size),
        write_sample(tmp_path, "ambiguous", generate_ambiguous_lines, size),
    ]


@pytest.fixture
def log_samples(tmp_path: Path) -> list[LogSample]:
    return build_samples(tmp_path, size=5000)


@pytest.mark.parametrize(
    "bench_fn",
    [_baseline, _regex_python_loop, _parser_based, _hybrid],
    ids=lambda fn: fn.__name__.lstrip("_"),
)
def test_benchmark_strategies(bench_fn, log_samples, tmp_path: Path) -> None:
    results: list[BenchmarkResult] = []
    for sample in log_samples:
        result = bench_fn(sample)
        results.append(result)
        logger.info(
            "%s | %s | rows=%d | %.3fs | %dKB%s",
            result.strategy,
            result.sample_name,
            result.rows,
            result.elapsed_seconds,
            result.peak_kb,
            f" | hits={result.regex_hits}" if result.regex_hits else "",
        )
    assert len(results) == len(log_samples)


def test_report_summary(log_samples, tmp_path: Path) -> None:
    strategies = [_baseline, _regex_python_loop, _parser_based, _hybrid]
    rows: list[dict] = []
    for fn in strategies:
        for sample in log_samples:
            result = fn(sample)
            rows.append({
                "strategy": result.strategy,
                "sample": result.sample_name,
                "rows": result.rows,
                "elapsed_seconds": result.elapsed_seconds,
                "peak_kb": result.peak_kb,
            })
    print("\n=== OVD-33 benchmark summary ===")
    for row in rows:
        print(
            f"{row['strategy']:20} {row['sample']:20} "
            f"rows={row['rows']:5} time={row['elapsed_seconds']:7.3f}s peak={row['peak_kb']:6}KB"
        )
    assert rows
