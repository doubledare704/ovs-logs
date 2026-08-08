from collections.abc import Callable
from pathlib import Path

import duckdb

from ovs_logs.core.ingestion.adapters import IngestionResult
from ovs_logs.core.validation import LogFile

type DuckDBConn = duckdb.DuckDBPyConnection
type TableName = str | None
type TextLogAdapterFunc = Callable[[LogFile, DuckDBConn, TableName], IngestionResult]
type FilePath = str | Path
type EvtxAdapterFunc = TextLogAdapterFunc
