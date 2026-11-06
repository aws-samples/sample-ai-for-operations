# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A local query engine over the synthetic flow logs, using DuckDB instead of Athena.

It loads the generated ``AWSLogs/`` tree into a raw table with the same partition columns a table
created by this agent would have, then answers the same Trino-dialect SQL the Athena engine receives.
It exists for ``nfi demo`` and for CI, where Athena is not available. Requires the ``duckdb`` package.
"""

from __future__ import annotations

import itertools
import time
from pathlib import Path

from ..core.athena import QueryResult
from ..core.tablescheme import FIELD_TYPES, TableScheme, ident, normalise_field

_DUCK_TYPES = {"int": "INTEGER", "bigint": "BIGINT", "string": "VARCHAR"}


def _qualified(name: str) -> str:
    """A ``database.table`` (or bare) name in which every part passes ``ident()``."""
    return ".".join(ident(part) for part in name.split("."))


def _create_schema_sql(database: str) -> str:
    return "CREATE SCHEMA IF NOT EXISTS " + ident(database)


def _create_table_sql(table: str, body: str) -> str:
    return "CREATE TABLE " + _qualified(table) + " AS " + body


def _ctas_sql(table: str, select_sql: str) -> str:
    return "CREATE OR REPLACE TABLE " + _qualified(table) + " AS " + select_sql


def _count_sql(table: str) -> str:
    return "SELECT COUNT(*) FROM " + _qualified(table)  # nosec B608 - the name passes ident()


_LOAD_SQL = r"""
SELECT * EXCLUDE (filename),
  regexp_extract(filename, 'AWSLogs/(\d+)/vpcflowlogs/([^/]+)/(\d{4}/\d{2}/\d{2})/', 1) AS part_account,
  regexp_extract(filename, 'AWSLogs/(\d+)/vpcflowlogs/([^/]+)/(\d{4}/\d{2}/\d{2})/', 2) AS part_region,
  regexp_extract(filename, 'AWSLogs/(\d+)/vpcflowlogs/([^/]+)/(\d{4}/\d{2}/\d{2})/', 3) AS day
FROM read_csv(?, delim=' ', header=true, nullstr='-', columns={__COLUMNS__}, filename=true)
"""


class DuckDBEngine:
    def __init__(
        self,
        s3_root: str | Path,
        database: str,
        table: str,
        *,
        simulate_scan: bool = True,
        accounts: list[str] | None = None,
    ) -> None:
        try:
            import duckdb
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("demo mode needs duckdb: pip install 'network-flow-insight[demo]'") from exc
        self._con = duckdb.connect(":memory:")
        self._n = itertools.count(1)
        self._simulate = simulate_scan
        self._con.execute(_create_schema_sql(database))
        files = sorted(
            str(p)
            for p in Path(s3_root).rglob("*.log.gz")
            if accounts is None or any(f"/AWSLogs/{a}/" in str(p) for a in accounts)
        )
        if not files:
            raise FileNotFoundError(f"no flow-log files under {s3_root}")
        header = self._header(files[0])
        cols = ", ".join(f"'{h}': '{_DUCK_TYPES[FIELD_TYPES[h]]}'" for h in header)
        body = _LOAD_SQL.replace("__COLUMNS__", cols)
        self._con.execute(_create_table_sql(database + "." + table, body), [files])  # file paths are bound parameters
        self.scheme = TableScheme(database, table, tuple(header))

    @staticmethod
    def _header(path: str) -> list[str]:
        import gzip

        with gzip.open(path, "rt") as fh:
            return [normalise_field(h) for h in fh.readline().split()]

    def run(self, sql: str, *, max_rows: int | None = None, hint_bytes: int | None = None) -> QueryResult:
        started = time.monotonic()
        cur = self._con.execute(sql)
        cols = [d[0] for d in (cur.description or [])]
        data = cur.fetchmany(max_rows) if max_rows else cur.fetchall()
        rows = [dict(zip(cols, r, strict=True)) for r in data]
        scanned = int(hint_bytes or 0) if self._simulate else 0
        return QueryResult(
            rows,
            cols,
            f"duckdb-{next(self._n):06d}",
            scanned,
            sql,
            int((time.monotonic() - started) * 1000),
            bool(max_rows and len(rows) >= max_rows),
        )

    def ctas(
        self, table: str, select_sql: str, location: str, *, hint_bytes: int | None = None
    ) -> QueryResult:
        self._con.execute(_ctas_sql(table, select_sql))  # select_sql is the aggregate statement sqlsafe checked
        n = self._con.execute(_count_sql(table)).fetchone()[0]
        return QueryResult(
            [{"rows": n}],
            ["rows"],
            f"duckdb-{next(self._n):06d}",
            int(hint_bytes or 0) if self._simulate else 0,
            f"CREATE TABLE {table} (local)",
        )
