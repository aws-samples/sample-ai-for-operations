# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Query engines and the cost gauge.

``AthenaEngine`` runs SQL on Amazon Athena and captures the execution ID and bytes scanned on every
call. ``CostGauge`` estimates before, records actuals after, and keeps the running total.
``GaugedEngine`` combines them so that no query runs without an estimate and every run is logged.
Both engines return ``QueryResult`` so tools never care which one they are talking to.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)

ATHENA_MIN_BILLED_BYTES = 10 * 1000 * 1000  # Athena bills at least 10 MB per query.
BYTES_PER_TB = 1000**4  # decimal; the gauge reports estimates, not invoices.


class QuerySkipped(RuntimeError):
    """The gauge declined to run a query (over ceiling in scheduled mode, or over budget)."""


@dataclass
class QueryResult:
    rows: list[dict[str, Any]]
    columns: list[str]
    execution_id: str
    scanned_bytes: int
    sql: str
    elapsed_ms: int = 0
    truncated: bool = False


class QueryEngine(Protocol):
    def run(self, sql: str, *, max_rows: int | None = None, hint_bytes: int | None = None) -> QueryResult: ...

    def ctas(
        self, table: str, select_sql: str, location: str, *, hint_bytes: int | None = None
    ) -> QueryResult: ...


_INT_TYPES = {"tinyint", "smallint", "integer", "bigint"}
_FLOAT_TYPES = {"float", "double", "real", "decimal"}


def _cast(value: str | None, athena_type: str) -> Any:
    if value is None:
        return None
    t = athena_type.lower()
    try:
        if t in _INT_TYPES:
            return int(value)
        if t in _FLOAT_TYPES:
            return float(value)
        if t == "boolean":
            return value.lower() == "true"
    except ValueError:
        return value
    return value


class AthenaEngine:
    """Thin, synchronous Athena runner."""

    def __init__(
        self,
        client: Any,
        workgroup: str,
        output_location: str = "",
        database: str = "",
        enforce_output: bool = False,
        poll_seconds: float = 1.0,
        timeout_seconds: int = 900,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._c = client
        self._workgroup = workgroup
        self._output = output_location
        self._db = database
        self._poll = poll_seconds
        self._enforce = enforce_output
        self._timeout = timeout_seconds
        self._sleep = sleep

    def ctas(
        self, table: str, select_sql: str, location: str, *, hint_bytes: int | None = None
    ) -> QueryResult:
        """Create a Parquet table from a SELECT. ``table`` and ``location`` come from validated config."""
        if not location.startswith("s3://") or "'" in location or "'" in table:
            raise ValueError("invalid CTAS target")
        loc = location if location.endswith("/") else location + "/"
        # A workgroup that enforces its output location rejects an explicit external_location.
        ext = "" if self._enforce else f", external_location='{loc}'"
        sql = f"CREATE TABLE {table} WITH (format='PARQUET', write_compression='SNAPPY'{ext}) AS {select_sql}"
        return self.run(sql)

    def run(self, sql: str, *, max_rows: int | None = None, hint_bytes: int | None = None) -> QueryResult:
        kw: dict[str, Any] = {"QueryString": sql, "WorkGroup": self._workgroup}
        if self._db:
            kw["QueryExecutionContext"] = {"Database": self._db}
        if self._output:
            kw["ResultConfiguration"] = {"OutputLocation": self._output}
        started = time.monotonic()
        qid = self._c.start_query_execution(**kw)["QueryExecutionId"]
        qe = self._wait(qid)
        stats = qe.get("Statistics", {})
        scanned = int(stats.get("DataScannedInBytes", 0))
        elapsed = int(stats.get("TotalExecutionTimeInMillis", (time.monotonic() - started) * 1000))
        stype = qe.get("StatementType", "DML")
        rows: list[dict[str, Any]] = []
        cols: list[str] = []
        truncated = False
        if stype == "DML" and not sql.lstrip().upper().startswith("CREATE"):
            rows, cols, truncated = self._fetch(qid, max_rows)
        logger.info(
            json.dumps(
                {
                    "event": "athena_query",
                    "execution_id": qid,
                    "scanned_bytes": scanned,
                    "elapsed_ms": elapsed,
                    "rows": len(rows),
                }
            )
        )
        return QueryResult(rows, cols, qid, scanned, sql, elapsed, truncated)

    def _wait(self, qid: str) -> dict:
        deadline = time.monotonic() + self._timeout
        while True:
            qe = self._c.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
            state = qe["Status"]["State"]
            if state == "SUCCEEDED":
                return qe
            if state in ("FAILED", "CANCELLED"):
                reason = qe["Status"].get("StateChangeReason", "no reason given")
                raise RuntimeError(f"Athena query {qid} {state}: {reason}")
            if time.monotonic() > deadline:
                with contextlib.suppress(Exception):
                    self._c.stop_query_execution(QueryExecutionId=qid)
                raise TimeoutError(f"Athena query {qid} exceeded {self._timeout}s")
            self._sleep(self._poll)

    def _fetch(self, qid: str, max_rows: int | None) -> tuple[list[dict], list[str], bool]:
        rows: list[dict] = []
        token = None
        cols: list[str] = []
        types: list[str] = []
        first = True
        while True:
            kw: dict[str, Any] = {"QueryExecutionId": qid, "MaxResults": 1000}
            if token:
                kw["NextToken"] = token
            page = self._c.get_query_results(**kw)
            if not cols:
                info = page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
                cols = [i["Label"] for i in info]
                types = [i["Type"] for i in info]
            data = page["ResultSet"]["Rows"]
            if first:
                data = data[1:]  # header row
                first = False
            for r in data:
                vals = [d.get("VarCharValue") for d in r["Data"]]
                rows.append({c: _cast(v, t) for c, v, t in zip(cols, vals, types, strict=False)})
                if max_rows is not None and len(rows) >= max_rows:
                    return rows, cols, True
            token = page.get("NextToken")
            if not token:
                return rows, cols, False


@dataclass
class LedgerEntry:
    label: str
    execution_id: str
    sql: str
    estimated_bytes: int | None
    scanned_bytes: int
    cost_usd: float
    skipped: bool = False
    reason: str = ""


@dataclass
class CostGauge:
    """Estimate before, actuals after, running total. Prices come from ``get_prices``."""

    price_per_tb: float
    ceiling_usd: float
    budget_usd: float
    ledger: list[LedgerEntry] = field(default_factory=list)

    def estimate(self, bytes_to_scan: int) -> dict:
        billed = max(int(bytes_to_scan), ATHENA_MIN_BILLED_BYTES)
        return {
            "bytes": int(bytes_to_scan),
            "gb": round(bytes_to_scan / 1000**3, 3),
            "cost_usd": round(billed / BYTES_PER_TB * self.price_per_tb, 4),
        }

    def actual_cost(self, scanned_bytes: int) -> float:
        billed = max(int(scanned_bytes), ATHENA_MIN_BILLED_BYTES)
        return billed / BYTES_PER_TB * self.price_per_tb

    @property
    def total_bytes(self) -> int:
        return sum(e.scanned_bytes for e in self.ledger)

    @property
    def total_cost_usd(self) -> float:
        return round(sum(e.cost_usd for e in self.ledger), 4)

    def decide(self, est: dict) -> str:
        """``run`` | ``confirm`` | ``over_budget``."""
        if self.total_cost_usd + est["cost_usd"] > self.budget_usd:
            return "over_budget"
        return "confirm" if est["cost_usd"] > self.ceiling_usd else "run"

    def summary(self) -> dict:
        return {
            "queries": len([e for e in self.ledger if not e.skipped]),
            "skipped": len([e for e in self.ledger if e.skipped]),
            "scanned_bytes": self.total_bytes,
            "cost_usd": self.total_cost_usd,
            "ceiling_usd": self.ceiling_usd,
            "budget_usd": self.budget_usd,
        }


class GaugedEngine:
    """Runs queries through an engine under a gauge.

    ``interactive`` + ``confirm`` decide what happens above the ceiling: in interactive mode the
    ``confirm`` callback is asked; in scheduled mode the query is skipped and recorded.
    """

    def __init__(
        self,
        engine: QueryEngine,
        gauge: CostGauge,
        *,
        interactive: bool = True,
        confirm: Callable[[str, dict], bool] | None = None,
    ) -> None:
        self.engine = engine
        self.gauge = gauge
        self.interactive = interactive
        self._confirm = confirm

    def run(
        self, sql: str, *, estimated_bytes: int, label: str = "", max_rows: int | None = None
    ) -> QueryResult:
        self._admit(label, sql, estimated_bytes)
        res = self.engine.run(sql, max_rows=max_rows, hint_bytes=estimated_bytes)
        self._record(label, sql, estimated_bytes, res)
        return res

    def ctas(
        self, table: str, select_sql: str, location: str, *, estimated_bytes: int, label: str = ""
    ) -> QueryResult:
        self._admit(label, select_sql, estimated_bytes)
        res = self.engine.ctas(table, select_sql, location, hint_bytes=estimated_bytes)
        self._record(label, select_sql, estimated_bytes, res)
        return res

    def _record(self, label: str, sql: str, estimated_bytes: int, res: QueryResult) -> None:
        self.gauge.ledger.append(
            LedgerEntry(
                label,
                res.execution_id,
                sql,
                estimated_bytes,
                res.scanned_bytes,
                self.gauge.actual_cost(res.scanned_bytes),
            )
        )
        return res

    def _admit(self, label: str, sql: str, estimated_bytes: int) -> None:
        est = self.gauge.estimate(estimated_bytes)
        decision = self.gauge.decide(est)
        if decision == "over_budget":
            self._skip(label, sql, estimated_bytes, "session budget would be exceeded")
        if decision == "confirm":
            if not self.interactive or self._confirm is None:
                self._skip(label, sql, estimated_bytes, "estimate above ceiling in non-interactive mode")
            elif not self._confirm(label or sql[:80], est):
                self._skip(label, sql, estimated_bytes, "declined at ceiling confirmation")

    def _skip(self, label: str, sql: str, est_bytes: int, reason: str) -> None:
        self.gauge.ledger.append(LedgerEntry(label, "", sql, est_bytes, 0, 0.0, True, reason))
        raise QuerySkipped(reason)
