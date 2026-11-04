# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Dates that reach SQL text are re-parsed at the point of use."""

from types import SimpleNamespace

import pytest

from network_flow_insight.analysis import Analysis
from network_flow_insight.core.athena import QueryResult
from network_flow_insight.core.tablescheme import iso_day
from network_flow_insight.tools import query_cur, query_resolver_logs

BAD = [
    "2026-03-02' OR '1'='1",
    "2026-03-02'; DROP TABLE x; --",
    "20260302",
    "2026-3-2",
    "2026-03-02T00:00:00",
    " 2026-03-02",
    "2026-03-02 ",
    "2026-13-01",
    "2026-02-30",
    "",
    "2026-W10-1",
]


def test_iso_day_accepts_only_a_plain_calendar_date():
    assert iso_day("2026-03-02") == "2026-03-02"
    assert iso_day("2024-02-29") == "2024-02-29"
    for bad in BAD:
        with pytest.raises(ValueError):
            iso_day(bad)
    with pytest.raises(ValueError):
        iso_day(20260302)  # type: ignore[arg-type]


class _Engine:
    def __init__(self):
        self.sql = []

    def run(self, sql, **kw):
        self.sql.append(sql)
        return QueryResult([], [], "q-1", 0, sql)


def _analysis(engine, database="nfi_agent"):
    return SimpleNamespace(b=SimpleNamespace(agg_database=database, engine=engine))


def test_load_rows_validates_dates_and_names_and_runs_nothing_when_they_are_bad():
    eng = _Engine()
    a = _analysis(eng)
    Analysis._load_rows(a, "nfi_agg_ab12cd34_20260302_20260308", "2026-03-02", "2026-03-08")
    assert eng.sql == [
        "SELECT * FROM nfi_agent.nfi_agg_ab12cd34_20260302_20260308 WHERE day BETWEEN '2026-03-02' AND '2026-03-08'"
    ]
    eng.sql.clear()
    for bad in BAD:
        with pytest.raises(ValueError):
            Analysis._load_rows(a, "t", bad, "2026-03-08")
        with pytest.raises(ValueError):
            Analysis._load_rows(a, "t", "2026-03-02", bad)
    with pytest.raises(ValueError):
        Analysis._load_rows(a, "t; drop table x", "2026-03-02", "2026-03-08")
    with pytest.raises(ValueError):
        Analysis._load_rows(_analysis(eng, "db.x"), "t", "2026-03-02", "2026-03-08")
    assert eng.sql == []


def test_cur_and_resolver_reject_bad_dates_without_running_a_statement():
    eng = _Engine()
    for bad in BAD:
        with pytest.raises(ValueError):
            query_cur.query_cur(eng, "d", "t", bad, "2026-03-08", ["1"])
        with pytest.raises(ValueError):
            query_cur.query_cur(eng, "d", "t", "2026-03-02", bad, ["1"])
        with pytest.raises(ValueError):
            query_resolver_logs.query_resolver_logs(eng, "d", "t", ["1.2.3.4"], bad, "2026-03-08")
        with pytest.raises(ValueError):
            query_resolver_logs.query_resolver_logs(eng, "d", "t", ["1.2.3.4"], "2026-03-02", bad)
    assert eng.sql == []
