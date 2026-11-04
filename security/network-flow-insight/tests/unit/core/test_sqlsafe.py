# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import pytest

from network_flow_insight.core.sqlsafe import SqlPolicy, SqlRejected, validate

POLICY = SqlPolicy(
    allowed_tables={"flow_raw": ("day",), "agg": ("day",), "cur": ()},
    max_limit=100,
)


def ok(sql):
    return validate(sql, POLICY)


def test_accepts_bounded_select_and_adds_limit():
    out = ok("SELECT dstport, SUM(bytes) FROM agg WHERE day BETWEEN '2026-01-01' AND '2026-01-07' GROUP BY 1")
    assert out.upper().endswith("LIMIT 100")


def test_caps_large_limit():
    out = ok("SELECT * FROM agg WHERE day = '2026-01-01' LIMIT 100000")
    assert out.upper().endswith("LIMIT 100")


def test_keeps_smaller_limit():
    assert ok("SELECT * FROM agg WHERE day = '2026-01-01' LIMIT 5").upper().endswith("LIMIT 5")


def test_cte_names_are_not_tables_but_inner_tables_are_checked():
    ok("WITH x AS (SELECT * FROM agg WHERE day >= '2026-01-01') SELECT * FROM x")
    with pytest.raises(SqlRejected, match="bounded"):
        ok("WITH x AS (SELECT * FROM agg) SELECT * FROM x WHERE day >= '2026-01-01'")


@pytest.mark.parametrize(
    "sql, reason",
    [
        ("SELECT * FROM agg", "bounded"),
        ("SELECT * FROM agg WHERE bytes > 5", "bounded"),
        ("SELECT * FROM agg WHERE day IS NOT NULL", "bounded"),
        ("SELECT * FROM other WHERE day = '2026-01-01'", "not allowed"),
        ("DROP TABLE agg", "SELECT"),
        ("SELECT 1; SELECT 2", "exactly one"),
        ("INSERT INTO agg SELECT * FROM agg WHERE day = 'x'", "SELECT"),
        ("CREATE TABLE t AS SELECT * FROM agg WHERE day = 'x'", "SELECT"),
        ("SELECT * FROM agg WHERE day = 'x' LIMIT ALL", "LIMIT"),
        ("SELECT \"$path\" FROM agg WHERE day = 'x'", "pseudo"),
        ("", "empty"),
        ("SELEKT nope", "not allowed|parse|SELECT"),
    ],
)
def test_rejections(sql, reason):
    with pytest.raises(SqlRejected, match=reason):
        ok(sql)


def test_unpartitioned_allowed_table_needs_no_predicate():
    ok("SELECT usage_type, SUM(x) FROM cur GROUP BY 1")


def test_subquery_in_from_checked():
    with pytest.raises(SqlRejected):
        ok("SELECT * FROM (SELECT * FROM agg) t WHERE t.day = '2026-01-01'")


def test_join_on_bound_accepted():
    ok("SELECT a.day FROM agg a JOIN cur c ON a.day = c.d WHERE a.day = '2026-01-01'")

# ---------------------------------------------------------------- window-bounded policy (raw table)

from network_flow_insight.core.sqlsafe import WindowBound  # noqa: E402

WIN = ("2026-03-02", "2026-03-08")


def _wpolicy(kind="slash", cols=("day",)):
    return SqlPolicy({"raw": cols}, max_limit=100, window=WindowBound(kind, *WIN))


def _w(sql, kind="slash", cols=("day",)):
    return validate(sql, _wpolicy(kind, cols))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 FROM raw WHERE day BETWEEN '2026/03/02' AND '2026/03/08'",
        "SELECT 1 FROM raw WHERE day BETWEEN '2026/03/03' AND '2026/03/04' AND action = 'ACCEPT'",
        "SELECT 1 FROM raw WHERE day = '2026/03/05'",
        "SELECT 1 FROM raw WHERE day IN ('2026/03/03', '2026/03/04')",
        "SELECT 1 FROM raw WHERE day >= '2026/03/02' AND day <= '2026/03/08'",
        "SELECT 1 FROM raw WHERE '2026/03/02' <= day AND '2026/03/08' >= day",
        "SELECT 1 FROM raw WHERE (day BETWEEN '2026/03/02' AND '2026/03/08') AND (bytes > 5)",
        "WITH x AS (SELECT * FROM raw WHERE day BETWEEN '2026/03/02' AND '2026/03/08') SELECT count(*) FROM x",
    ],
)
def test_window_accepts_literal_range_inside_the_window(sql):
    assert _w(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 FROM raw WHERE day > '2000/01/01'",
        "SELECT 1 FROM raw WHERE day = day",
        "SELECT 1 FROM raw WHERE day LIKE '%'",
        "SELECT 1 FROM raw WHERE day <> 'x'",
        "SELECT 1 FROM raw WHERE day = '2026/03/02' OR 1 = 1",
        "SELECT 1 FROM raw WHERE day BETWEEN '2026/03/02' AND '2026/03/08' OR bytes > 0",
        "SELECT 1 FROM raw WHERE NOT (day BETWEEN '2026/03/02' AND '2026/03/08')",
        "SELECT 1 FROM raw WHERE day >= '2026/03/02'",
        "SELECT 1 FROM raw WHERE day <= '2026/03/08'",
        "SELECT 1 FROM raw WHERE day BETWEEN '2026/03/01' AND '2026/03/08'",
        "SELECT 1 FROM raw WHERE day BETWEEN '2026/03/02' AND '2026/03/09'",
        "SELECT 1 FROM raw WHERE day BETWEEN '2025/01/01' AND '2025/01/07'",
        "SELECT 1 FROM raw WHERE day BETWEEN '2026-03-02' AND '2026-03-08'",
        "SELECT 1 FROM raw WHERE day BETWEEN 'a' AND 'b'",
        "SELECT 1 FROM raw WHERE day IN ('2026/03/03', day)",
        "SELECT 1 FROM raw WHERE day BETWEEN lower(day) AND '2026/03/08'",
    ],
)
def test_window_rejects_predicates_that_do_not_bound_the_scan(sql):
    with pytest.raises(SqlRejected, match="window"):
        _w(sql)


def test_window_message_names_the_window_and_shows_the_form():
    with pytest.raises(SqlRejected) as exc:
        _w("SELECT 1 FROM raw WHERE day > '2000/01/01'")
    msg = str(exc.value)
    assert "2026-03-02" in msg and "2026-03-08" in msg and "BETWEEN '2026/03/02' AND '2026/03/08'" in msg


@pytest.mark.parametrize(
    "kind, lit_a, lit_b",
    [
        ("dash", "'2026-03-02'", "'2026-03-08'"),
        ("date", "DATE '2026-03-02'", "DATE '2026-03-08'"),
    ],
)
def test_window_other_day_formats(kind, lit_a, lit_b):
    assert _w(f"SELECT 1 FROM raw WHERE day BETWEEN {lit_a} AND {lit_b}", kind)  # nosec B608 -- test SQL names only tables and values the test itself defines
    with pytest.raises(SqlRejected, match="window"):
        _w(f"SELECT 1 FROM raw WHERE day BETWEEN {lit_a} AND {lit_b.replace('08', '09')}", kind)  # nosec B608 -- test SQL names only tables and values the test itself defines


def test_window_ymd_columns_each_need_bounds_and_the_box_must_fit():
    cols = ("p_year", "p_month", "p_day")
    good = "SELECT 1 FROM raw WHERE p_year = '2026' AND p_month = '03' AND p_day BETWEEN '02' AND '08'"
    assert _w(good, "ymd", cols)
    assert _w(
        "SELECT 1 FROM raw WHERE p_year = 2026 AND p_month = 3 AND p_day >= 2 AND p_day <= 8", "ymd", cols
    )
    for bad in (
        "SELECT 1 FROM raw WHERE p_year = '2026' AND p_month = '03'",
        "SELECT 1 FROM raw WHERE p_year = '2026' AND p_month = '03' AND p_day BETWEEN '01' AND '08'",
        "SELECT 1 FROM raw WHERE p_year = '2026' AND p_month BETWEEN '02' AND '03' AND p_day BETWEEN '02' AND '08'",
        "SELECT 1 FROM raw WHERE p_year = '2026' AND p_month = '03' AND p_day > '01'",
    ):
        with pytest.raises(SqlRejected, match="window"):
            _w(bad, "ymd", cols)


def test_window_still_requires_a_predicate_and_a_limit():
    with pytest.raises(SqlRejected, match="window"):
        _w("SELECT 1 FROM raw")
    assert _w("SELECT 1 FROM raw WHERE day = '2026/03/05'").upper().endswith("LIMIT 100")


def test_without_a_window_the_presence_check_is_unchanged():
    # aggregate and build-time statements keep the original rule
    assert ok("SELECT * FROM agg WHERE day >= '2026-01-01'")
