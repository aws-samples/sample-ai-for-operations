# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""SQL validation. Every statement that touches Athena passes through ``validate`` first.

Rules (design section 4.4): single statement; SELECT only; tables restricted to an allowlist;
every partitioned table carries a bounded predicate on a partition column in the SELECT that reads
it; LIMIT present and capped; deny-listed functions and pseudo-columns rejected.
Failing statements are returned to the caller with the reason and never executed.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from datetime import date

import sqlglot
from sqlglot import exp

DIALECT = "trino"

DEFAULT_DENY_FUNCTIONS = frozenset({"unload", "system", "reflect", "java_method", "http_get", "http_post"})
_DML_DDL = tuple(
    getattr(exp, n)
    for n in (
        "Insert",
        "Create",
        "Drop",
        "Delete",
        "Update",
        "Alter",
        "Command",
        "Merge",
        "Use",
        "Set",
        "Copy",
        "Grant",
        "TruncateTable",
        "Describe",
        "Show",
        "Transaction",
        "Commit",
        "Rollback",
    )
    if hasattr(exp, n)
)
_COMPARISONS = tuple(
    getattr(exp, n)
    for n in ("EQ", "GT", "GTE", "LT", "LTE", "Between", "In", "Like", "NEQ")
    if hasattr(exp, n)
)


class SqlRejected(ValueError):
    """Raised with a reason the model (or user) can act on."""


@dataclass(frozen=True)
class WindowBound:
    """The days a cost estimate covers. With it set, a partitioned table must be bounded inside these days."""

    kind: str  # the raw table's day format: slash | dash | date | ymd
    first_day: str  # ISO dates, inclusive
    last_day: str


@dataclass(frozen=True)
class SqlPolicy:
    # table name (lower case, unqualified) -> partition columns of which one must be bounded.
    allowed_tables: dict[str, tuple[str, ...]]
    max_limit: int = 1000
    # unqualified table name -> database to qualify it with in the executed statement
    qualify: dict[str, str] = field(default_factory=dict)
    deny_functions: frozenset[str] = field(default_factory=lambda: DEFAULT_DENY_FUNCTIONS)
    # When set, a partitioned table needs literal start and end dates inside this window (see _window_bounded).
    # When None, a comparison on a partition column is enough (small, separately priced tables).
    window: WindowBound | None = None


def validate(sql: str, policy: SqlPolicy) -> str:
    """Return the (possibly LIMIT-rewritten) SQL or raise ``SqlRejected``."""
    if not isinstance(sql, str) or not sql.strip():
        raise SqlRejected("empty statement")
    try:
        parsed = [p for p in sqlglot.parse(sql, read=DIALECT) if p is not None]
    except sqlglot.errors.SqlglotError as exc:
        raise SqlRejected(f"could not parse SQL: {str(exc)[:200]}") from exc
    if len(parsed) != 1:
        raise SqlRejected("exactly one statement is allowed")
    root = parsed[0]
    if not isinstance(root, exp.Select | exp.Union | exp.Subquery):
        raise SqlRejected("only SELECT statements are allowed")
    for node in root.walk():
        if isinstance(node, _DML_DDL):
            raise SqlRejected(f"{type(node).__name__} is not allowed")
        if isinstance(node, exp.Into):
            raise SqlRejected("SELECT INTO is not allowed")

    ctes = {c.alias.lower() for c in root.find_all(exp.CTE) if c.alias}
    allowed = {k.lower(): v for k, v in policy.allowed_tables.items()}
    tables = [t for t in root.find_all(exp.Table) if t.name]
    if not tables:
        raise SqlRejected("statement must read from an allowed table")
    for t in tables:
        name = t.name.lower()
        if name in ctes:
            continue
        if name not in allowed:
            raise SqlRejected(f"table '{t.name}' is not allowed; allowed tables: {sorted(allowed)}")
        cols = allowed[name]
        if cols and policy.window is not None:
            if not _window_bounded(t, cols, policy.window):
                raise SqlRejected(_window_message(t.name, cols, policy.window))
        elif cols and not _has_bounded_predicate(t, cols):
            raise SqlRejected(
                f"table '{t.name}' must be bounded by a predicate on one of {list(cols)} "
                "(for example WHERE day BETWEEN '2026-01-01' AND '2026-01-07')"
            )

    for node in root.walk():
        if isinstance(node, exp.Anonymous):
            fname = node.name.lower()
        elif isinstance(node, exp.Func):
            fname = node.sql_name().lower()
        else:
            fname = ""
        if fname and fname in policy.deny_functions:
            raise SqlRejected(f"function '{fname}' is not allowed")
        if isinstance(node, exp.Identifier) and node.name.startswith("$"):
            raise SqlRejected("pseudo-columns such as $path are not allowed")

    for t in tables:
        db = {k.lower(): v for k, v in policy.qualify.items()}.get(t.name.lower())
        if db and t.name.lower() not in ctes:
            t.set("db", exp.to_identifier(db))

    limit = root.args.get("limit")
    if limit is None:
        root = root.limit(policy.max_limit, copy=False)
    else:
        expr = limit.args.get("expression")
        if isinstance(expr, exp.Literal) and expr.is_int:  # is_int is a property of sqlglot's Literal, not a method  # nosemgrep: is-function-without-parentheses
            if int(expr.this) > policy.max_limit:
                limit.set("expression", exp.Literal.number(policy.max_limit))
        else:
            raise SqlRejected("LIMIT must be an integer literal")
    return root.sql(dialect=DIALECT)


_SLASH = re.compile(r"^\d{4}/\d{2}/\d{2}$")
_DASH = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _terms(node: exp.Expression):
    """The AND-ed terms of a condition. OR, NOT and everything else is one opaque term."""
    if isinstance(node, exp.Paren):
        yield from _terms(node.this)
    elif isinstance(node, exp.And):
        yield from _terms(node.this)
        yield from _terms(node.expression)
    else:
        yield node


def _literal(node: exp.Expression | None) -> str | None:
    """A plain string, number or DATE literal, else None (columns, functions and arithmetic are not literals)."""
    if isinstance(node, exp.Cast) and isinstance(node.args.get("to"), exp.DataType) and node.args["to"].is_type("date"):
        node = node.this
    if isinstance(node, exp.Literal):
        return str(node.this)
    return None


def _parse_day(kind: str, raw: str) -> date | int | None:
    """One literal as a comparable value: a date for slash, dash and date; an integer for one ymd column."""
    try:
        if kind == "slash":
            return date.fromisoformat(raw.replace("/", "-")) if _SLASH.match(raw) else None
        if kind in ("dash", "date"):
            return date.fromisoformat(raw) if _DASH.match(raw) else None
        return int(raw) if raw.isdigit() else None
    except ValueError:
        return None


def _column_bounds(term: exp.Expression, cols: set[str], kind: str):
    """(column, [lower candidates], [upper candidates]) for a comparison of a partition column with literals."""
    if isinstance(term, exp.Between):
        col, lo, hi = term.this, _literal(term.args.get("low")), _literal(term.args.get("high"))
        if isinstance(col, exp.Column) and col.name.lower() in cols and lo is not None and hi is not None:
            return col.name.lower(), [_parse_day(kind, lo)], [_parse_day(kind, hi)]
        return None
    if isinstance(term, exp.In):
        col, vals = term.this, [_literal(v) for v in term.expressions]
        if isinstance(col, exp.Column) and col.name.lower() in cols and vals and None not in vals:
            parsed = [_parse_day(kind, v) for v in vals]
            if None in parsed:
                return col.name.lower(), [None], [None]
            return col.name.lower(), [min(parsed)], [max(parsed)]
        return None
    ops = {exp.EQ: "eq", exp.GT: "lo", exp.GTE: "lo", exp.LT: "hi", exp.LTE: "hi"}
    for cls, role in ops.items():
        if type(term) is cls:
            left, right = term.this, term.expression
            flipped = False
            if isinstance(right, exp.Column) and not isinstance(left, exp.Column):
                left, right, flipped = right, left, True
            val = _literal(right)
            if not (isinstance(left, exp.Column) and left.name.lower() in cols and val is not None):
                return None
            parsed = _parse_day(kind, val)
            if role == "eq":
                return left.name.lower(), [parsed], [parsed]
            if flipped:
                role = "hi" if role == "lo" else "lo"
            return (left.name.lower(), [parsed], []) if role == "lo" else (left.name.lower(), [], [parsed])
    return None


def _window_bounded(table: exp.Table, cols: tuple[str, ...], window: WindowBound) -> bool:
    """True if the table's SELECT limits every day column to literal start and end values inside the window.

    The terms must be AND-ed at the top of the WHERE (or of a join condition). A term under OR or NOT, a comparison
    with a column or function, an unparseable literal and a one-sided range do not count. Exclusive bounds are
    read as inclusive, which can only widen the range.
    """
    select = table.find_ancestor(exp.Select)
    if select is None:
        return False
    where = select.args.get("where")
    scopes = [where.this] if where is not None else []
    scopes += [j.args["on"] for j in select.args.get("joins") or [] if j.args.get("on") is not None]
    wanted = {c.lower() for c in cols}
    ymd = window.kind == "ymd"
    lowers: dict[str, list] = {c: [] for c in wanted}
    uppers: dict[str, list] = {c: [] for c in wanted}
    for scope in scopes:
        for term in _terms(scope):
            found = _column_bounds(term, wanted, "ymd" if ymd else window.kind)
            if found is None:
                continue
            col, lows, ups = found
            lowers[col] += [v for v in lows if v is not None]
            uppers[col] += [v for v in ups if v is not None]
    if any(not lowers[c] or not uppers[c] for c in wanted):
        return False
    first, last = date.fromisoformat(window.first_day), date.fromisoformat(window.last_day)
    if not ymd:
        col = next(iter(wanted))
        return first <= max(lowers[col]) and min(uppers[col]) <= last
    y, m, d = (c.lower() for c in cols)
    try:
        lo = _ymd_date(max(lowers[y]), max(lowers[m]), max(lowers[d]))
        hi = _ymd_date(min(uppers[y]), min(uppers[m]), min(uppers[d]))
    except ValueError:
        return False
    return first <= lo and hi <= last


def _ymd_date(year: int, month: int, day: int) -> date:
    if not 1 <= month <= 12 or day < 1:
        raise ValueError("not a calendar month or day")
    return date(year, month, min(day, calendar.monthrange(year, month)[1]))


def _window_message(table: str, cols: tuple[str, ...], window: WindowBound) -> str:
    a, b = date.fromisoformat(window.first_day), date.fromisoformat(window.last_day)
    if window.kind == "ymd":
        form = f"a literal start and end for each of {list(cols)}"
    elif window.kind == "slash":
        form = f"{cols[0]} BETWEEN '{a:%Y/%m/%d}' AND '{b:%Y/%m/%d}'"
    elif window.kind == "date":
        form = f"{cols[0]} BETWEEN DATE '{a.isoformat()}' AND DATE '{b.isoformat()}'"
    else:
        form = f"{cols[0]} BETWEEN '{a.isoformat()}' AND '{b.isoformat()}'"
    return (
        f"table '{table}' must be bounded to the window {a.isoformat()} to {b.isoformat()}: AND a literal start and "
        f"end date on {list(cols)} that lie inside it, for example WHERE {form}. "
        "Open-ended ranges, OR, NOT and comparisons with other columns do not bound the scan."
    )


def _has_bounded_predicate(table: exp.Table, cols: tuple[str, ...]) -> bool:
    select = table.find_ancestor(exp.Select)
    if select is None:
        return False
    wanted = {c.lower() for c in cols}
    where = select.args.get("where")
    scopes = [where] if where is not None else []
    # A join condition may carry the bound for the joined table.
    scopes += [j.args.get("on") for j in select.args.get("joins") or [] if j.args.get("on") is not None]
    for scope in scopes:
        for cmp_node in scope.find_all(*_COMPARISONS):
            if any(c.name.lower() in wanted for c in cmp_node.find_all(exp.Column)):
                return True
    return False
