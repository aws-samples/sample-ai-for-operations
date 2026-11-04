# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""How a flow-log table is partitioned and which fields it carries, and the SQL that follows.

The raw flow-log table can be one the customer already has (any reasonable partitioning) or one
this agent creates (partition projection over the standard or Hive-compatible layout). Every SQL
builder in the package asks a ``TableScheme`` for the day expression and the window predicate so it
never hard-codes a partition column name.

Partition columns of tables this agent creates are ``part_account``, ``part_region`` and ``day``
(or ``p_year``, ``p_month``, ``p_day`` for the Hive-compatible layout). They deliberately do not reuse
``account_id`` or ``region`` because those are also flow-log field names and Athena rejects a
partition column that duplicates a data column.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Literal

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Field name (Athena column name) -> Athena type.
FIELD_TYPES: dict[str, str] = {
    "version": "int",
    "account_id": "string",
    "interface_id": "string",
    "srcaddr": "string",
    "dstaddr": "string",
    "srcport": "int",
    "dstport": "int",
    "protocol": "bigint",
    "packets": "bigint",
    "bytes": "bigint",
    "start": "bigint",
    "end": "bigint",
    "action": "string",
    "log_status": "string",
    "vpc_id": "string",
    "subnet_id": "string",
    "instance_id": "string",
    "tcp_flags": "int",
    "type": "string",
    "pkt_srcaddr": "string",
    "pkt_dstaddr": "string",
    "region": "string",
    "az_id": "string",
    "sublocation_type": "string",
    "sublocation_id": "string",
    "pkt_src_aws_service": "string",
    "pkt_dst_aws_service": "string",
    "flow_direction": "string",
    "traffic_path": "int",
}
DEFAULT_FIELDS = (
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
)
ENHANCED_FIELDS = ("vpc_id", "subnet_id", "az_id", "flow_direction", "pkt_srcaddr", "pkt_dstaddr")
FULL_FIELDS = ENHANCED_FIELDS + ("traffic_path", "pkt_src_aws_service", "pkt_dst_aws_service", "region")

DayKind = Literal["slash", "dash", "date", "ymd"]


def ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"unsafe identifier: {name!r}")
    return name


_ISO_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def iso_day(value: str) -> str:
    """A plain ``YYYY-MM-DD`` calendar date, rebuilt from the parsed value, for use inside SQL text.

    Python's own ``date.fromisoformat`` also accepts other forms, so the shape is checked first. Anything that is
    not exactly a calendar date raises ``ValueError`` and never reaches a statement.
    """
    if not isinstance(value, str) or not _ISO_DAY.match(value):
        raise ValueError(f"not an ISO date (YYYY-MM-DD): {value!r}")
    return date.fromisoformat(value).isoformat()


def normalise_field(name: str) -> str:
    return name.strip().replace("-", "_").lower()


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@dataclass(frozen=True)
class TableScheme:
    database: str
    table: str
    fields: tuple[str, ...] = DEFAULT_FIELDS
    day_kind: DayKind = "slash"
    day_col: str = "day"
    year_col: str = "p_year"
    month_col: str = "p_month"
    account_col: str | None = "part_account"
    region_col: str | None = "part_region"
    file_format: Literal["text", "parquet"] = "text"
    extra_partitions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for n in (self.database, self.table, self.day_col, self.year_col, self.month_col):
            ident(n)
        for n in (self.account_col, self.region_col):
            if n:
                ident(n)

    @property
    def qualified(self) -> str:
        return f"{ident(self.database)}.{ident(self.table)}"

    @property
    def partition_cols(self) -> tuple[str, ...]:
        if self.day_kind == "ymd":
            return (self.year_col, self.month_col, self.day_col)
        return (self.day_col,)

    def has(self, *names: str) -> bool:
        return all(n in self.fields for n in names)

    # -- SQL fragments ----------------------------------------------------------------------
    def day_expr(self) -> str:
        d = self.day_col
        if self.day_kind == "slash":
            return f"replace({d}, '/', '-')"
        if self.day_kind == "dash":
            return d
        if self.day_kind == "date":
            return f"CAST({d} AS varchar)"
        y, m = self.year_col, self.month_col
        return (
            f"concat(CAST({y} AS varchar), '-', lpad(CAST({m} AS varchar), 2, '0'), '-', "
            f"lpad(CAST({d} AS varchar), 2, '0'))"
        )

    def window_predicate(self, first_day: str, last_day: str) -> str:
        """Predicate bounding the partitions for ``first_day``..``last_day`` (inclusive, ISO dates)."""
        a, b = date.fromisoformat(first_day), date.fromisoformat(last_day)
        if a > b:
            raise ValueError("window start is after window end")
        d = self.day_col
        if self.day_kind == "slash":
            return (
                f"{d} BETWEEN {sql_literal(a.strftime('%Y/%m/%d'))} AND {sql_literal(b.strftime('%Y/%m/%d'))}"
            )
        if self.day_kind == "dash":
            return f"{d} BETWEEN {sql_literal(a.isoformat())} AND {sql_literal(b.isoformat())}"
        if self.day_kind == "date":
            return f"{d} BETWEEN DATE {sql_literal(a.isoformat())} AND DATE {sql_literal(b.isoformat())}"
        y, m = self.year_col, self.month_col
        num = f"(CAST({y} AS bigint) * 10000 + CAST({m} AS bigint) * 100 + CAST({d} AS bigint))"
        return f"{num} BETWEEN {a.year * 10000 + a.month * 100 + a.day} AND {b.year * 10000 + b.month * 100 + b.day}"

    def account_expr(self) -> str:
        return self.account_col or ("account_id" if self.has("account_id") else "'unknown'")

    def region_expr(self) -> str:
        if self.region_col:
            return self.region_col
        return "region" if self.has("region") else "'unknown'"


def window_days(first_day: str, last_day: str) -> list[str]:
    a, b = date.fromisoformat(first_day), date.fromisoformat(last_day)
    return [(a + timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]


def detect_scheme(
    database: str, table: str, columns: list[str], partition_keys: list[str], file_format: str = "text"
) -> TableScheme:
    """Infer the day/account/region partition columns of an existing table from its Glue schema."""
    cols = tuple(normalise_field(c) for c in columns if normalise_field(c) in FIELD_TYPES)
    keys = [normalise_field(k) for k in partition_keys]
    pk = set(keys)

    def pick(*cands: str) -> str | None:
        return next((c for c in cands if c in pk), None)

    account = pick("part_account", "aws_account_id", "account_id", "accountid", "account")
    region = pick("part_region", "aws_region", "region")
    if {"year", "month", "day"} <= pk:
        return TableScheme(database, table, cols, "ymd", "day", "year", "month", account, region, file_format)  # type: ignore[arg-type]
    if {"p_year", "p_month", "p_day"} <= pk:
        return TableScheme(
            database, table, cols, "ymd", "p_day", "p_year", "p_month", account, region, file_format
        )  # type: ignore[arg-type]
    day = pick("day", "date", "dt", "log_date", "partition_date")
    if day is None:
        raise ValueError(
            f"cannot find a day partition in {sorted(pk)}; expected day, date, or year/month/day"
        )
    # The kind (slash/dash/date) cannot be read from the schema alone; probe_table refines it
    # with a sample partition value. Default to the AWS-documented form.
    kind: DayKind = "date" if day == "date" else "slash"
    return TableScheme(database, table, cols, kind, day, "year", "month", account, region, file_format)  # type: ignore[arg-type]


def refine_day_kind(scheme: TableScheme, sample_partition_value: str) -> TableScheme:
    """Choose slash/dash/date from one real partition value (``2026/01/07``, ``2026-01-07``)."""
    if scheme.day_kind == "ymd":
        return scheme
    kind: DayKind = "slash" if "/" in sample_partition_value else "dash"
    if scheme.day_col == "date" and "-" in sample_partition_value:
        kind = "date"
    return TableScheme(**{**scheme.__dict__, "day_kind": kind})


# -- DDL for the create path (opt-in) ----------------------------------------------------------


def _col_defs(fields: tuple[str, ...]) -> str:
    return ",\n  ".join(f"`{f}` {FIELD_TYPES[f]}" for f in fields)


def projection_ddl(
    *,
    database: str,
    table: str,
    bucket: str,
    fields: tuple[str, ...],
    accounts: list[str],
    regions: list[str],
    first_day: str,
    layout: Literal["standard", "hive"] = "standard",
    file_format: Literal["text", "parquet"] = "text",
    prefix: str = "AWSLogs/",
    org_id: str = "",
) -> str:
    """CREATE EXTERNAL TABLE with partition projection over the delivered layout."""
    ident(database), ident(table)
    for f in fields:
        if f not in FIELD_TYPES:
            raise ValueError(f"unknown flow-log field {f!r}")
    for v in [*accounts, *regions]:
        if not re.fullmatch(r"[A-Za-z0-9\-]+", v):
            raise ValueError(f"unsafe account or Region value: {v!r}")
    if not re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        raise ValueError(f"unsafe bucket name: {bucket!r}")
    base = f"s3://{bucket}/{prefix.rstrip('/')}/"
    org = f"{org_id}/" if org_id else ""
    props = [
        "'projection.enabled'='true'",
        "'projection.part_account.type'='enum'",
        f"'projection.part_account.values'='{','.join(accounts)}'",
        "'projection.part_region.type'='enum'",
        f"'projection.part_region.values'='{','.join(regions)}'",
    ]
    if layout == "standard":
        parts = "`part_account` string, `part_region` string, `day` string"
        first = date.fromisoformat(first_day).strftime("%Y/%m/%d")
        props += [
            "'projection.day.type'='date'",
            "'projection.day.format'='yyyy/MM/dd'",
            f"'projection.day.range'='{first},NOW'",
            f"'storage.location.template'='{base}{org}${{part_account}}/vpcflowlogs/${{part_region}}/${{day}}'",
        ]
    else:
        parts = "`part_account` string, `part_region` string, `p_year` int, `p_month` int, `p_day` int"
        y = date.fromisoformat(first_day).year
        props += [
            "'projection.p_year.type'='integer'",
            f"'projection.p_year.range'='{y},{y + 10}'",
            "'projection.p_month.type'='integer'",
            "'projection.p_month.range'='1,12'",
            "'projection.p_month.digits'='2'",
            "'projection.p_day.type'='integer'",
            "'projection.p_day.range'='1,31'",
            "'projection.p_day.digits'='2'",
            "'storage.location.template'='"  # one location template split over three strings, not separate list items  # nosemgrep: string-concat-in-list
            f"{base}{org}aws-account-id=${{part_account}}/aws-service=vpcflowlogs/aws-region=${{part_region}}/"
            "year=${p_year}/month=${p_month}/day=${p_day}'",
        ]
    if file_format == "parquet":
        storage = "STORED AS PARQUET"
    else:
        storage = "ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '\nSTORED AS TEXTFILE"
        props.append("'skip.header.line.count'='1'")
    props.append("'agent-managed'='true'")
    return (
        f"CREATE EXTERNAL TABLE IF NOT EXISTS {database}.{table} (\n  {_col_defs(fields)}\n)\n"
        f"PARTITIONED BY ({parts})\n{storage}\nLOCATION '{base}'\nTBLPROPERTIES (\n  "
        + ",\n  ".join(props)
        + "\n)"
    )


def scheme_for_created_table(
    database: str, table: str, fields: tuple[str, ...], layout: str, file_format: str
) -> TableScheme:
    if layout == "hive":
        return TableScheme(
            database,
            table,
            fields,
            "ymd",
            "p_day",
            "p_year",
            "p_month",
            "part_account",
            "part_region",
            file_format,
        )  # type: ignore[arg-type]
    return TableScheme(
        database,
        table,
        fields,
        "slash",
        "day",
        "p_year",
        "p_month",
        "part_account",
        "part_region",
        file_format,
    )  # type: ignore[arg-type]
