# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The aggregate: one pass over the raw partitions for a window, at the finest grain any section needs.

Every report section and every chat question then runs against this compact table, so the raw scan is
paid once per window. Columns that the flow-log format does not carry are NULL.

Port normalisation keeps the aggregate small. A port counts as ephemeral (stored as 0) when it is 32768
or above, or when the other side of the record uses a well-known port (below 1024) and this side is
1024 or above. Servers on ports below 32768 keep their exact port.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .tablescheme import TableScheme, ident

AGG_COLUMNS = (
    "day",
    "hour",
    "account_id",
    "region",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "pkt_srcaddr",
    "pkt_dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "action",
    "log_status",
    "flow_direction",
    "traffic_path",
    "pkt_src_aws_service",
    "pkt_dst_aws_service",
    "vpc_id",
    "subnet_id",
    "az_id",
    "bytes",
    "packets",
    "records",
)
GROUP_COLUMNS = AGG_COLUMNS[:-3]
INT_COLUMNS = ("srcport", "dstport", "protocol", "traffic_path", "bytes", "packets", "records")

_HOUR = {
    "trino": 'hour(from_unixtime("start"))',
    "duckdb": 'hour(to_timestamp("start"))',
}


@dataclass(frozen=True)
class AggregateSpec:
    table: str  # unqualified aggregate table name
    first_day: str
    last_day: str


def source_tag(source: str) -> str:
    """Short, stable tag for the raw flow-log table an aggregate is built from (``database.table``)."""
    return hashlib.sha256(source.strip().lower().encode()).hexdigest()[:8]


def aggregate_table_name(first_day: str, last_day: str, source: str) -> str:
    """One aggregate name per raw flow-log table and window, so tables sharing an agent database never collide
    and a settled aggregate is only ever reused for the table it was built from."""
    return f"nfi_agg_{source_tag(source)}_{first_day.replace('-', '')}_{last_day.replace('-', '')}"


def _port(this: str, other: str) -> str:
    return f"CASE WHEN {other} < 1024 AND {this} >= 1024 THEN 0 WHEN {this} >= 32768 THEN 0 ELSE {this} END"


def aggregate_select(scheme: TableScheme, first_day: str, last_day: str, dialect: str = "trino") -> str:
    """The SELECT that builds the aggregate. Bounded by the scheme's partition predicate."""
    ident(scheme.table)
    has = scheme.has

    def col(name: str, sql_type: str = "varchar") -> str:
        return name if has(name) else f"CAST(NULL AS {sql_type})"

    selects = [
        f"{scheme.day_expr()} AS day",
        f"{_HOUR[dialect]} AS hour" if has("start") else "CAST(NULL AS integer) AS hour",
        f"{scheme.account_expr()} AS account_id",
        f"{scheme.region_expr()} AS region",
        "interface_id",
        "srcaddr",
        "dstaddr",
        f"{col('pkt_srcaddr')} AS pkt_srcaddr",
        f"{col('pkt_dstaddr')} AS pkt_dstaddr",
        f"{_port('srcport', 'dstport')} AS srcport",
        f"{_port('dstport', 'srcport')} AS dstport",
        "protocol",
        "action",
        "log_status",
        f"{col('flow_direction')} AS flow_direction",
        f"{col('traffic_path', 'integer')} AS traffic_path",
        f"{col('pkt_src_aws_service')} AS pkt_src_aws_service",
        f"{col('pkt_dst_aws_service')} AS pkt_dst_aws_service",
        f"{col('vpc_id')} AS vpc_id",
        f"{col('subnet_id')} AS subnet_id",
        f"{col('az_id')} AS az_id",
        "COALESCE(SUM(bytes), 0) AS bytes",
        "COALESCE(SUM(packets), 0) AS packets",
        "COUNT(*) AS records",
    ]
    group = ", ".join(str(i) for i in range(1, len(GROUP_COLUMNS) + 1))
    body = ",\n  ".join(selects)
    return (
        f"SELECT\n  {body}\nFROM {scheme.qualified}\n"  # nosec B608 - identifiers pass ident(); values are quoted or parsed
        f"WHERE {scheme.window_predicate(first_day, last_day)}\nGROUP BY {group}"
    )
