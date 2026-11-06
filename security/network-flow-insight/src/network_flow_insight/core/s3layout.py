# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Walk the ``AWSLogs/`` layout of the configured flow-log bucket (this bucket only).

Supports the standard layout (``AWSLogs/<account>/vpcflowlogs/<region>/yyyy/mm/dd/``), the
Hive-compatible layout (``aws-account-id=…/aws-service=vpcflowlogs/aws-region=…/year=…/month=…/day=…``)
and the organisation form that puts an ``o-…`` segment after ``AWSLogs/``. Listing is hierarchical
(accounts, then Regions, then one listing per day in the window) so cost is proportional to the
window and not to the history in the bucket.
"""

from __future__ import annotations

import io
import logging
import re
import zlib
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .tablescheme import normalise_field, window_days

logger = logging.getLogger(__name__)

_STD = re.compile(
    r"(?:^|/)AWSLogs/(?:o-[a-z0-9]+/)?(\d{12})/vpcflowlogs/([a-z0-9-]+)/(\d{4})/(\d{2})/(\d{2})/"
)
_HIVE = re.compile(
    r"(?:^|/)AWSLogs/(?:o-[a-z0-9]+/)?aws-account-id=(\d{12})/aws-service=vpcflowlogs/aws-region=([a-z0-9-]+)/"
    r"year=(\d{4})/month=(\d{2})/day=(\d{2})/"
)


@dataclass(frozen=True)
class PartitionKey:
    account_id: str
    region: str
    day: str  # ISO yyyy-mm-dd
    layout: str  # standard | hive


def parse_key(key: str) -> PartitionKey | None:
    for rx, layout in ((_STD, "standard"), (_HIVE, "hive")):
        m = rx.search(key)
        if m:
            a, r, y, mo, d = m.groups()
            return PartitionKey(a, r, f"{y}-{mo}-{d}", layout)
    return None


@dataclass
class LogInventory:
    bucket: str
    layout: str = "standard"
    org_id: str = ""
    file_format: str = "text"
    hourly: bool = False
    bytes_by_partition: dict[tuple[str, str, str], int] = field(default_factory=dict)
    objects_by_partition: dict[tuple[str, str, str], int] = field(default_factory=dict)
    accounts: set[str] = field(default_factory=set)
    regions_by_account: dict[str, set[str]] = field(default_factory=dict)
    sample_key: str = ""

    def add(self, key: str, size: int) -> None:
        pk = parse_key(key)
        if pk is None:
            return
        part = (pk.account_id, pk.region, pk.day)
        self.bytes_by_partition[part] = self.bytes_by_partition.get(part, 0) + int(size)
        self.objects_by_partition[part] = self.objects_by_partition.get(part, 0) + 1
        self.accounts.add(pk.account_id)
        self.regions_by_account.setdefault(pk.account_id, set()).add(pk.region)
        self.layout = pk.layout
        if key.endswith(".parquet"):
            self.file_format = "parquet"
        if re.search(r"/hour=\d{2}/|/\d{4}/\d{2}/\d{2}/\d{2}/", key):
            self.hourly = True
        self.sample_key = self.sample_key or key

    def merge(self, other: LogInventory) -> None:
        """Fold in partitions found for another window (the previous-window comparison)."""
        self.bytes_by_partition.update(other.bytes_by_partition)
        self.objects_by_partition.update(other.objects_by_partition)
        self.accounts |= other.accounts
        for a, rs in other.regions_by_account.items():
            self.regions_by_account.setdefault(a, set()).update(rs)
        self.sample_key = self.sample_key or other.sample_key

    @property
    def regions(self) -> set[str]:
        return {r for rs in self.regions_by_account.values() for r in rs}

    @property
    def days(self) -> list[str]:
        return sorted({d for (_, _, d) in self.bytes_by_partition})

    def bytes_for(
        self, accounts: set[str] | None = None, regions: set[str] | None = None, days: set[str] | None = None
    ) -> int:
        return sum(
            b
            for (a, r, d), b in self.bytes_by_partition.items()
            if (accounts is None or a in accounts)
            and (regions is None or r in regions)
            and (days is None or d in days)
        )

    def summary(self) -> dict:
        return {
            "bucket": self.bucket,
            "layout": self.layout,
            "file_format": self.file_format,
            "hourly": self.hourly,
            "org_id": self.org_id,
            "accounts": sorted(self.accounts),
            "regions": {a: sorted(r) for a, r in sorted(self.regions_by_account.items())},
            "days": self.days,
            "bytes": self.bytes_for(),
            "partitions": [
                {
                    "account_id": a,
                    "region": r,
                    "day": d,
                    "bytes": b,
                    "objects": self.objects_by_partition[(a, r, d)],
                }
                for (a, r, d), b in sorted(self.bytes_by_partition.items())
            ],
        }


def _common_prefixes(s3: Any, bucket: str, prefix: str) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kw: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "Delimiter": "/"}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        out += [p["Prefix"] for p in page.get("CommonPrefixes", [])]
        if not page.get("IsTruncated"):
            return out
        token = page["NextContinuationToken"]


def _list_objects(s3: Any, bucket: str, prefix: str):
    token = None
    while True:
        kw: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        yield from page.get("Contents", [])
        if not page.get("IsTruncated"):
            return
        token = page["NextContinuationToken"]


def _last(prefix: str) -> str:
    return prefix.rstrip("/").rsplit("/", 1)[-1]


def walk(s3: Any, bucket: str, first_day: str, last_day: str, prefix: str = "AWSLogs/") -> LogInventory:
    """Inventory the partitions under ``bucket/prefix`` for the window. Lists this bucket only."""
    inv = LogInventory(bucket)
    root = prefix if prefix.endswith("/") else prefix + "/"
    level1 = _common_prefixes(s3, bucket, root)
    bases: list[tuple[str, str]] = []  # (org_prefix, org_id)
    if any(re.fullmatch(r"o-[a-z0-9]+", _last(p)) for p in level1):
        for p in level1:
            if re.fullmatch(r"o-[a-z0-9]+", _last(p)):
                bases.append((p, _last(p)))
                inv.org_id = _last(p)
    else:
        bases.append((root, ""))
    days = window_days(first_day, last_day)
    for base, _org in bases:
        for acct_p in _common_prefixes(s3, bucket, base):
            name = _last(acct_p)
            hive = name.startswith("aws-account-id=")
            acct = name.split("=", 1)[1] if hive else name
            if not re.fullmatch(r"\d{12}", acct):
                continue
            svc = f"{acct_p}aws-service=vpcflowlogs/" if hive else f"{acct_p}vpcflowlogs/"
            for reg_p in _common_prefixes(s3, bucket, svc):
                reg = _last(reg_p).split("=", 1)[-1]
                for d in days:
                    y, m, dd = d.split("-")
                    dpath = f"{reg_p}year={y}/month={m}/day={dd}/" if hive else f"{reg_p}{y}/{m}/{dd}/"
                    for obj in _list_objects(s3, bucket, dpath):
                        inv.add(obj["Key"], obj["Size"])
                if reg not in inv.regions_by_account.get(acct, set()):
                    # Region exists but has nothing in the window: still record that it exists.
                    inv.regions_by_account.setdefault(acct, set()).add(reg)
                    inv.accounts.add(acct)
    return inv


def estimate_bytes(
    inv: LogInventory,
    first_day: str,
    last_day: str,
    accounts: set[str] | None = None,
    regions: set[str] | None = None,
) -> int:
    return inv.bytes_for(accounts, regions, set(window_days(first_day, last_day)))


def discover(s3: Any, bucket: str, prefix: str = "AWSLogs/") -> LogInventory:
    """Find accounts, Regions and the day range without knowing the window (standard and Hive layouts).

    Lists common prefixes down to the day, so the cost is proportional to the number of days, not objects.
    One object from the newest day (from any hour below it) is recorded so field detection has something to
    read; it also sets the inventory's layout, file format and hourly flag.
    """
    inv = LogInventory(bucket)
    root = prefix if prefix.endswith("/") else prefix + "/"
    level1 = _common_prefixes(s3, bucket, root)
    bases = [p for p in level1 if re.fullmatch(r"o-[a-z0-9]+", _last(p))]
    if bases:
        inv.org_id = _last(bases[0])
    else:
        bases = [root]
    newest = ""
    def val(p: str) -> str:  # "aws-region=eu-west-2" -> "eu-west-2"; "2026" -> "2026"
        return _last(p).split("=", 1)[-1]

    newest_day = ""
    for base in bases:
        for acct_p in _common_prefixes(s3, bucket, base):
            name = _last(acct_p)
            hive = name.startswith("aws-account-id=")
            acct = val(acct_p)
            if not re.fullmatch(r"\d{12}", acct):
                continue
            svc = f"{acct_p}aws-service=vpcflowlogs/" if hive else f"{acct_p}vpcflowlogs/"
            for reg_p in _common_prefixes(s3, bucket, svc):
                region = val(reg_p)
                inv.accounts.add(acct)
                inv.regions_by_account.setdefault(acct, set()).add(region)
                for y in _common_prefixes(s3, bucket, reg_p):
                    for m in _common_prefixes(s3, bucket, y):
                        for d in _common_prefixes(s3, bucket, m):
                            day = f"{val(y)}-{val(m)}-{val(d)}"
                            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                                continue
                            inv.bytes_by_partition.setdefault((acct, region, day), 0)
                            if day > newest_day:
                                newest_day, newest = day, d
    if newest:
        obj = next(iter(_list_objects(s3, bucket, newest)), None)
        if obj:
            inv.add(obj["Key"], obj["Size"])
    return inv


# -- field detection for the create path -----------------------------------------------------


def read_text_header(s3: Any, bucket: str, key: str) -> list[str]:
    """First line of a gzip or plain-text flow-log object, as normalised field names."""
    body = s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-65535")["Body"].read()
    if body[:2] == b"\x1f\x8b":
        text = zlib.decompressobj(31).decompress(body)
    else:
        text = body
    first = text.split(b"\n", 1)[0].decode("utf-8", "replace")
    return [normalise_field(f) for f in first.split()]


def read_parquet_columns(s3: Any, bucket: str, key: str, max_bytes: int = 256 * 1000 * 1000) -> list[str]:
    import pyarrow.parquet as pq

    head = s3.head_object(Bucket=bucket, Key=key)
    if head["ContentLength"] > max_bytes:
        raise ValueError("first Parquet object is too large to read for schema detection")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return [normalise_field(n) for n in pq.read_schema(io.BytesIO(body)).names]


def detect_fields(s3: Any, inv: LogInventory) -> tuple[str, ...]:
    if not inv.sample_key:
        raise ValueError("no flow-log objects found to detect fields from")
    if inv.file_format == "parquet":
        cols = read_parquet_columns(s3, inv.bucket, inv.sample_key)
    else:
        cols = read_text_header(s3, inv.bucket, inv.sample_key)
    return tuple(cols)


def previous_complete_days(today: date, n: int) -> tuple[str, str]:
    """The last ``n`` complete UTC days before ``today``: (first_day, last_day)."""
    from datetime import timedelta

    last = today - timedelta(days=1)
    first = last - timedelta(days=n - 1)
    return first.isoformat(), last.isoformat()
