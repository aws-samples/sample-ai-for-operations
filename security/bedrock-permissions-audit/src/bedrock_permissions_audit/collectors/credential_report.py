# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""IAM credential report: the only source of the root account's access keys. IAM reuses a report
generated within the last four hours, so these values can be up to four hours old, and a user
created since then is missing from it. For that reason nothing about IAM users is taken from it."""

from __future__ import annotations

import csv
import io
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

ROOT_USER = "<root_account>"
_NOT_READY = {"ReportInProgress"}
_NEEDS_GENERATING = {"ReportNotPresent", "ReportExpired"}
_ABSENT = {"", "N/A", "not_supported", "no_information"}


class CredentialReportTimeout(RuntimeError):
    """The report was not ready within the allowed time."""


@dataclass(frozen=True)
class ReportKey:
    slot: int
    active: bool
    last_rotated: datetime | None  # None means this slot holds no key
    last_used: datetime | None
    last_used_region: str | None

    @property
    def exists(self) -> bool:
        return self.last_rotated is not None


@dataclass(frozen=True)
class ReportRow:
    user: str
    arn: str
    mfa_active: bool
    keys: tuple[ReportKey, ...]


def fetch_credential_report(
    iam: Any,
    timeout_seconds: float = 60.0,
    poll_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, ReportRow]:
    """Return the report keyed by user name; the root account is keyed '<root_account>'."""
    return fetch_credential_report_with_time(iam, timeout_seconds, poll_seconds, sleep, clock)[0]


def fetch_credential_report_with_time(
    iam: Any,
    timeout_seconds: float = 60.0,
    poll_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, ReportRow], datetime | None]:
    """Like fetch_credential_report, and also returns when IAM generated the report. IAM reuses a
    report up to four hours old, so callers need this to say how fresh the root-key data is."""
    deadline = clock() + timeout_seconds
    iam.generate_credential_report()
    while True:
        try:
            response = iam.get_credential_report()
            return parse_report(response["Content"]), response.get("GeneratedTime")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NEEDS_GENERATING:
                iam.generate_credential_report()
            elif code not in _NOT_READY:
                raise
        if clock() >= deadline:
            raise CredentialReportTimeout(
                f"IAM credential report not ready after {timeout_seconds:.0f} seconds"
            )
        sleep(poll_seconds)


def parse_report(content: bytes | str) -> dict[str, ReportRow]:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    rows: dict[str, ReportRow] = {}
    for raw in csv.DictReader(io.StringIO(text)):
        user = raw["user"]
        keys = tuple(_parse_key(raw, slot) for slot in (1, 2))
        rows[user] = ReportRow(
            user=user,
            arn=raw.get("arn", ""),
            mfa_active=raw.get("mfa_active", "false").lower() == "true",
            keys=keys,
        )
    return rows


def _parse_key(raw: dict[str, str], slot: int) -> ReportKey:
    prefix = f"access_key_{slot}_"
    return ReportKey(
        slot=slot,
        active=raw.get(prefix + "active", "false").lower() == "true",
        last_rotated=_parse_time(raw.get(prefix + "last_rotated")),
        last_used=_parse_time(raw.get(prefix + "last_used_date")),
        last_used_region=_clean(raw.get(prefix + "last_used_region")),
    )


def _clean(value: str | None) -> str | None:
    return None if value is None or value in _ABSENT else value


def _parse_time(value: str | None) -> datetime | None:
    cleaned = _clean(value)
    return datetime.fromisoformat(cleaned) if cleaned else None
