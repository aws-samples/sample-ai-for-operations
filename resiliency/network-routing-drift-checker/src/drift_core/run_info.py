# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Run identity and execution-input overrides (requirements §9.2, design.md D§3.1)."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from typing import Any

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


class InputError(ValueError):
    """The execution input is malformed; the run fails before touching anything."""


def _iso(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"not an ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise InputError(f"timestamp must include a timezone: {value!r}")
    return parsed.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class RunInfo:
    run_id: str
    started_at: str
    override_regions: tuple[str, ...] | None
    override_lookback_from: str | None

    @property
    def scope(self) -> str:
        """'full' only when no override touched Regions or lookback (requirements §9.2)."""
        return "partial" if (self.override_regions or self.override_lookback_from) else "full"

    @property
    def date(self) -> str:
        return self.started_at[:10]

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> RunInfo:
        """Event from the state machine: {execution_name, started_at, input: <execution input>}."""
        if not isinstance(event, dict):
            raise InputError("event must be an object")
        started_at = _iso(str(event.get("started_at") or ""))
        name = str(event.get("execution_name") or "")
        if not name:
            raise InputError("execution_name is required")
        run_id = f"{started_at}-{hashlib.sha256(name.encode()).hexdigest()[:8]}"
        overrides = event.get("input") or {}
        if not isinstance(overrides, dict):
            raise InputError("execution input must be an object")
        unknown = set(overrides) - {"regions", "lookback_from"}
        if unknown:
            raise InputError(f"unknown execution input keys: {sorted(unknown)}")
        regions = overrides.get("regions")
        if regions is not None:
            if not isinstance(regions, list) or not regions or not all(
                    isinstance(r, str) and REGION_RE.match(r) for r in regions):
                raise InputError("regions must be a non-empty list of Region codes, e.g. [\"eu-central-1\"]")
            regions = tuple(sorted(set(regions)))
        lookback = overrides.get("lookback_from")
        return cls(run_id=run_id, started_at=started_at, override_regions=regions,
                   override_lookback_from=_iso(str(lookback)) if lookback else None)


def default_lookback(started_at: str) -> str:
    """First run (no marker): look back 24 hours."""
    start = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    return (start - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
