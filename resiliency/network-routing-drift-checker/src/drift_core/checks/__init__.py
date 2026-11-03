# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The six deterministic drift checks. Each is a pure function (EvaluationContext) -> list[Finding]."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvaluationContext:
    """Everything a check may read. No clients, no clock."""

    cloudwan: dict[str, Any] | None
    regions: dict[str, dict[str, Any]]  # region -> RegionSnapshot (evaluated Regions only)
    intent: dict[str, Any] | None = None  # validated intent model, or None when absent/rejected
    regions_not_evaluated: frozenset[str] = frozenset()  # "not found" is unverifiable while this is non-empty
    environment_tag_key: str = "Environment"
    limit_threshold_percent: float = 80.0
    limit_threshold_overrides: dict[str, float] = field(default_factory=dict)
