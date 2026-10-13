# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision stage: tier, order and recommendation, all pure functions."""

from __future__ import annotations

from dataclasses import replace

from ..config import Config
from ..models import Finding
from . import recommendations, tiers


def score(finding: Finding, config: Config) -> Finding:
    """Return the finding with tier, reasons and recommended action filled in."""
    result = tiers.assign(finding, config)
    scored = replace(
        finding,
        tier=result.tier,
        tier_reasons=result.reasons,
        if_reactivated_tier=result.if_reactivated,
    )
    return replace(scored, recommended_action=recommendations.for_finding(scored, config))
