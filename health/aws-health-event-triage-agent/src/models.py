# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Data models for the AWS Health Event Triage Agent."""

from __future__ import annotations

from typing import Literal, Optional, TypedDict


class AccountContext(TypedDict):
    """Account context enrichment from AWS Organizations."""

    account_id: str
    account_name: str
    ou_path: str
    tags: dict[str, str]
    environment_type: Literal["production", "non-production", "unknown"]


class AffectedAccountDetail(TypedDict):
    """Account-level detail within a consolidated view or classification result."""

    account_id: str
    account_name: str
    environment_type: Literal["production", "non-production", "unknown"]
    affected_resources: list[str]


class EnvironmentBreakdown(TypedDict):
    """Production / non-production count breakdown."""

    production_count: int
    non_production_count: int


class ConsolidatedView(TypedDict):
    """Unified representation grouping related notifications across accounts."""

    event_key: str
    event_arns: list[str]
    service: str
    eventTypeCode: str
    eventDescription: str
    affected_accounts: list[AffectedAccountDetail]
    environment_breakdown: EnvironmentBreakdown
    org_impact_summary: str


class ImpactAccountDetail(TypedDict):
    """Per-account impact detail with required action."""

    account_id: str
    environment_type: Literal["production", "non-production", "unknown"]
    affected_resources: list[str]
    required_action: str


class ImpactAnalysis(TypedDict):
    """Result of breaking-change impact analysis."""

    notification_id: str
    action_required: bool
    risk_level: Literal["high", "medium", "low"]
    affected_accounts: list[ImpactAccountDetail]
    summary: str


class PerAccountCost(TypedDict):
    """Projected cost for a single account."""

    account_id: str
    projected_cost: Optional[float]
    currency: str


class CostProjection(TypedDict):
    """Result of cost estimation for a COST_IMPLICATION notification."""

    notification_id: str
    projectable: bool
    per_account_costs: list[PerAccountCost]
    org_total_projected_cost: Optional[float]
    currency: str
    reason: Optional[str]
    historical_reference: Optional[str]


class ClassificationResult(TypedDict):
    """Single classified notification in the agent output."""

    notification_id: str
    classification: Literal["BREAKING_CHANGE", "COST_IMPLICATION", "SECURITY_RELATED"]
    reason: str
    event_type: str
    affected_service: str
    affected_accounts: list[AffectedAccountDetail]
    environment_breakdown: EnvironmentBreakdown
    impact_analysis: Optional[ImpactAnalysis]
    cost_projection: Optional[CostProjection]


class SNSPayload(TypedDict):
    """Structured payload published to the SNS topic."""

    notification_id: str
    event_type: str
    affected_service: str
    classification: Literal["BREAKING_CHANGE", "COST_IMPLICATION", "SECURITY_RELATED"]
    reason: str
    affected_accounts: list[AffectedAccountDetail]
    impact_analysis: Optional[ImpactAnalysis]
    cost_projection: Optional[CostProjection]
