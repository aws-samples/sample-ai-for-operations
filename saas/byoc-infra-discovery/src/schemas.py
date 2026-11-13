# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Pydantic schemas for Strands structured output.

The agent returns a typed FactsBundle (facts only, no verdict). Deterministic
code in the handler then computes the verdict/confidence and assembles the
final JSON contract, so the model never decides the verdict or confidence.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class AvailabilityZone(BaseModel):
    az_id: str
    az_name: Optional[str] = None


class GatheredFacts(BaseModel):
    """Raw infrastructure facts the agent collected via its tools.

    Every field must come from a tool result, never the model's own knowledge.
    This schema intentionally contains NO verdict and NO overall confidence —
    those are computed deterministically downstream.
    """

    query_mode: Literal["fact", "readiness"] = Field(
        description="fact for a single-dataset lookup, readiness for a deploy check"
    )

    # Target of a readiness query (optional for fact queries).
    region: Optional[str] = None
    region_long_name: Optional[str] = None
    instance_type: Optional[str] = None
    eks_version: Optional[str] = None
    eks_required: bool = Field(
        default=False, description="Whether the query concerns an EKS deployment"
    )

    # Collected facts (populated from tool results; None when not gathered).
    region_exists: Optional[bool] = None
    ec2_available: Optional[bool] = None
    eks_available: Optional[bool] = None
    availability_zones: list[AvailabilityZone] = Field(default_factory=list)
    az_names_available: bool = False
    ami_available: Optional[bool] = None
    instance_type_offered: Optional[bool] = None
    instance_type_offered_source: Optional[str] = Field(
        default=None,
        description='Source of the offering fact, e.g. "pricing-api" or "ec2-live"',
    )
    eks_ecr_registry: Optional[str] = None

    # Per-fact source confidences the agent observed (e.g. ["high","medium"]).
    source_confidences: list[str] = Field(default_factory=list)

    # For a fact-mode query: the dataset name and its raw result payload.
    fact_dataset: Optional[str] = None
    fact_source: Optional[str] = None
    fact_confidence: Optional[str] = None
