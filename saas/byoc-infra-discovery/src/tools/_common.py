# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Shared helpers for data-retrieval tools.

Provides boto3 client construction with fast-fail timeouts (so an unreachable
regional endpoint falls back quickly to the account-independent source) and
the canonical source / confidence label constants.
"""

from typing import Optional

import boto3
from botocore.config import Config

from config import (
    GLOBAL_SOURCE_REGION,
    LIVE_CALL_CONNECT_TIMEOUT,
    LIVE_CALL_MAX_ATTEMPTS,
    LIVE_CALL_READ_TIMEOUT,
    PRICING_REGION,
)

# --- Source labels (reported to the caller so they can judge authority) ---
SOURCE_SSM_GLOBAL = "ssm-global-infrastructure"
SOURCE_PRICING = "pricing-api"
SOURCE_EC2_LIVE = "ec2-live"
SOURCE_SSM_PUBLIC_PARAM = "ssm-public-parameter"
SOURCE_CURATED = "curated"

# --- Confidence labels ---
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

_LIVE_CONFIG = Config(
    connect_timeout=LIVE_CALL_CONNECT_TIMEOUT,
    read_timeout=LIVE_CALL_READ_TIMEOUT,
    retries={"max_attempts": LIVE_CALL_MAX_ATTEMPTS, "mode": "standard"},
)


def ssm_global_client():
    """SSM client pinned to the global source region (us-east-1).

    The /aws/service/global-infrastructure/* parameters are account-independent
    and readable here for regions NOT enabled in the caller's account.
    """
    return boto3.client("ssm", region_name=GLOBAL_SOURCE_REGION, config=_LIVE_CONFIG)


def pricing_client():
    """AWS Price List API client (account-independent, region-global)."""
    return boto3.client("pricing", region_name=PRICING_REGION, config=_LIVE_CONFIG)


def ec2_client(region: str):
    """EC2 client for a specific region (live calls; only works when enabled)."""
    return boto3.client("ec2", region_name=region, config=_LIVE_CONFIG)


def ssm_regional_client(region: str):
    """SSM client for a specific region (regional public params / AMIs)."""
    return boto3.client("ssm", region_name=region, config=_LIVE_CONFIG)


def require_region(region: Optional[str]) -> str:
    """Validate a region argument from an external caller.

    Returns the stripped region string, or raises ValueError for malformed
    input (handled by the tool wrapper into a structured error).
    """
    if not isinstance(region, str) or not region.strip():
        raise ValueError("region must be a non-empty string")
    return region.strip()
