# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Centralized configuration for the byoc-infra-discovery agent.

All environment-configurable values live here. No other module reads
``os.environ`` directly (per the no-hard-coding standard).
"""

import os

# --- Bedrock model ---
# Current Claude models on Amazon Bedrock are invoked via a region-prefixed
# inference profile (e.g. "us.anthropic.claude-..."), not the bare on-demand id.
BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
)
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-east-1")
BEDROCK_MAX_TOKENS = int(os.environ.get("BEDROCK_MAX_TOKENS", "4096"))
# Low temperature: this is a factual/deterministic-reasoning task, not creative.
BEDROCK_TEMPERATURE = float(os.environ.get("BEDROCK_TEMPERATURE", "0.2"))

# --- Bedrock Guardrails ---
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION")

# --- Account-independent source endpoints ---
# SSM global-infrastructure parameters and the Pricing API are reachable from a
# single global endpoint (us-east-1) and work for regions NOT enabled in the
# caller's account. This is the backbone of BYOC non-enabled-region support.
GLOBAL_SOURCE_REGION = os.environ.get("GLOBAL_SOURCE_REGION", "us-east-1")
PRICING_REGION = os.environ.get("PRICING_REGION", "us-east-1")

# --- Caching (in-memory + /tmp only; no paid store) ---
# nosec B108: /tmp is the only writable path in the AWS Lambda runtime and the
# cache is intentionally the ephemeral per-execution-environment directory.
# The location is overridable via CACHE_TMP_DIR; this is the documented default,
# not an insecure hardcoded temp path.
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "3600"))
CACHE_TMP_DIR = os.environ.get("CACHE_TMP_DIR", "/tmp/byoc-cache")  # nosec B108

# --- Observability ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# --- Timeouts for live/regional AWS calls (seconds) ---
# Kept short so an unreachable regional endpoint (e.g. the documented me-south-1
# case) fails fast and falls back to the account-independent source.
LIVE_CALL_CONNECT_TIMEOUT = float(os.environ.get("LIVE_CALL_CONNECT_TIMEOUT", "3"))
LIVE_CALL_READ_TIMEOUT = float(os.environ.get("LIVE_CALL_READ_TIMEOUT", "5"))
LIVE_CALL_MAX_ATTEMPTS = int(os.environ.get("LIVE_CALL_MAX_ATTEMPTS", "2"))
