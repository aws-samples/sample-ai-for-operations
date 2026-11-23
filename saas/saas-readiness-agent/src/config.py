# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Centralized runtime configuration for local and published profiles."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

SessionProfile = Literal["v1", "v2"]

DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-5"
DEFAULT_REGION = "us-east-1"
DEFAULT_SESSION_PATH = "sessions/session.json"

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$")

DEFAULT_MAX_INPUT_JSON_BYTES = 262_144
DEFAULT_BEDROCK_MAX_TOKENS = 4096
DEFAULT_AWS_MAX_ATTEMPTS = 5
DEFAULT_AWS_RETRY_MODE = "adaptive"
_AWS_RETRY_MODES = {"legacy", "standard", "adaptive"}
DEFAULT_LOG_LEVEL = "INFO"
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
DEFAULT_DOCUMENTS_DIR = "documents"
DEFAULT_REPORTS_DIR = "reports"


class ConfigurationError(ValueError):
    """Raised when a selected runtime profile is incomplete or unsafe."""


@dataclass(frozen=True)
class RuntimeLimits:
    """Cost and resilience limits shared by every entrypoint.

    Kept separate from AppSettings so library code (agent tools, discovery)
    can read them without needing a fully valid v1/v2 session profile.
    """

    max_input_json_bytes: int = DEFAULT_MAX_INPUT_JSON_BYTES
    bedrock_max_tokens: int = DEFAULT_BEDROCK_MAX_TOKENS
    aws_max_attempts: int = DEFAULT_AWS_MAX_ATTEMPTS
    aws_retry_mode: str = DEFAULT_AWS_RETRY_MODE


def _positive_int(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive integer.") from exc
    if parsed < 1:
        raise ConfigurationError(f"{name} must be a positive integer.")
    return parsed


def load_bedrock_model(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """Return (BEDROCK_MODEL_ID, BEDROCK_REGION) without validating a session profile.

    Used by code paths that only need the model, such as the deterministic
    CLI's optional --explain bedrock narrative.
    """
    values = env if env is not None else os.environ
    model_id = (values.get("BEDROCK_MODEL_ID") or DEFAULT_MODEL_ID).strip()
    region = (values.get("BEDROCK_REGION") or DEFAULT_REGION).strip()
    return model_id, region


def load_documents_dir(env: Mapping[str, str] | None = None) -> str:
    """Return DOCUMENTS_DIR: the only directory the document reader may read from."""
    values = env if env is not None else os.environ
    value = (values.get("DOCUMENTS_DIR") or DEFAULT_DOCUMENTS_DIR).strip()
    if not value:
        raise ConfigurationError("DOCUMENTS_DIR cannot be empty.")
    return value


def load_reports_dir(env: Mapping[str, str] | None = None) -> str:
    """Return REPORTS_DIR: the only directory the report-writing tools may write to."""
    values = env if env is not None else os.environ
    value = (values.get("REPORTS_DIR") or DEFAULT_REPORTS_DIR).strip()
    if not value:
        raise ConfigurationError("REPORTS_DIR cannot be empty.")
    return value


def load_log_level(env: Mapping[str, str] | None = None) -> str:
    """Return the validated LOG_LEVEL (default INFO)."""
    values = env if env is not None else os.environ
    level = (values.get("LOG_LEVEL") or DEFAULT_LOG_LEVEL).upper()
    if level not in _LOG_LEVELS:
        raise ConfigurationError(
            "LOG_LEVEL must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        )
    return level


def load_limits(env: Mapping[str, str] | None = None) -> RuntimeLimits:
    """Load input-size, token, and AWS retry limits from the environment."""
    values = env if env is not None else os.environ
    retry_mode = values.get("AWS_DISCOVERY_RETRY_MODE") or DEFAULT_AWS_RETRY_MODE
    if retry_mode not in _AWS_RETRY_MODES:
        raise ConfigurationError(
            "AWS_DISCOVERY_RETRY_MODE must be one of: legacy, standard, adaptive."
        )
    return RuntimeLimits(
        max_input_json_bytes=_positive_int(
            values, "MAX_INPUT_JSON_BYTES", DEFAULT_MAX_INPUT_JSON_BYTES
        ),
        bedrock_max_tokens=_positive_int(
            values, "BEDROCK_MAX_TOKENS", DEFAULT_BEDROCK_MAX_TOKENS
        ),
        aws_max_attempts=_positive_int(
            values, "AWS_DISCOVERY_MAX_ATTEMPTS", DEFAULT_AWS_MAX_ATTEMPTS
        ),
        aws_retry_mode=retry_mode,
    )


@dataclass(frozen=True)
class AppSettings:
    """Validated settings shared by the CLI and Strands entrypoints."""

    session_profile: SessionProfile = "v1"
    session_path: str = DEFAULT_SESSION_PATH
    model_id: str = DEFAULT_MODEL_ID
    model_region: str = DEFAULT_REGION
    bedrock_guardrail_id: str | None = None
    bedrock_guardrail_version: str | None = None
    agentcore_region: str = DEFAULT_REGION
    agentcore_memory_id: str | None = None
    assessment_id: str = "local-assessment"
    contributor_id: str = "local-user"
    knowledge_base_id: str | None = None

    @property
    def memory_actor_id(self) -> str:
        """Return the shared actor partition for one assessment."""

        return f"saas-readiness-assessment-{self.assessment_id}"

    @property
    def memory_session_id(self) -> str:
        """Return the shared workflow session used by every assessment persona."""

        return f"saas-readiness-workflow-{self.assessment_id}"

    def validate(self) -> AppSettings:
        """Validate profile-specific values before constructing clients."""

        if self.session_profile not in {"v1", "v2"}:
            raise ConfigurationError("SESSION_PROFILE must be either 'v1' or 'v2'.")
        if bool(self.bedrock_guardrail_id) != bool(self.bedrock_guardrail_version):
            raise ConfigurationError(
                "BEDROCK_GUARDRAIL_ID and BEDROCK_GUARDRAIL_VERSION must be set together."
            )

        if self.session_profile == "v1":
            if not self.session_path.strip():
                raise ConfigurationError("SESSION_PATH cannot be empty for profile v1.")
            return self

        missing = [
            name
            for name, value in (
                ("AGENTCORE_MEMORY_ID", self.agentcore_memory_id),
                ("ASSESSMENT_ID", self.assessment_id),
                ("CONTRIBUTOR_ID", self.contributor_id),
            )
            if not value or not str(value).strip()
        ]
        if missing:
            raise ConfigurationError(
                f"Profile v2 requires: {', '.join(missing)}."
            )

        # Identifiers become AgentCore partition keys and log context. Restrict
        # them to pseudonymous, path-safe values rather than accepting PII.
        for name, value in (
            ("ASSESSMENT_ID", self.assessment_id),
            ("CONTRIBUTOR_ID", self.contributor_id),
        ):
            if not _SAFE_IDENTIFIER.fullmatch(value):
                raise ConfigurationError(
                    f"{name} must be 3-128 letters, numbers, hyphens, or underscores."
                )
        return self


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    profile_override: str | None = None,
    session_path_override: str | None = None,
    assessment_id_override: str | None = None,
    contributor_id_override: str | None = None,
) -> AppSettings:
    """Load settings once from an injectable environment mapping."""

    values = env if env is not None else os.environ
    profile = profile_override or values.get("SESSION_PROFILE", "v1")
    if profile not in {"v1", "v2"}:
        raise ConfigurationError("SESSION_PROFILE must be either 'v1' or 'v2'.")

    settings = AppSettings(
        session_profile=cast(SessionProfile, profile),
        session_path=(
            session_path_override
            or values.get("SESSION_PATH")
            or DEFAULT_SESSION_PATH
        ),
        model_id=values.get("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID),
        model_region=values.get("BEDROCK_REGION", DEFAULT_REGION),
        bedrock_guardrail_id=values.get("BEDROCK_GUARDRAIL_ID"),
        bedrock_guardrail_version=values.get("BEDROCK_GUARDRAIL_VERSION"),
        agentcore_region=values.get(
            "AGENTCORE_REGION", values.get("BEDROCK_REGION", DEFAULT_REGION)
        ),
        agentcore_memory_id=values.get("AGENTCORE_MEMORY_ID"),
        assessment_id=(
            assessment_id_override
            or values.get("ASSESSMENT_ID")
            or ("local-assessment" if profile == "v1" else "")
        ),
        contributor_id=(
            contributor_id_override
            or values.get("CONTRIBUTOR_ID")
            or ("local-user" if profile == "v1" else "")
        ),
        knowledge_base_id=values.get("KNOWLEDGE_BASE_ID"),
    )
    return settings.validate()
