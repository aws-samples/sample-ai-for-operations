# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Runtime configuration. The ONLY module in this project that reads os.environ.

Deploy-time-only parameters (ScheduleExpression, ScheduleTimezone) are not read here:
they are consumed by EventBridge Scheduler and validated in infra (tasks.md 1.4).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field


class ConfigError(ValueError):
    """Raised when a configuration value is present but malformed."""


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _int(env: Mapping[str, str], key: str, default: int, minimum: int = 0) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{key} must be >= {minimum}, got {value}")
    return value


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number, got {raw!r}") from exc
    if not 0 < value <= 100:
        raise ConfigError(f"{key} must be in (0, 100], got {value}")
    return value


def _overrides(env: Mapping[str, str], key: str) -> dict[str, float]:
    raw = env.get(key, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{key} must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ConfigError(f"{key} must be a JSON object")
    result: dict[str, float] = {}
    for name, pct in parsed.items():
        if not isinstance(pct, (int, float)) or not 0 < pct <= 100:
            raise ConfigError(f"{key}[{name!r}] must be a number in (0, 100]")
        result[str(name)] = float(pct)
    return result


def _account_id(env: Mapping[str, str], key: str) -> str:
    raw = env.get(key, "").strip()
    if raw and not (len(raw) == 12 and raw.isdigit()):
        raise ConfigError(f"{key} must be a 12-digit AWS account ID, got {raw!r}")
    return raw


@dataclass(frozen=True)
class Settings:
    """All runtime settings, parsed once. Handlers pass these into drift_core explicitly."""

    bucket_name: str = ""
    table_name: str = ""
    intent_object_key: str = "intent/routing-intent.yaml"
    environment_tag_key: str = "Environment"
    production_tag_values: tuple[str, ...] = ("prod", "production")
    limit_threshold_percent: float = 80.0
    limit_threshold_overrides: dict[str, float] = field(default_factory=dict)
    region_allowlist: tuple[str, ...] = ()
    region_exclude_list: tuple[str, ...] = ()
    region_concurrency: int = 4
    log_level: str = "INFO"
    # DevOps Agent hand-off (Phase 3). Empty unless EnableDevOpsAgentHandoff=true.
    handoff_enabled: bool = False
    webhook_url: str = ""
    webhook_secret_parameter_name: str = ""
    devops_agent_space_id: str = ""
    # Empty = the Agent Space lives in this account. Otherwise the callback assumes the
    # journal-reader role in that account (design.md D§3.3a).
    devops_agent_account_id: str = ""
    max_findings_per_investigation: int = 25
    investigation_description_max_bytes: int = 12 * 1024
    investigation_timeout_seconds: int = 2700
    webhook_timeout_seconds: int = 10

    def require(self, name: str) -> str:
        """Return a string setting that must be set at runtime (e.g. bucket name)."""
        value = getattr(self, name)
        if not value:
            raise ConfigError(f"required setting {name} is not configured")
        return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Parse settings from an environment mapping (defaults to os.environ)."""
    env = os.environ if env is None else env
    return Settings(
        bucket_name=env.get("BUCKET_NAME", "").strip(),
        table_name=env.get("TABLE_NAME", "").strip(),
        intent_object_key=env.get("INTENT_OBJECT_KEY", "").strip() or "intent/routing-intent.yaml",
        environment_tag_key=env.get("ENVIRONMENT_TAG_KEY", "").strip() or "Environment",
        production_tag_values=_csv(env.get("PRODUCTION_TAG_VALUES", "")) or ("prod", "production"),
        limit_threshold_percent=_float(env, "LIMIT_THRESHOLD_PERCENT", 80.0),
        limit_threshold_overrides=_overrides(env, "LIMIT_THRESHOLD_OVERRIDES"),
        region_allowlist=_csv(env.get("REGION_ALLOWLIST", "")),
        region_exclude_list=_csv(env.get("REGION_EXCLUDE_LIST", "")),
        region_concurrency=_int(env, "REGION_CONCURRENCY", 4, minimum=1),
        log_level=(env.get("LOG_LEVEL", "").strip() or "INFO").upper(),
        handoff_enabled=env.get("ENABLE_DEVOPS_AGENT_HANDOFF", "").strip().lower() == "true",
        webhook_url=env.get("DEVOPS_AGENT_WEBHOOK_URL", "").strip(),
        webhook_secret_parameter_name=env.get("WEBHOOK_SECRET_PARAMETER_NAME", "").strip(),
        devops_agent_space_id=env.get("DEVOPS_AGENT_SPACE_ID", "").strip(),
        devops_agent_account_id=_account_id(env, "DEVOPS_AGENT_ACCOUNT_ID"),
        max_findings_per_investigation=_int(env, "MAX_FINDINGS_PER_INVESTIGATION", 25, minimum=1),
        investigation_description_max_bytes=_int(env, "INVESTIGATION_DESCRIPTION_MAX_BYTES", 12 * 1024,
                                                 minimum=2048),
        investigation_timeout_seconds=_int(env, "INVESTIGATION_TIMEOUT_SECONDS", 2700, minimum=60),
        webhook_timeout_seconds=_int(env, "WEBHOOK_TIMEOUT_SECONDS", 10, minimum=1),
    )
