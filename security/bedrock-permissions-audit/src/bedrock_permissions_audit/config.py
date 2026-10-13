# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The only module that reads configuration files. Precedence: flag > TOML file > default."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime

# nosemgrep: python37-compatibility-importlib2 -- the package requires Python 3.12 or later
from importlib import resources
from pathlib import Path
from typing import Any

DEFAULT_INVOKE_ACTIONS = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
    "bedrock:CallWithBearerToken",
    "bedrock-mantle:CallWithBearerToken",
)
DEFAULT_ESCALATION_ACTIONS = (
    "aws-marketplace:Subscribe",
    "bedrock:CreateMarketplaceModelEndpoint",
    "iam:CreateServiceSpecificCredential",
)
# ALL of these allowed on "*" means the principal effectively holds bedrock:*, a cheap stand-in
# for simulating every Amazon Bedrock action. They are unrelated management actions on purpose:
# any one of them is granted by narrower managed policies (AmazonBedrockLimitedAccess lists
# explicit actions and allows DeleteCustomModel, DeleteGuardrail and
# CreateProvisionedModelThroughput), but a policy that also allows the logging, agent and
# knowledge-base actions below is for practical purposes bedrock:*.
DEFAULT_CANARY_ACTIONS = (
    "bedrock:DeleteCustomModel",
    "bedrock:PutModelInvocationLoggingConfiguration",
    "bedrock:DeleteGuardrail",
    "bedrock:CreateProvisionedModelThroughput",
    "bedrock:DeleteAgent",
    "bedrock:DeleteKnowledgeBase",
)
DEFAULT_ADMIN_POLICY_ARNS = (
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
)
VALID_MODES = ("auto", "org", "single")
# The read-only role that infra/audit-role.yaml creates. An administrator role is never the default.
DEFAULT_ROLE_NAME = "BedrockPermissionsAuditRole"


class ConfigError(ValueError):
    """Raised for any invalid configuration. The CLI maps this to exit code 2."""


@dataclass(frozen=True)
class Config:
    mode: str = "auto"
    role_name: str = DEFAULT_ROLE_NAME
    external_id: str | None = None
    dormant_days: int = 90
    invoke_actions: tuple[str, ...] = DEFAULT_INVOKE_ACTIONS
    escalation_actions: tuple[str, ...] = DEFAULT_ESCALATION_ACTIONS
    canary_actions: tuple[str, ...] = DEFAULT_CANARY_ACTIONS
    admin_policy_arns: tuple[str, ...] = DEFAULT_ADMIN_POLICY_ARNS
    bedrock_regions: tuple[str, ...] = ()  # empty = use the bundled list
    representative_models: tuple[str, ...] = ()  # empty = use the bundled list
    approved_models: tuple[str, ...] = ()
    scp_exception_principals: tuple[str, ...] = ()
    parallel_accounts: int = 8
    output_dir: Path | None = None  # None = ./bedrock-audit-<UTC timestamp>/
    show_all: bool = False
    unmask: bool = False
    resume: bool = False
    no_color: bool = False
    log_level: str = "INFO"

    @property
    def all_actions(self) -> tuple[str, ...]:
        """Every action the evaluator simulates, de-duplicated, order preserved."""
        return tuple(
            dict.fromkeys(self.invoke_actions + self.escalation_actions + self.canary_actions)
        )


# TOML file layout -> Config field. Flat keys map to themselves; the [actions] table is flattened.
_TOML_ACTIONS_KEYS = {
    "invoke": "invoke_actions",
    "escalation": "escalation_actions",
    "canary": "canary_actions",
}
_TUPLE_FIELDS = {
    "invoke_actions",
    "escalation_actions",
    "canary_actions",
    "admin_policy_arns",
    "bedrock_regions",
    "representative_models",
    "approved_models",
    "scp_exception_principals",
}
_FIELD_NAMES = {f.name for f in fields(Config)}
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def load_config(path: Path | None = None, overrides: Mapping[str, Any] | None = None) -> Config:
    """Build a Config. `overrides` holds explicitly supplied flags; None values are ignored."""
    values: dict[str, Any] = {}
    if path is not None:
        values.update(_read_toml(path))
    for key, value in (overrides or {}).items():
        if value is not None:
            values[key] = value
    unknown = set(values) - _FIELD_NAMES
    if unknown:
        raise ConfigError(f"Unknown configuration key(s): {', '.join(sorted(unknown))}")
    return _validate(Config(**{k: _coerce(k, v) for k, v in values.items()}))


def resolve_output_dir(config: Config, now: datetime | None = None) -> Path:
    if config.output_dir is not None:
        return config.output_dir
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return Path(f"bedrock-audit-{stamp}")


def bundled_region_data() -> dict[str, Any]:
    text = (
        resources.files("bedrock_permissions_audit")
        .joinpath("data/bedrock_regions.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(text)


def effective_regions(config: Config) -> tuple[str, ...]:
    return config.bedrock_regions or tuple(bundled_region_data()["regions"])


def effective_models(config: Config) -> tuple[str, ...]:
    return config.representative_models or tuple(bundled_region_data()["representative_models"])


def with_overrides(config: Config, **changes: Any) -> Config:
    return _validate(replace(config, **changes))


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid TOML: {exc}") from exc

    values: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "actions":
            if not isinstance(value, dict):
                raise ConfigError("[actions] must be a table")
            for sub_key, sub_value in value.items():
                if sub_key not in _TOML_ACTIONS_KEYS:
                    raise ConfigError(f"Unknown key in [actions]: {sub_key}")
                values[_TOML_ACTIONS_KEYS[sub_key]] = sub_value
        else:
            values[key] = value
    return values


def _coerce(key: str, value: Any) -> Any:
    if key in _TUPLE_FIELDS:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (list, tuple)):
            return tuple(str(item) for item in value)
        raise ConfigError(f"{key} must be a list of strings")
    if key == "output_dir":
        return Path(value)
    if key in ("dormant_days", "parallel_accounts"):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{key} must be an integer")
    if key in ("show_all", "unmask", "resume", "no_color") and not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _validate(config: Config) -> Config:
    if config.mode not in VALID_MODES:
        raise ConfigError(f"mode must be one of {', '.join(VALID_MODES)}")
    if config.dormant_days < 1:
        raise ConfigError("dormant_days must be at least 1")
    if not 1 <= config.parallel_accounts <= 64:
        raise ConfigError("parallel_accounts must be between 1 and 64")
    if not config.role_name:
        raise ConfigError("role_name must not be empty")
    if not config.invoke_actions:
        raise ConfigError("actions.invoke must contain at least one action")
    if config.log_level.upper() not in _LOG_LEVELS:
        raise ConfigError(f"log_level must be one of {', '.join(_LOG_LEVELS)}")
    for action in config.all_actions:
        if ":" not in action or action.startswith(":") or action.endswith(":"):
            raise ConfigError(f"Invalid IAM action name: {action!r}")
    return config
