# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""All settings. This is the only module that reads the environment or ``~/.nfi.toml``.

Precedence: explicit overrides > environment variables > ``~/.nfi.toml`` > defaults.
Nothing here is a secret; credentials come from the standard AWS credential chain.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_TOML = Path.home() / ".nfi.toml"


@dataclass(frozen=True)
class Settings:
    # --- Region and model -------------------------------------------------------------------
    aws_region: str = "eu-west-2"
    bedrock_region: str = "eu-west-2"
    bedrock_model_id: str = "eu.anthropic.claude-sonnet-5"
    bedrock_max_tokens: int = 16384
    bedrock_temperature: float = (
        -1.0
    )  # negative: not sent (some models, for example Claude Sonnet 5, reject it)
    guardrail_id: str = ""
    guardrail_version: str = "DRAFT"
    allow_no_guardrail: bool = False  # local development only; logged

    # --- Flow logs ---------------------------------------------------------------------------
    flow_log_bucket: str = ""
    flow_log_prefix: str = "AWSLogs/"
    flow_log_database: str = "default"
    flow_log_table: str = ""
    athena_workgroup: str = "primary"
    athena_results_location: str = ""  # s3://bucket/prefix/ ; agent-managed bucket in hosted mode

    # --- Agent-managed resources -------------------------------------------------------------
    agent_database: str = "nfi_agent"
    report_bucket: str = ""
    reports_dir: str = "./reports"

    # --- Optional enrichments ----------------------------------------------------------------
    inventory_provider: str = "auto"  # auto | ec2 | config | file | none
    inventory_file: str = ""
    config_aggregator: str = ""
    cur_database: str = ""
    cur_table: str = ""
    cur_role_arn: str = ""
    cur_workgroup: str = ""
    resolver_database: str = ""
    resolver_table: str = ""
    resolver_role_arn: str = ""
    intent_file: str = ""
    ip_ranges_url: str = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    ip_ranges_cache_dir: str = ""
    ip_ranges_file: str = ""  # use a local copy instead of downloading (air-gapped, pinned or test ranges)

    # --- Cost gauge and thresholds -----------------------------------------------------------
    athena_price_per_tb: float = 0.0  # operator override when pricing:GetProducts is not permitted
    scan_ceiling_usd: float = 5.0  # per-query confirmation threshold
    session_budget_usd: float = 25.0  # hard stop for one session or report
    default_window_days: int = 7
    reconcile_tolerance: float = 0.05
    skipdata_threshold: float = 0.02
    # Flow records arrive in S3 minutes after capture. An aggregate is reused only if it was built this long
    # after the end of its last day; windows that have not settled get a versioned build that is never reused.
    aggregate_settle_minutes: int = 60
    idle_gateway_bytes: int = 1_000_000_000  # below this per window a NAT gateway is "near-idle"
    max_result_rows: int = 5000
    max_chat_limit: int = 1000
    # provider D thresholds
    forwarding_foreign_share: float = 0.30
    nat_dominant_share: float = 0.50

    # --- Run limits (one agent invocation: a scheduled run or one chat turn); 0 turns a limit off -----
    max_tool_calls: int = 60  # tool calls before the model is told to answer; see core/runbudget.py
    run_deadline_seconds: int = 780  # kept under the 880 s the scheduled-run Lambda waits
    # --- Operations --------------------------------------------------------------------------
    log_level: str = "INFO"
    ssm_prefix: str = ""
    agentcore_runtime_arn: str = ""
    extras: Mapping[str, Any] = field(default_factory=dict)

    def with_overrides(self, **kw: Any) -> Settings:
        known = {f.name for f in fields(self)}
        clean = {k: v for k, v in kw.items() if k in known and v is not None}
        return Settings(**{**{f.name: getattr(self, f.name) for f in fields(self)}, **clean})


# Environment variable -> Settings field. NFI_<FIELD> works for every field; these are the
# conventional names the framework uses for model and region.
_ALIASES = {
    "BEDROCK_MODEL_ID": "bedrock_model_id",
    "BEDROCK_REGION": "bedrock_region",
    "BEDROCK_MAX_TOKENS": "bedrock_max_tokens",
    "BEDROCK_TEMPERATURE": "bedrock_temperature",
    "GUARDRAIL_ID": "guardrail_id",
    "GUARDRAIL_VERSION": "guardrail_version",
    "AWS_REGION": "aws_region",
    "LOG_LEVEL": "log_level",
}


def _coerce(name: str, raw: Any) -> Any:
    target = {f.name: f.type for f in fields(Settings)}[name]
    if target in ("int", int):
        return int(raw)
    if target in ("float", float):
        return float(raw)
    if target in ("bool", bool):
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    return str(raw) if target in ("str", str) else raw


def load_settings(
    env: Mapping[str, str] | None = None,
    toml_path: Path | None = None,
    **overrides: Any,
) -> Settings:
    env = os.environ if env is None else env
    names = {f.name for f in fields(Settings)} - {"extras"}
    values: dict[str, Any] = {}

    path = toml_path if toml_path is not None else DEFAULT_TOML
    if path.is_file():
        with path.open("rb") as fh:
            for k, v in tomllib.load(fh).items():
                if k in names:
                    values[k] = _coerce(k, v)

    for env_key, field_name in _ALIASES.items():
        if env_key in env and env[env_key] != "":
            values[field_name] = _coerce(field_name, env[env_key])
    for name in names:
        key = f"NFI_{name.upper()}"
        if key in env and env[key] != "":
            values[name] = _coerce(name, env[key])

    for k, v in overrides.items():
        if k in names and v is not None:
            values[k] = _coerce(k, v)
    return Settings(**values)
