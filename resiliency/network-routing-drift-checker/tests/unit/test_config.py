# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""config.py defaults, parsing, and the single-reader rule (tasks.md 1.2)."""

import pathlib
import re

import pytest

from config import ConfigError, load_settings

SRC = pathlib.Path(__file__).resolve().parents[2] / "src"


def test_defaults():
    s = load_settings({})
    assert s.intent_object_key == "intent/routing-intent.yaml"
    assert s.environment_tag_key == "Environment"
    assert s.production_tag_values == ("prod", "production")
    assert s.limit_threshold_percent == 80.0
    assert s.region_concurrency == 4
    assert s.handoff_enabled is False
    assert s.region_allowlist == ()


def test_parsing():
    s = load_settings(
        {
            "BUCKET_NAME": "b",
            "REGION_ALLOWLIST": "eu-central-1, eu-west-1,",
            "PRODUCTION_TAG_VALUES": "PROD,live",
            "LIMIT_THRESHOLD_PERCENT": "75",
            "LIMIT_THRESHOLD_OVERRIDES": '{"tgw-total-routes": 90}',
            "REGION_CONCURRENCY": "2",
            "ENABLE_DEVOPS_AGENT_HANDOFF": "True",
            "log_level": "ignored",
            "LOG_LEVEL": "debug",
        }
    )
    assert s.region_allowlist == ("eu-central-1", "eu-west-1")
    assert s.production_tag_values == ("PROD", "live")
    assert s.limit_threshold_percent == 75.0
    assert s.limit_threshold_overrides == {"tgw-total-routes": 90.0}
    assert s.region_concurrency == 2
    assert s.handoff_enabled is True
    assert s.log_level == "DEBUG"
    assert s.require("bucket_name") == "b"


@pytest.mark.parametrize(
    "env",
    [
        {"REGION_CONCURRENCY": "zero"},
        {"REGION_CONCURRENCY": "0"},
        {"LIMIT_THRESHOLD_PERCENT": "120"},
        {"LIMIT_THRESHOLD_PERCENT": "abc"},
        {"LIMIT_THRESHOLD_OVERRIDES": "[1]"},
        {"LIMIT_THRESHOLD_OVERRIDES": "{bad"},
        {"LIMIT_THRESHOLD_OVERRIDES": '{"x": 0}'},
    ],
)
def test_malformed_values_raise(env):
    with pytest.raises(ConfigError):
        load_settings(env)


def test_require_missing_raises():
    with pytest.raises(ConfigError):
        load_settings({}).require("table_name")


def test_config_is_only_environ_reader():
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if p.name != "config.py" and re.search(r"os\.environ|os\.getenv", p.read_text())
    ]
    assert offenders == []
