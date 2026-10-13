# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bedrock_permissions_audit.config import (
    DEFAULT_INVOKE_ACTIONS,
    Config,
    ConfigError,
    effective_models,
    effective_regions,
    load_config,
    resolve_output_dir,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def write_toml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "audit.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_match_the_design():
    config = load_config()
    assert config.mode == "auto"
    assert config.role_name == "BedrockPermissionsAuditRole"
    assert config.dormant_days == 90
    assert config.parallel_accounts == 8
    assert config.invoke_actions == DEFAULT_INVOKE_ACTIONS
    assert "aws-marketplace:Subscribe" in config.escalation_actions
    assert "iam:CreateServiceSpecificCredential" in config.escalation_actions
    assert config.show_all is False
    assert config.unmask is False


def test_file_overrides_default(tmp_path):
    path = write_toml(tmp_path, 'dormant_days = 30\nrole_name = "AuditRole"\n')
    config = load_config(path)
    assert config.dormant_days == 30
    assert config.role_name == "AuditRole"


def test_flag_overrides_file(tmp_path):
    path = write_toml(tmp_path, "dormant_days = 30\n")
    config = load_config(path, {"dormant_days": 45})
    assert config.dormant_days == 45


def test_none_flag_does_not_override_file(tmp_path):
    path = write_toml(tmp_path, "dormant_days = 30\n")
    config = load_config(path, {"dormant_days": None})
    assert config.dormant_days == 30


def test_actions_table_is_flattened(tmp_path):
    path = write_toml(tmp_path, '[actions]\ninvoke = ["bedrock:InvokeModel"]\ncanary = []\n')
    config = load_config(path)
    assert config.invoke_actions == ("bedrock:InvokeModel",)
    assert config.canary_actions == ()
    assert config.all_actions[0] == "bedrock:InvokeModel"


def test_comma_separated_flag_value_becomes_tuple():
    config = load_config(overrides={"bedrock_regions": "us-east-1, eu-west-1"})
    assert config.bedrock_regions == ("us-east-1", "eu-west-1")


def test_all_actions_is_deduplicated_and_ordered():
    config = Config(
        invoke_actions=("a:One", "a:Two"),
        escalation_actions=("a:Two", "b:Three"),
        canary_actions=("c:Four",),
    )
    assert config.all_actions == ("a:One", "a:Two", "b:Three", "c:Four")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"mode": "everything"}, "mode must be one of"),
        ({"dormant_days": 0}, "dormant_days"),
        ({"dormant_days": "ninety"}, "must be an integer"),
        ({"dormant_days": True}, "must be an integer"),
        ({"parallel_accounts": 0}, "parallel_accounts"),
        ({"parallel_accounts": 65}, "parallel_accounts"),
        ({"role_name": ""}, "role_name"),
        ({"invoke_actions": []}, "at least one action"),
        ({"invoke_actions": ["not-an-action"]}, "Invalid IAM action"),
        ({"log_level": "LOUD"}, "log_level"),
        ({"show_all": "yes"}, "true or false"),
        ({"no_such_key": 1}, "Unknown configuration key"),
    ],
)
def test_invalid_values_are_rejected(overrides, message):
    with pytest.raises(ConfigError, match=message):
        load_config(overrides=overrides)


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_malformed_toml_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(write_toml(tmp_path, "this is = = not toml"))


def test_unknown_key_in_actions_table_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match=r"\[actions\]"):
        load_config(write_toml(tmp_path, '[actions]\nbogus = ["a:B"]\n'))


def test_example_config_loads_and_equals_defaults():
    """The shipped example documents the defaults, so it must not drift from them."""
    example = load_config(REPO_ROOT / "config" / "audit.example.toml")
    assert example == Config()


def test_output_dir_default_is_timestamped():
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    assert resolve_output_dir(Config(), now) == Path("bedrock-audit-20260304T050607Z")


def test_output_dir_explicit_wins():
    assert resolve_output_dir(Config(output_dir=Path("out"))) == Path("out")


def test_bundled_regions_and_models_are_used_when_not_overridden():
    config = Config()
    regions = effective_regions(config)
    assert "us-east-1" in regions
    assert len(regions) == len(set(regions))
    assert all(r.count("-") == 2 for r in regions)
    assert len(effective_models(config)) >= 3


def test_region_override_replaces_bundled_list():
    assert effective_regions(Config(bedrock_regions=("eu-west-1",))) == ("eu-west-1",)
