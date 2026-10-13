# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from dataclasses import fields
from pathlib import Path

import pytest

from bedrock_permissions_audit import cli
from bedrock_permissions_audit.accounts import DiscoveryError
from bedrock_permissions_audit.checkpoint import CheckpointError
from bedrock_permissions_audit.config import Config, load_config

# A config setting that is a command-line flag under a different name.
FLAG_FOR = {"show_all": "--all"}


def parse(*argv):
    return cli.build_parser().parse_args(list(argv))


def test_every_config_setting_is_a_flag_or_documented_as_file_only():
    help_text = cli.build_parser().format_help()
    for setting in (f.name for f in fields(Config)):
        flag = FLAG_FOR.get(setting, "--" + setting.replace("_", "-"))
        reachable = flag in help_text or setting in cli.FILE_ONLY_SETTINGS
        assert reachable, f"{setting} has neither a flag nor a mention in the help text"


def test_file_only_settings_are_real_settings():
    names = {f.name for f in fields(Config)}
    assert set(cli.FILE_ONLY_SETTINGS) <= names


def test_help_states_the_read_only_promise_and_exit_codes():
    text = cli.build_parser().format_help()
    assert "Read-only" in text
    assert "Exit codes" in text


def test_unset_flags_do_not_override_the_file():
    assert cli.overrides_from(parse()) == {}


def test_flags_become_overrides():
    overrides = cli.overrides_from(
        parse(
            "--dormant-days",
            "30",
            "--all",
            "--unmask",
            "--bedrock-regions",
            "eu-west-1,us-east-1",
            "--single-account",
        )
    )
    assert overrides == {
        "dormant_days": 30,
        "show_all": True,
        "unmask": True,
        "bedrock_regions": "eu-west-1,us-east-1",
        "mode": "single",
    }


def test_flags_beat_the_file(tmp_path):
    path = tmp_path / "audit.toml"
    path.write_text("dormant_days = 30\nparallel_accounts = 4\n")

    config = load_config(path, cli.overrides_from(parse("--dormant-days", "45")))

    assert (config.dormant_days, config.parallel_accounts) == (45, 4)


def test_bad_configuration_exits_2_with_a_message(capsys):
    assert cli.main(["--dormant-days", "0"]) == 2
    assert "dormant_days" in capsys.readouterr().err


def test_missing_config_file_exits_2(capsys):
    assert cli.main(["--config", "/nonexistent/audit.toml"]) == 2
    assert "not found" in capsys.readouterr().err


@pytest.mark.parametrize("error", [DiscoveryError("no credentials"), CheckpointError("exists")])
def test_pre_run_errors_exit_2(monkeypatch, capsys, error):
    def boom(config):
        raise error

    monkeypatch.setattr(cli, "run_audit", boom)

    assert cli.main([]) == 2
    assert str(error) in capsys.readouterr().err


def test_interrupt_explains_how_to_resume(monkeypatch, capsys):
    def interrupted(config):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_audit", interrupted)

    assert cli.main([]) == 130
    assert "--resume" in capsys.readouterr().err


def test_successful_run_prints_the_report_and_returns_the_exit_code(monkeypatch, capsys, tmp_path):
    from datetime import UTC, datetime

    from bedrock_permissions_audit.app import RunOutcome
    from bedrock_permissions_audit.summary import summarize

    summary = summarize("single", datetime.now(UTC), datetime.now(UTC), [], Config())
    monkeypatch.setattr(cli, "run_audit", lambda config: RunOutcome(3, summary, [], Path(tmp_path)))

    assert cli.main(["--no-color"]) == 3
    output = capsys.readouterr().out
    assert "No findings to report." in output
    assert "\x1b[" not in output
