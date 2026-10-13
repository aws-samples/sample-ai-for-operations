# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import json
import stat
from datetime import UTC, datetime

import pytest

from bedrock_permissions_audit import checkpoint
from bedrock_permissions_audit.checkpoint import (
    CheckpointError,
    CheckpointStore,
    config_fingerprint,
)
from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Account, AccountResult, Tier
from bedrock_permissions_audit.scoring import score
from bedrock_permissions_audit.serialization import account_result_from_plain, to_plain

from .factories import ADMIN, credential, finding

CONFIG = Config()


def result(account_id="123456789012", status="ok", **kwargs):
    findings = (
        score(finding(admin_policies=(ADMIN,), account_id=account_id), CONFIG),
        score(
            finding(
                credential=credential(
                    created=datetime(2025, 1, 1, tzinfo=UTC),
                    last_used=datetime(2025, 6, 1, tzinfo=UTC),
                    last_used_region="eu-west-1",
                    unused_days=300,
                ),
                account_id=account_id,
                principal_name="bob",
            ),
            CONFIG,
        ),
    )
    return AccountResult(
        Account(account_id, "workloads"),
        status,
        findings=findings,
        principals_evaluated=2,
        warnings=("a warning",),
        **kwargs,
    )


def test_serialisation_round_trip_is_lossless():
    original = result()

    assert account_result_from_plain(json.loads(json.dumps(to_plain(original)))) == original


def test_round_trip_preserves_tier_as_an_enum():
    restored = account_result_from_plain(json.loads(json.dumps(to_plain(result()))))
    assert restored.findings[0].tier is Tier.CRITICAL


def test_save_then_load(tmp_path):
    store = CheckpointStore(tmp_path, config_fingerprint(CONFIG))
    store.prepare(resume=False)
    original = result()

    store.save(original)

    assert store.load("123456789012") == original
    path = tmp_path / ".checkpoints" / "123456789012.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_missing_checkpoint_loads_as_none(tmp_path):
    store = CheckpointStore(tmp_path, "abc")
    store.prepare(resume=False)
    assert store.load("999999999999") is None


def test_failed_accounts_are_not_checkpointed_so_resume_retries_them(tmp_path):
    store = CheckpointStore(tmp_path, "abc")
    store.prepare(resume=False)

    store.save(AccountResult(Account("222222222222"), "failed", reason="boom"))

    assert store.load("222222222222") is None


def test_non_empty_directory_without_resume_is_refused(tmp_path):
    first = CheckpointStore(tmp_path, "abc")
    first.prepare(resume=False)
    first.save(result())

    with pytest.raises(CheckpointError, match="--resume"):
        CheckpointStore(tmp_path, "abc").prepare(resume=False)


def test_resume_accepts_a_populated_directory(tmp_path):
    first = CheckpointStore(tmp_path, "abc")
    first.prepare(resume=False)
    first.save(result())

    second = CheckpointStore(tmp_path, "abc")
    second.prepare(resume=True)

    assert second.load("123456789012") is not None


def test_the_reactivation_tier_survives_a_checkpoint_round_trip(tmp_path):
    inactive = score(
        finding(
            admin_policies=(ADMIN,),
            mfa_active=False,
            credential=credential(active=False, age_days=390, unused_days=350),
        ),
        CONFIG,
    )
    assert inactive.if_reactivated_tier is Tier.CRITICAL
    original = AccountResult(Account("123456789012"), "ok", findings=(inactive,))
    store = CheckpointStore(tmp_path, "abc")
    store.prepare(resume=False)

    store.save(original)

    restored = store.load("123456789012")
    assert restored == original
    assert restored.findings[0].if_reactivated_tier is Tier.CRITICAL


def test_old_results_without_the_field_load_as_not_reactivated():
    plain = to_plain(result())
    for item in plain["findings"]:
        del item["if_reactivated_tier"]

    restored = account_result_from_plain(plain)

    assert all(f.if_reactivated_tier is None for f in restored.findings)


def test_a_checkpoint_scored_under_the_old_rules_is_not_reused(tmp_path):
    """Regression guard: without a format bump, --resume would silently keep Info results for
    inactive keys that now rate Low."""
    store = CheckpointStore(tmp_path, "abc")
    store.prepare(resume=False)
    store.save(result())
    path = tmp_path / ".checkpoints" / "123456789012.json"
    payload = json.loads(path.read_text())
    payload["version"] = checkpoint.FORMAT_VERSION - 1
    path.write_text(json.dumps(payload))

    assert store.load("123456789012") is None
    assert checkpoint.FORMAT_VERSION >= 2


def test_checkpoint_from_different_scoring_settings_is_ignored(tmp_path):
    old = CheckpointStore(tmp_path, config_fingerprint(Config(dormant_days=90)))
    old.prepare(resume=False)
    old.save(result())

    new = CheckpointStore(tmp_path, config_fingerprint(Config(dormant_days=30)))
    new.prepare(resume=True)

    assert new.load("123456789012") is None


def test_corrupt_checkpoint_is_ignored_not_fatal(tmp_path):
    store = CheckpointStore(tmp_path, "abc")
    store.prepare(resume=False)
    (tmp_path / ".checkpoints" / "123456789012.json").write_text("{not json")

    assert store.load("123456789012") is None


@pytest.mark.parametrize(
    "change",
    [
        {"output_dir": "/elsewhere"},
        {"show_all": True},
        {"unmask": True},
        {"parallel_accounts": 32},
        {"role_name": "OtherRole"},
        {"log_level": "DEBUG"},
        {"no_color": True},
    ],
)
def test_presentation_and_run_settings_do_not_invalidate_checkpoints(change):
    from bedrock_permissions_audit.config import load_config

    assert config_fingerprint(load_config(overrides=change)) == config_fingerprint(CONFIG)


@pytest.mark.parametrize(
    "change",
    [
        {"dormant_days": 30},
        {"invoke_actions": ("bedrock:InvokeModel",)},
        {"admin_policy_arns": ()},
        {"bedrock_regions": ("eu-west-1",)},
    ],
)
def test_scoring_settings_change_the_fingerprint(change):
    from bedrock_permissions_audit.config import load_config

    assert config_fingerprint(load_config(overrides=change)) != config_fingerprint(CONFIG)


def test_a_partial_account_is_not_checkpointed_so_resume_audits_it_again(tmp_path):
    store = CheckpointStore(tmp_path, config_fingerprint(CONFIG))
    store.prepare(resume=False)

    store.save(result("111111111111", "partial", reason="API keys not evaluated"))

    assert store.load("111111111111") is None


def test_report_generation_time_survives_a_round_trip():
    generated = datetime(2026, 6, 1, 8, 30, tzinfo=UTC)

    restored = account_result_from_plain(to_plain(result(credential_report_generated_at=generated)))

    assert restored.credential_report_generated_at == generated
