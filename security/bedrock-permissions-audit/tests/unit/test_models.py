# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from dataclasses import FrozenInstanceError, replace

import pytest

from bedrock_permissions_audit.models import (
    ActionResult,
    Credential,
    Finding,
    Tier,
    mask_key_id,
)

from .factories import KEY_ID


def test_tier_sorts_critical_first():
    assert sorted([Tier.INFO, Tier.CRITICAL, Tier.MEDIUM, Tier.HIGH, Tier.LOW]) == [
        Tier.CRITICAL,
        Tier.HIGH,
        Tier.MEDIUM,
        Tier.LOW,
        Tier.INFO,
    ]
    assert Tier.CRITICAL.label == "Critical"


@pytest.mark.parametrize(
    ("key_id", "expected"),
    [(KEY_ID, "...MPLE"), ("abcd", "..."), ("", "...")],
)
def test_mask_key_id(key_id, expected):
    assert mask_key_id(key_id) == expected


def test_credential_masks_and_reports_never_used():
    credential = Credential(kind="access_key", key_id=KEY_ID, active=True)
    assert credential.id_masked == "...MPLE"
    assert KEY_ID not in credential.id_masked
    assert credential.never_used is True


def test_models_are_immutable():
    credential = Credential(kind="access_key", key_id=KEY_ID, active=True)
    with pytest.raises(FrozenInstanceError):
        credential.active = False  # type: ignore[misc]


def test_granting_policies_lists_only_allowed_unique_statements():
    finding = Finding(
        account_id="123456789012",
        account_name=None,
        principal_arn="arn:aws:iam::123456789012:user/alice",
        principal_name="alice",
        credential=None,
        results=(
            ActionResult("bedrock:InvokeModel", "allowed", "*", ("PolicyA", "PolicyB")),
            ActionResult("bedrock:Converse", "allowed", "*", ("PolicyA",)),
            ActionResult("bedrock:DeleteCustomModel", "implicitDeny", "*", ("PolicyC",)),
        ),
    )
    assert finding.granting_policies == ("PolicyA", "PolicyB")


def test_finding_tier_is_set_with_replace_not_mutation():
    finding = Finding("1", None, "arn", "alice", None)
    assert finding.tier is Tier.INFO
    assert replace(finding, tier=Tier.HIGH).tier is Tier.HIGH
