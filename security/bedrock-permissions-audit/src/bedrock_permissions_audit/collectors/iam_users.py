# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""IAM users that hold a long-lived credential, plus the root account's access keys."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from ..models import Credential, Principal
from .api_keys import is_phantom_user
from .credential_report import ROOT_USER, ReportRow

logger = logging.getLogger(__name__)


def list_user_names(iam: Any) -> list[str]:
    return [
        user["UserName"]
        for page in iam.get_paginator("list_users").paginate()
        for user in page["Users"]
    ]


def collect_principals(
    iam: Any,
    account_id: str,
    report: Mapping[str, ReportRow],
    api_keys: Mapping[str, tuple[Credential, ...]],
    now: datetime,
) -> tuple[list[Principal], list[str]]:
    """Return (principals, warnings). The root account is first when it holds an access key.

    A user is included if it has an access key, a long-term API key, or is a BedrockAPIKey-* /
    AeaApiKey-* user (so an orphaned one can be reported). Console-only users are skipped: they
    hold no long-lived credential to review."""
    principals: list[Principal] = []
    warnings: list[str] = []

    root = _root_principal(account_id, report, now)
    if root is not None:
        principals.append(root)

    group_policies: dict[str, tuple[str, ...]] = {}
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                principal = _user_principal(
                    iam, account_id, user, api_keys.get(name, ()), group_policies, now
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                    warnings.append(f"User {name} was deleted during the scan and was skipped.")
                    continue
                raise
            if principal is not None:
                principals.append(principal)
    return principals, warnings


def _user_principal(
    iam: Any,
    account_id: str,
    user: Mapping[str, Any],
    api_keys: tuple[Credential, ...],
    group_policies: dict[str, tuple[str, ...]],
    now: datetime,
) -> Principal | None:
    name = user["UserName"]
    access_keys = _access_keys(iam, name, now)
    phantom = is_phantom_user(name)
    if not access_keys and not api_keys and not phantom:
        return None

    attached = [
        policy["PolicyArn"]
        for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
        for policy in page["AttachedPolicies"]
    ]
    group_names: list[str] = []
    for page in iam.get_paginator("list_groups_for_user").paginate(UserName=name):
        for group in page["Groups"]:
            group_name = group["GroupName"]
            group_names.append(group_name)
            if group_name not in group_policies:
                group_policies[group_name] = tuple(
                    policy["PolicyArn"]
                    for group_page in iam.get_paginator("list_attached_group_policies").paginate(
                        GroupName=group_name
                    )
                    for policy in group_page["AttachedPolicies"]
                )
            attached.extend(group_policies[group_name])

    return Principal(
        account_id=account_id,
        name=name,
        arn=user["Arn"],
        mfa_active=_has_mfa(iam, name),
        access_keys=access_keys,
        api_keys=api_keys,
        attached_policy_arns=tuple(dict.fromkeys(attached)),
        groups=tuple(group_names),
        is_phantom=phantom,
    )


def _has_mfa(iam: Any, user_name: str) -> bool:
    """Current MFA state. The credential report is not used for this: IAM serves a report up to
    four hours old, which omits recently created users and would show them as having no MFA."""
    for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
        if page["MFADevices"]:
            return True
    return False


def _access_keys(iam: Any, user_name: str, now: datetime) -> tuple[Credential, ...]:
    credentials: list[Credential] = []
    for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
        for key in page["AccessKeyMetadata"]:
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])[
                "AccessKeyLastUsed"
            ]
            used_at = last_used.get("LastUsedDate")
            created = key.get("CreateDate")
            credentials.append(
                Credential(
                    kind="access_key",
                    key_id=key["AccessKeyId"],
                    active=key["Status"] == "Active",
                    created=created,
                    last_used=used_at,
                    last_used_region=_region(last_used),
                    age_days=(now - created).days if created else None,
                    unused_days=(now - used_at).days if used_at else None,
                )
            )
    return tuple(credentials)


def _region(last_used: Mapping[str, Any]) -> str | None:
    region = last_used.get("Region")
    return None if region in (None, "", "N/A") else region


def _root_principal(
    account_id: str, report: Mapping[str, ReportRow], now: datetime
) -> Principal | None:
    row = report.get(ROOT_USER)
    if row is None:
        return None
    keys = tuple(
        Credential(
            kind="root_access_key",
            key_id=f"root-access-key-{key.slot}",
            active=key.active,
            created=key.last_rotated,
            last_used=key.last_used,
            last_used_region=key.last_used_region,
            age_days=(now - key.last_rotated).days if key.last_rotated else None,
            unused_days=(now - key.last_used).days if key.last_used else None,
        )
        for key in row.keys
        if key.exists
    )
    if not keys:
        return None
    return Principal(
        account_id=account_id,
        name=ROOT_USER,
        arn=row.arn or f"arn:aws:iam::{account_id}:root",
        is_root=True,
        mfa_active=row.mfa_active,
        access_keys=keys,
    )
