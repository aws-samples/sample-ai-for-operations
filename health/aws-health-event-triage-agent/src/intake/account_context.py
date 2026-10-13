# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Account context enrichment tool.

Retrieves account name, OU membership path, tags, and environment type
from AWS Organizations for a given account ID.
"""

from __future__ import annotations

import logging

import boto3
from strands import tool

logger = logging.getLogger(__name__)


def _build_ou_path(org_client, child_id: str) -> str:
    """Recursively walk ``list_parents`` to build the full OU path.

    Returns a slash-separated path like ``Root/Production/US-East``.
    """
    parts: list[str] = []
    current = child_id

    while True:
        try:
            resp = org_client.list_parents(ChildId=current)
        except Exception:
            break

        parents = resp.get("Parents", [])
        if not parents:
            break

        parent = parents[0]
        parent_id = parent["Id"]
        parent_type = parent["Type"]

        if parent_type == "ROOT":
            parts.append("Root")
            break

        # Resolve the OU name
        try:
            ou_resp = org_client.describe_organizational_unit(
                OrganizationalUnitId=parent_id,
            )
            ou_name = ou_resp["OrganizationalUnit"]["Name"]
        except Exception:
            ou_name = parent_id

        parts.append(ou_name)
        current = parent_id

    parts.reverse()
    return "/".join(parts) if parts else "Root"


def _determine_environment_type(tags: dict[str, str], ou_path: str) -> str:
    """Determine environment type from account tags or OU path.

    Checks the ``Environment`` tag first (case-insensitive value match).
    Falls back to checking whether the OU path contains ``production``
    (case-insensitive).
    """
    env_tag = tags.get("Environment", tags.get("environment", ""))
    if env_tag:
        return "production" if env_tag.lower() == "production" else "non-production"

    if "production" in ou_path.lower():
        return "production"

    return "non-production"


@tool
def get_account_context(account_id: str) -> dict:
    """Retrieve account context from AWS Organizations for a given account.

    Calls ``describe_account``, ``list_parents``, and
    ``list_tags_for_resource`` to return the account name, OU membership
    path, account tags, and derived environment type.

    Args:
        account_id: The AWS account ID to look up.

    Returns:
        A dict with ``account_id``, ``account_name``, ``ou_path``,
        ``tags``, and ``environment_type``.
    """
    try:
        org_client = boto3.client("organizations")

        # Account name
        acct_resp = org_client.describe_account(AccountId=account_id)
        account_name = acct_resp["Account"]["Name"]

        # OU path
        ou_path = _build_ou_path(org_client, account_id)

        # Tags
        tags_resp = org_client.list_tags_for_resource(ResourceId=account_id)
        tags = {t["Key"]: t["Value"] for t in tags_resp.get("Tags", [])}

        environment_type = _determine_environment_type(tags, ou_path)

        return {
            "account_id": account_id,
            "account_name": account_name,
            "ou_path": ou_path,
            "tags": tags,
            "environment_type": environment_type,
        }
    except Exception:
        logger.exception(
            "Failed to retrieve account context for %s", account_id,
        )
        return {
            "account_id": account_id,
            "account_name": account_id,
            "ou_path": "unknown",
            "tags": {},
            "environment_type": "unknown",
        }
