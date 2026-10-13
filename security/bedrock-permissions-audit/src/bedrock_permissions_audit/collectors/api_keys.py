# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Long-term API keys, which IAM stores as service-specific credentials.

Amazon Bedrock long-term keys can belong to any IAM user, not only to the BedrockAPIKey-* users
the console creates, so they are listed account-wide. Claude Platform on AWS keys live on
dedicated AeaApiKey-* users and are listed per user."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError, ParamValidationError

from ..models import Credential, CredentialKind

logger = logging.getLogger(__name__)

ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
BEDROCK_SERVICE = "bedrock.amazonaws.com"
BEDROCK_USER_PREFIX = "BedrockAPIKey-"
CLAUDE_USER_PREFIX = "AeaApiKey-"
PHANTOM_PREFIXES = (BEDROCK_USER_PREFIX, CLAUDE_USER_PREFIX)


def is_access_denied(exc: ClientError) -> bool:
    return exc.response.get("Error", {}).get("Code", "") in ACCESS_DENIED_CODES


def is_phantom_user(user_name: str) -> bool:
    return user_name.startswith(PHANTOM_PREFIXES)


def collect_bedrock_api_keys(
    iam: Any, now: datetime
) -> tuple[dict[str, tuple[Credential, ...]], list[str]]:
    """Every Amazon Bedrock long-term API key in the account, grouped by IAM user name."""
    warnings: list[str] = []
    found: dict[str, list[Credential]] = {}
    try:
        for item in _list_all(iam, ServiceName=BEDROCK_SERVICE, AllUsers=True):
            found.setdefault(item["UserName"], []).append(
                _to_credential(item, "bedrock_api_key", now)
            )
    except ParamValidationError:
        # An older boto3 that predates the AllUsers parameter.
        warnings.append(
            "This boto3 version cannot list API keys account-wide (upgrade boto3 to 1.39 or "
            "later); only BedrockAPIKey-* and AeaApiKey-* users were checked, so a key on any "
            "other user may be missing."
        )
        logger.warning("api_key_listing_unsupported")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Error")
        if code in ACCESS_DENIED_CODES:
            # Not hidden here: the caller decides. The account audit marks the account partial.
            raise
        warnings.append(
            f"Account-wide Amazon Bedrock API key listing failed ({code}); "
            "only BedrockAPIKey-* users were checked."
        )
        logger.warning("api_key_listing_failed", extra={"error": code})
    return {user: tuple(keys) for user, keys in found.items()}, warnings


def collect_user_api_keys(
    iam: Any, user_names: Iterable[str], now: datetime
) -> dict[str, tuple[Credential, ...]]:
    """Service-specific credentials for named users. A user deleted mid-scan is skipped."""
    found: dict[str, tuple[Credential, ...]] = {}
    for user_name in user_names:
        try:
            items = list(_list_all(iam, UserName=user_name))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                continue
            raise
        credentials: tuple[Credential, ...] = ()
        for item in items:
            kind = _kind_for(user_name, item)
            if kind is not None:
                credentials += (_to_credential(item, kind, now),)
        if credentials:
            found[user_name] = credentials
    return found


def merge(*sources: Mapping[str, tuple[Credential, ...]]) -> dict[str, tuple[Credential, ...]]:
    """Combine mappings, de-duplicating by credential ID."""
    merged: dict[str, dict[str, Credential]] = {}
    for source in sources:
        for user, credentials in source.items():
            bucket = merged.setdefault(user, {})
            for credential in credentials:
                bucket.setdefault(credential.key_id, credential)
    return {user: tuple(bucket.values()) for user, bucket in merged.items()}


def _kind_for(user_name: str, item: Mapping[str, Any]) -> CredentialKind | None:
    if item.get("ServiceName") == BEDROCK_SERVICE:
        return "bedrock_api_key"
    if user_name.startswith(CLAUDE_USER_PREFIX):
        return "claude_api_key"
    return None


def _list_all(iam: Any, **params: Any) -> Iterable[dict[str, Any]]:
    """boto3 has no paginator for this call, so follow the marker by hand."""
    marker: str | None = None
    while True:
        call_params = {**params, "Marker": marker} if marker else params
        page = iam.list_service_specific_credentials(**call_params)
        yield from page.get("ServiceSpecificCredentials", [])
        if not page.get("IsTruncated"):
            return
        marker = page["Marker"]


def _to_credential(item: Mapping[str, Any], kind: CredentialKind, now: datetime) -> Credential:
    created = item.get("CreateDate")
    expires = item.get("ExpirationDate")
    expired = expires is not None and expires <= now
    return Credential(
        kind=kind,
        key_id=item["ServiceSpecificCredentialId"],
        active=item.get("Status") == "Active" and not expired,
        created=created,
        age_days=(now - created).days if created else None,
        last_used_known=False,
        expires=expires,
        expired=expired,
    )
