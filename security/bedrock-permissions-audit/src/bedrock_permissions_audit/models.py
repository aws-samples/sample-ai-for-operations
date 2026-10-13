# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Plain data containers shared by every stage of the pipeline. No behaviour beyond tiny helpers."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


class Tier(enum.IntEnum):
    """Risk tier. Lower value = more urgent, so sorting ascending puts Critical first."""

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


CredentialKind = Literal["access_key", "root_access_key", "bedrock_api_key", "claude_api_key"]
Decision = Literal["allowed", "explicitDeny", "implicitDeny"]
Grant = Literal["none", "scoped", "broad", "unknown"]


def mask_key_id(key_id: str) -> str:
    """Return '...abcd' (last four characters). Short or empty values are fully hidden."""
    if len(key_id) <= 4:
        return "..."
    return "..." + key_id[-4:]


@dataclass(frozen=True)
class Credential:
    kind: CredentialKind
    key_id: str  # full ID; writers must call id_masked unless the user passed --unmask
    active: bool
    created: datetime | None = None
    last_used: datetime | None = None
    last_used_region: str | None = None
    age_days: int | None = None
    unused_days: int | None = None  # None means never used (or unknown, see last_used_known)
    # IAM does not report when a long-term API key was last used, so for those it is unknown,
    # and "never used" must not be inferred.
    last_used_known: bool = True
    expires: datetime | None = None
    # True when the credential's expiry date has passed. An expired credential cannot be
    # re-enabled, unlike one that was merely deactivated.
    expired: bool = False

    @property
    def id_masked(self) -> str:
        if self.kind == "root_access_key":
            return self.key_id  # a label such as "root-access-key-1", not a real key ID
        return mask_key_id(self.key_id)

    @property
    def never_used(self) -> bool:
        return self.last_used_known and self.last_used is None

    def is_dormant(self, threshold_days: int) -> bool:
        """Never used, or unused for at least threshold_days. Unknown last use is not dormant."""
        if not self.last_used_known:
            return False
        return self.last_used is None or (
            self.unused_days is not None and self.unused_days >= threshold_days
        )


@dataclass(frozen=True)
class ActionResult:
    action: str
    decision: Decision
    resource: str  # "*" or the ARN that was tested
    matched_statements: tuple[str, ...] = ()
    # Condition keys the simulator had no value for. A non-allowed result with entries here may
    # be allowed in real use, so it is reported rather than hidden.
    missing_context: tuple[str, ...] = ()


@dataclass(frozen=True)
class Account:
    account_id: str
    name: str | None = None
    is_caller: bool = False  # the account the running credentials belong to: no role assumption


@dataclass(frozen=True)
class Principal:
    """An IAM user (or the account root) that holds at least one long-lived credential."""

    account_id: str
    name: str
    arn: str
    is_root: bool = False
    mfa_active: bool = False
    access_keys: tuple[Credential, ...] = ()
    api_keys: tuple[Credential, ...] = ()  # long-term Amazon Bedrock / Claude Platform API keys
    attached_policy_arns: tuple[str, ...] = ()  # directly attached plus via groups
    groups: tuple[str, ...] = ()  # names of the groups the user belongs to
    is_phantom: bool = False  # named BedrockAPIKey-* or AeaApiKey-*

    @property
    def credentials(self) -> tuple[Credential, ...]:
        return self.access_keys + self.api_keys


@dataclass(frozen=True)
class Finding:
    """One row per credential. A principal with no credential at all (an orphaned
    BedrockAPIKey-* user) produces one row with credential=None."""

    account_id: str
    account_name: str | None
    principal_arn: str
    principal_name: str
    credential: Credential | None
    mfa_active: bool = False
    is_root: bool = False
    is_phantom: bool = False
    orphaned: bool = False
    admin_policies: tuple[str, ...] = ()
    results: tuple[ActionResult, ...] = ()
    grant: Grant = "none"
    regions_allowed: tuple[str, ...] = ()
    tier: Tier = Tier.INFO
    # For an inactive access key reported as Low: the tier it would get if re-enabled
    # (Critical or High). None for every other finding.
    if_reactivated_tier: Tier | None = None
    tier_reasons: tuple[str, ...] = ()  # why this tier, in plain words, for the customer
    recommended_action: str = ""
    warnings: tuple[str, ...] = ()  # evaluation caveats, e.g. a rejected action name

    @property
    def granting_policies(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for result in self.results:
            if result.decision == "allowed":
                for statement in result.matched_statements:
                    seen.setdefault(statement, None)
        return tuple(seen)


AccountStatus = Literal["ok", "partial", "failed"]


@dataclass(frozen=True)
class AccountResult:
    """`partial` means the account was audited but without its Amazon Bedrock API keys, because
    the role cannot list them. Its findings are still reported; `reason` says what is missing."""

    account: Account
    status: AccountStatus
    reason: str | None = None
    findings: tuple[Finding, ...] = ()
    principals_evaluated: int = 0
    # Non-fatal problems that may reduce coverage, e.g. a fallback path was used. Always printed.
    warnings: tuple[str, ...] = ()
    # When IAM generated the credential report (it can reuse one up to four hours old).
    credential_report_generated_at: datetime | None = None

    @property
    def audited(self) -> bool:
        """True when findings exist for the account: complete (ok) or partial."""
        return self.status in ("ok", "partial")


@dataclass(frozen=True)
class AccountBreakout:
    """One row of the per-account table."""

    account_id: str
    name: str | None
    status: Literal["ok", "partial"]
    principals_evaluated: int
    tier_counts: dict[str, int]  # visible findings only
    credential_report_generated_at: datetime | None = None


@dataclass
class RunSummary:
    mode: Literal["org", "single"]
    started_at: datetime
    finished_at: datetime | None = None
    accounts_scanned: int = 0
    accounts_failed: int = 0
    failed_accounts: list[dict[str, str]] = field(default_factory=list)
    accounts_partial: int = 0  # also counted in accounts_scanned
    partial_accounts: list[dict[str, str]] = field(default_factory=list)
    accounts: list[AccountBreakout] = field(default_factory=list)
    principals_evaluated: int = 0
    tier_counts: dict[str, int] = field(default_factory=dict)  # visible findings only
    hidden_info: int = 0  # Info findings left out because --all was not given
    # The same findings by cause: "cannot_invoke" and "inactive_or_expired". Sums to hidden_info.
    hidden_info_by_reason: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
