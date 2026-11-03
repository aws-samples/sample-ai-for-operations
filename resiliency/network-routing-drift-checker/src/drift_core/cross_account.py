# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Cross-account hand-off names and the same/cross-account switch (design.md D§3.3a).

The role names are fixed so the checker stack (account N) can name roles in the Agent Space
account (D) before they exist. This module is the single source of the name format; the CDK
companion stack (task 3.13) must produce exactly the same names (its synth test asserts the format).
"""

from __future__ import annotations

JOURNAL_READER_ROLE_FORMAT = "nrdc-journal-reader-{checker_account}-{region}"
EVENT_FORWARDER_ROLE_FORMAT = "nrdc-event-forwarder-{checker_account}-{region}"
ROLE_NAME_MAX = 64  # IAM role-name limit


def _name(fmt: str, checker_account: str, region: str) -> str:
    if not (len(checker_account) == 12 and checker_account.isdigit()):
        raise ValueError("checker_account must be a 12-digit account ID")
    if not region or not region.replace("-", "").isalnum():
        raise ValueError("region is required")
    name = fmt.format(checker_account=checker_account, region=region)
    if len(name) > ROLE_NAME_MAX:
        raise ValueError(f"role name longer than {ROLE_NAME_MAX} characters")
    return name


def journal_reader_role_name(checker_account: str, region: str) -> str:
    """Role in account D that the callback assumes to call aidevops:ListJournalRecords."""
    return _name(JOURNAL_READER_ROLE_FORMAT, checker_account, region)


def event_forwarder_role_name(checker_account: str, region: str) -> str:
    """EventBridge execution role in account D that invokes the callback in account N."""
    return _name(EVENT_FORWARDER_ROLE_FORMAT, checker_account, region)


def journal_reader_role_arn(devops_account: str, checker_account: str, region: str, partition: str = "aws") -> str:
    if not (len(devops_account) == 12 and devops_account.isdigit()):
        raise ValueError("devops_account must be a 12-digit account ID")
    return f"arn:{partition}:iam::{devops_account}:role/{journal_reader_role_name(checker_account, region)}"


def parse_function_arn(arn: str) -> tuple[str, str, str]:
    """(partition, region, account) of a Lambda function ARN, e.g. from context.invoked_function_arn."""
    parts = (arn or "").split(":")
    if len(parts) < 7 or parts[0] != "arn" or parts[2] != "lambda" or not parts[3] or not parts[4]:
        raise ValueError("not a Lambda function ARN")
    return parts[1], parts[3], parts[4]


def is_cross_account(devops_account: str, own_account: str) -> bool:
    """Empty or equal to our own account means same-account (D§3.3)."""
    return bool(devops_account) and devops_account != own_account
