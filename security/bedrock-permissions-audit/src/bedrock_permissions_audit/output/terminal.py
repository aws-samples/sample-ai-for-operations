# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Plain-text report. ANSI colour only when asked for; control characters are always stripped
from values, since IAM names and tags are attacker-influenced text."""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

from ..config import Config
from ..models import Finding, RunSummary, Tier
from ..scoring.ordering import CANNOT_INVOKE, INACTIVE_OR_EXPIRED
from ..scoring.tiers import WOULD_RATE_PREFIX
from .rows import CREDENTIAL_LABELS, clean, key_label, last_used_text, protect

COLORS = {
    Tier.CRITICAL: "\x1b[1;97;41m",
    Tier.HIGH: "\x1b[1;31m",
    Tier.MEDIUM: "\x1b[33m",
    Tier.LOW: "\x1b[36m",
    Tier.INFO: "\x1b[2m",
}
RESET = "\x1b[0m"
HEADERS = ("TIER", "ACCOUNT", "PRINCIPAL", "CREDENTIAL", "KEY", "AGE", "LAST USED", "MFA", "GRANT")
MAX_WIDTH = {"PRINCIPAL": 34, "CREDENTIAL": 24}
DETAIL_WIDTH = 100
HIDDEN_LABELS = {
    CANNOT_INVOKE: "cannot invoke Amazon Bedrock",
    INACTIVE_OR_EXPIRED: "expired or inactive credentials",
}


def render_report(
    findings: Sequence[Finding],
    summary: RunSummary,
    config: Config,
    output_dir: Path | None = None,
    color: bool = False,
) -> str:
    lines: list[str] = []
    lines.extend(_table(findings, config, color))
    lines.append("")
    lines.extend(_summary_lines(summary, output_dir, color))
    return "\n".join(lines) + "\n"


def _table(findings: Sequence[Finding], config: Config, color: bool) -> list[str]:
    if not findings:
        return ["No findings to report."]

    rows = [_cells(finding, config) for finding in findings]
    widths = [max(len(HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(len(HEADERS))]
    header = "  ".join(name.ljust(width) for name, width in zip(HEADERS, widths, strict=True))
    lines = [_bold(header, color), "-" * len(header)]

    for finding, row in zip(findings, rows, strict=True):
        cells = [cell.ljust(width) for cell, width in zip(row, widths, strict=True)]
        cells[0] = _paint(cells[0], finding.tier, color)
        lines.append("  ".join(cells))
        lines.extend(_detail(finding, config, widths[0] + 2))
    return lines


def _cells(finding: Finding, config: Config) -> list[str]:
    credential = finding.credential
    age = f"{credential.age_days}d" if credential and credential.age_days is not None else "-"
    kind = CREDENTIAL_LABELS.get(credential.kind, "") if credential else "none"
    if finding.orphaned:
        kind = "none (orphaned user)"
    return [
        finding.tier.label,
        clean(finding.account_id),
        _truncate(clean(finding.principal_name), MAX_WIDTH["PRINCIPAL"]),
        _truncate(kind, MAX_WIDTH["CREDENTIAL"]),
        clean(key_label(finding, config)) or "-",
        age,
        last_used_text(finding) if credential else "-",
        "yes" if finding.mfa_active else "no",
        finding.grant,
    ]


def _detail(finding: Finding, config: Config, indent: int) -> list[str]:
    pad = " " * indent
    text = protect(clean(finding.recommended_action), config)
    wrapped = textwrap.wrap(text, DETAIL_WIDTH) or [""]
    lines = [f"{pad}-> {wrapped[0]}", *(f"{pad}   {line}" for line in wrapped[1:])]
    # Every reason is printed: for an inactive key the ones after the "would rate" line are the
    # evidence for that tier, and are shown indented under it.
    nested = False
    for reason in finding.tier_reasons:
        text = protect(clean(reason), config)
        lines.append(f"{pad}        - {text}" if nested else f"{pad}   why: {text}")
        if reason.startswith(WOULD_RATE_PREFIX) and reason.endswith(":"):
            nested = True
    return lines


def _summary_lines(summary: RunSummary, output_dir: Path | None, color: bool) -> list[str]:
    counts = summary.tier_counts
    tiers = "  ".join(f"{label} {counts.get(label, 0)}" for label in (t.label for t in Tier))
    lines = [
        _bold("Summary", color),
        f"  Mode: {'organization' if summary.mode == 'org' else 'single account'}",
        # nosemgrep: string-concat-in-list -- one summary line, split across lines on purpose
        f"  Accounts scanned: {summary.accounts_scanned}"
        f"   partial: {summary.accounts_partial}"
        f"   failed: {summary.accounts_failed}"
        f"   principals evaluated: {summary.principals_evaluated}",
        f"  Findings: {tiers}",
    ]
    if summary.hidden_info:
        causes = ", ".join(
            f"{summary.hidden_info_by_reason[key]} {label}"
            for key, label in HIDDEN_LABELS.items()
            if summary.hidden_info_by_reason.get(key)
        )
        detail = f" ({causes})" if causes else ""
        lines.append(
            f"  {summary.hidden_info} Info findings hidden{detail}; use --all to show them."
        )
    lines.extend(_account_table(summary))
    if summary.partial_accounts:
        lines.append("  Accounts audited with incomplete coverage (findings still reported):")
        for account in summary.partial_accounts:
            name = f" ({clean(account['name'])})" if account["name"] else ""
            lines.append(f"    {account['account_id']}{name}: {clean(account['reason'])}")
    if summary.failed_accounts:
        lines.append("  Accounts that could not be audited:")
        for account in summary.failed_accounts:
            name = f" ({clean(account['name'])})" if account["name"] else ""
            lines.append(f"    {account['account_id']}{name}: {clean(account['reason'])}")
    if summary.warnings:
        lines.append("  Warnings:")
        lines.extend(f"    {clean(w)}" for w in summary.warnings)
    lines.append("  Limitations:")
    for notice in summary.notices:
        wrapped = textwrap.wrap(clean(notice), 96)
        lines.append(f"    - {wrapped[0]}")
        lines.extend(f"      {line}" for line in wrapped[1:])
    if output_dir is not None:
        lines.append(f"  Output: {output_dir}")
    return lines


ACCOUNT_HEADERS = ["ACCOUNT", "NAME", "STATUS", "PRINCIPALS", *(t.label.upper() for t in Tier)]


def _account_table(summary: RunSummary) -> list[str]:
    """Per-account tier counts, the account with the most Critical findings first."""
    if not summary.accounts:
        return []
    rows = [
        [
            clean(a.account_id),
            _truncate(clean(a.name or "-"), MAX_WIDTH["PRINCIPAL"]),
            a.status,
            str(a.principals_evaluated),
            *(str(a.tier_counts.get(t.label, 0)) for t in Tier),
            f"{a.credential_report_generated_at:%Y-%m-%d %H:%M} UTC"
            if a.credential_report_generated_at
            else "-",
        ]
        for a in summary.accounts
    ]
    headers = [*ACCOUNT_HEADERS, "REPORT GENERATED"]
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))]
    lines = ["  Accounts:"]
    for cells in (headers, *rows):
        lines.append(
            "    " + "  ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()
        )
    return lines


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "~"


def _paint(text: str, tier: Tier, color: bool) -> str:
    return f"{COLORS[tier]}{text}{RESET}" if color else text


def _bold(text: str, color: bool) -> str:
    return f"\x1b[1m{text}{RESET}" if color else text
