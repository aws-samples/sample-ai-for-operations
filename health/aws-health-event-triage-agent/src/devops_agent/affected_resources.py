# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: parse_affected_resources.

Parses the DevOps Agent investigation's `## Affected resources` markdown
table into a structured, validated result. Pure code — no model call, never
raises. This is the trust boundary of the whole enrichment design (working
spec feat-devops-agent-enrichment, design §1, §3.3): the investigating
agent's output is untrusted text; it becomes trusted data only after this
parser validates it against a fixed contract.

Contract (verbatim, what the skill is told to write):

  ## Affected resources

  | account | resource_arn | resource_type | current_version | status | evidence |
  |---|---|---|---|---|---|
  | 111122223333 | arn:aws:rds:...:db:orders | rds-instance | 11.9 | affected | ... |

  - Header row must match the six column names exactly, in order. This is
    the parse anchor.
  - status vocabulary is fixed: affected | at_risk | not_affected |
    inaccessible | unknown.
  - account must be a 12-digit string; resource_arn must start with "arn:".
    A row failing either is dropped and counted, unless every row is
    dropped (hard failure).
  - A missing table, a header mismatch, or zero valid rows is a hard
    failure: result.error is set, result.raw carries the section text (or
    the whole message if no section was found).
  - An optional "## Dependents verified: yes|no" line immediately after the
    table maps "yes" to dependents_verified: true on every row; anything
    else (no, absent, any other value) leaves it unset/false. Re-listing
    the same resources AWS already listed is NOT verification — only an
    explicit "yes" counts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TABLE_HEADING_RE = re.compile(r"##\s*Affected resources\b", re.IGNORECASE)
_DEPENDENTS_VERIFIED_RE = re.compile(
    r"^\s*##\s*Dependents verified:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)

_EXPECTED_HEADER = (
    "account",
    "resource_arn",
    "resource_type",
    "current_version",
    "status",
    "evidence",
)

_VALID_STATUSES = frozenset({"affected", "at_risk", "not_affected", "inaccessible", "unknown"})

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


@dataclass
class ParseResult:
    """Result of parsing one '## Affected resources' table.

    Attributes:
        rows: Validated, well-formed rows. Empty when error is set.
        warnings: Non-fatal issues (bad status value, dropped row, etc.) —
            present even when the overall parse succeeded.
        dropped_rows: Rows that failed account/ARN validation and were
            excluded from `rows`, each carrying the original row dict and
            a "reason" key.
        error: None on success. Set to a short machine-readable string on
            hard failure (missing table, header mismatch, zero valid rows).
        raw: The raw section text (or the whole input) when error is set,
            so the ticket can still surface it for the operator. None on
            success (rows already carry everything needed).
        dependents_verified: True only when the message contains an exact
            "## Dependents verified: yes" line (case-insensitive on the
            keyword, exact "yes" on the value). False for "no", absent, or
            any other value — including a table that merely re-lists the
            same resources AWS already listed without this explicit marker.
    """

    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dropped_rows: list[dict] = field(default_factory=list)
    error: str | None = None
    raw: str | None = None
    dependents_verified: bool = False

    def as_lookups(self) -> list[dict]:
        """Convert parsed rows into the `lookups: list[dict]` shape
        build_impact_inventory() consumes — the same shape the three
        deleted per-service plug-ins (eks.py, rds.py, lambda_.py) produced,
        so per-environment breakdown and pricing apply unchanged.

        Each lookup dict carries accountId (matching build_impact_inventory's
        existing key), the ARN/type/version/status/evidence fields renamed
        to avoid colliding with build_impact_inventory's own bookkeeping
        keys ({region, accountId, dependents_verified} are excluded from
        becoming "resource_keys" there), and dependents_verified when this
        parse result found the marker.

        Returns:
            An empty list when self.error is set (a hard-failure result
            has nothing valid to hand build_impact_inventory — the caller
            is expected to fall back to the entity-list baseline instead,
            per design §3.1's MERGE_ENRICHMENT pseudocode).
        """
        if self.error:
            return []
        lookups: list[dict] = []
        for row in self.rows:
            lookup = {
                "accountId": row["account"],
                "resource_arn": row["resource_arn"],
                "resource_type": row["resource_type"],
                "current_version": row["current_version"],
                "status": row["status"],
                "evidence": row["evidence"],
            }
            if self.dependents_verified:
                lookup["dependents_verified"] = True
            lookups.append(lookup)
        return lookups


def _find_dependents_verified(markdown: str) -> bool:
    match = _DEPENDENTS_VERIFIED_RE.search(markdown)
    if not match:
        return False
    return match.group(1).strip().lower() == "yes"


def _extract_section(markdown: str) -> str | None:
    """Return the text from the '## Affected resources' heading to the
    next '##' heading (or end of string), or None if the heading is absent."""
    heading_match = _TABLE_HEADING_RE.search(markdown)
    if not heading_match:
        return None
    start = heading_match.start()
    # Find the next '##' heading strictly after this one's own line.
    rest = markdown[heading_match.end():]
    next_heading = re.search(r"\n##\s", rest)
    end = heading_match.end() + next_heading.start() if next_heading else len(markdown)
    return markdown[start:end]


def _split_table_rows(section: str) -> list[list[str]]:
    """Extract every '|'-delimited line in the section as a list of cells,
    trimmed, with the leading/trailing empty cells (from a leading/trailing
    '|') stripped. Returns an empty list if no such lines exist."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        rows.append(cells)
    return rows


def _is_separator_row(cells: list[str]) -> bool:
    """True for a markdown table separator row like '|---|---|...|'."""
    return all(re.fullmatch(r":?-{1,}:?", c) for c in cells if c)


def parse_affected_resources(markdown: str | None) -> ParseResult:
    """Parses a DevOps Agent investigation's '## Affected resources' table.

    Never raises. Args:
        markdown: The investigation's full analysis text (the same
            analysisMarkdown the callback already retrieves), or None/empty
            if the callback could not retrieve any analysis.

    Returns:
        A ParseResult. On hard failure (missing table, header mismatch,
        every row invalid), .error is set and .rows is empty; the caller
        (MERGE_ENRICHMENT, design §3.1) falls back to the entity-list
        baseline per req §1a — this parser never invents evidence and
        never erases AWS's own entity-list evidence.
    """
    if not markdown or not markdown.strip():
        return ParseResult(error="no analysis text available", raw=markdown or "")

    section = _extract_section(markdown)
    if section is None:
        return ParseResult(error="no '## Affected resources' section found", raw=markdown)

    table_rows = _split_table_rows(section)
    if not table_rows:
        return ParseResult(error="no markdown table found under '## Affected resources'", raw=section)

    header = tuple(c.lower() for c in table_rows[0])
    if header != _EXPECTED_HEADER:
        return ParseResult(
            error=(
                f"header mismatch: expected {list(_EXPECTED_HEADER)}, got {list(table_rows[0])}"
            ),
            raw=section,
        )

    data_rows = table_rows[1:]
    # Drop the separator row ('|---|---|...|') if present — it's optional
    # per strict CommonMark table syntax, but the skill's own template
    # includes one, and a real agent may omit or duplicate it.
    data_rows = [r for r in data_rows if not _is_separator_row(r)]

    if not data_rows:
        return ParseResult(error="table has a header but zero data rows", raw=section)

    rows: list[dict] = []
    dropped_rows: list[dict] = []
    warnings: list[str] = []

    for raw_row in data_rows:
        if len(raw_row) != len(_EXPECTED_HEADER):
            dropped_rows.append({
                "cells": raw_row,
                "reason": f"expected {len(_EXPECTED_HEADER)} columns, got {len(raw_row)}",
            })
            continue

        row = dict(zip(_EXPECTED_HEADER, raw_row))

        if not _ACCOUNT_ID_RE.match(row["account"]):
            dropped_rows.append({**row, "reason": f"account {row['account']!r} is not a 12-digit ID"})
            continue

        if not row["resource_arn"].startswith("arn:"):
            dropped_rows.append(
                {**row, "reason": f"resource_arn {row['resource_arn']!r} does not start with 'arn:'"}
            )
            continue

        status = row["status"].lower()
        if status not in _VALID_STATUSES:
            warnings.append(
                f"row for {row['resource_arn']!r} has unrecognised status {row['status']!r}; "
                "treated as 'unknown'"
            )
            status = "unknown"
        row["status"] = status

        rows.append(row)

    if not rows:
        return ParseResult(
            error="every row failed validation (bad account ID or resource_arn)",
            raw=section,
        )

    if dropped_rows:
        warnings.append(f"{len(dropped_rows)} row(s) dropped for failing account/ARN validation")

    return ParseResult(
        rows=rows,
        warnings=warnings,
        dropped_rows=dropped_rows,
        dependents_verified=_find_dependents_verified(markdown),
    )
