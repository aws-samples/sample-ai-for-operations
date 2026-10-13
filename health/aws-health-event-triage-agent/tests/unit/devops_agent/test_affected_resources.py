# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.affected_resources.parse_affected_resources.

Requirements covered: req E2, design §3.3, working spec
feat-devops-agent-enrichment task 1.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from src.devops_agent.affected_resources import parse_affected_resources

_WELL_FORMED = """\
## Summary

Two accounts affected by the RDS engine deprecation.

## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | engine aurora-postgresql 11.9, EOL 2026-02-28 |
| 111122223333 | arn:aws:eks:eu-west-1:111122223333:cluster/prod | eks-cluster | 1.25 | at_risk | 2 Deployments with replicas=1 in fp-default |
| 444455556666 | arn:aws:rds:eu-west-1:444455556666:db:billing | rds-instance | 11.9 | affected | engine aurora-postgresql 11.9, EOL 2026-02-28 |

## Recommended Actions

Upgrade before the deadline.
"""


class TestWellFormedTable:
    def test_three_rows_parsed(self):
        result = parse_affected_resources(_WELL_FORMED)
        assert result.error is None
        assert len(result.rows) == 3

    def test_row_fields_correct(self):
        result = parse_affected_resources(_WELL_FORMED)
        row = result.rows[0]
        assert row["account"] == "111122223333"
        assert row["resource_arn"] == "arn:aws:rds:eu-west-1:111122223333:db:orders"
        assert row["resource_type"] == "rds-instance"
        assert row["current_version"] == "11.9"
        assert row["status"] == "affected"
        assert "aurora-postgresql" in row["evidence"]

    def test_status_at_risk_preserved(self):
        result = parse_affected_resources(_WELL_FORMED)
        statuses = [r["status"] for r in result.rows]
        assert "at_risk" in statuses

    def test_no_dropped_rows(self):
        result = parse_affected_resources(_WELL_FORMED)
        assert result.dropped_rows == []

    def test_no_warnings(self):
        result = parse_affected_resources(_WELL_FORMED)
        assert result.warnings == []

    def test_dependents_verified_false_when_absent(self):
        result = parse_affected_resources(_WELL_FORMED)
        assert result.dependents_verified is False

    def test_as_lookups_shape(self):
        result = parse_affected_resources(_WELL_FORMED)
        lookups = result.as_lookups()
        assert len(lookups) == 3
        assert lookups[0]["accountId"] == "111122223333"
        assert "dependents_verified" not in lookups[0]


class TestHeaderOutOfOrder:
    def test_columns_swapped_is_hard_failure(self):
        markdown = """\
## Affected resources

| resource_arn | account | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| arn:aws:rds:eu-west-1:111122223333:db:orders | 111122223333 | rds-instance | 11.9 | affected | evidence text |
"""
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "header mismatch" in result.error
        assert result.rows == []
        assert result.raw is not None


class TestMissingColumn:
    def test_missing_evidence_column_is_hard_failure(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status |
|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected |
"""
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "header mismatch" in result.error


class TestOneBadRowAmongGood:
    def test_bad_row_dropped_good_rows_kept(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | evidence 1 |
| not-an-account | arn:aws:rds:eu-west-1:444455556666:db:billing | rds-instance | 11.9 | affected | evidence 2 |
| 777788889999 | arn:aws:rds:eu-west-1:777788889999:db:reports | rds-instance | 11.9 | affected | evidence 3 |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 2
        assert len(result.dropped_rows) == 1
        assert result.dropped_rows[0]["reason"].startswith("account")
        assert any("dropped" in w for w in result.warnings)


class TestAllRowsBad:
    def test_every_row_invalid_is_hard_failure(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| bad-account-1 | not-an-arn | rds-instance | 11.9 | affected | evidence 1 |
| bad-account-2 | also-not-an-arn | rds-instance | 11.9 | affected | evidence 2 |
"""
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "every row failed validation" in result.error
        assert result.rows == []


class TestNoTableAtAll:
    def test_no_heading_is_hard_failure(self):
        markdown = "## Summary\n\nNo impact detected. All resources are current.\n"
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "no '## Affected resources' section" in result.error
        assert result.raw == markdown

    def test_none_input_is_hard_failure(self):
        result = parse_affected_resources(None)
        assert result.error is not None

    def test_empty_string_input_is_hard_failure(self):
        result = parse_affected_resources("")
        assert result.error is not None

    def test_whitespace_only_input_is_hard_failure(self):
        result = parse_affected_resources("   \n\n  ")
        assert result.error is not None


class TestTablePresentButEmpty:
    def test_heading_with_no_table_below_is_hard_failure(self):
        markdown = "## Affected resources\n\nNo resources found in this account.\n"
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "no markdown table found" in result.error

    def test_header_row_only_no_data_rows_is_hard_failure(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
"""
        result = parse_affected_resources(markdown)
        assert result.error is not None
        assert "zero data rows" in result.error


class TestNonArnResourceArn:
    def test_non_arn_resource_arn_dropped(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | my-cluster-not-an-arn | eks-cluster | 1.25 | affected | evidence |
| 444455556666 | arn:aws:eks:eu-west-1:444455556666:cluster/prod | eks-cluster | 1.25 | affected | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 1
        assert len(result.dropped_rows) == 1
        assert "resource_arn" in result.dropped_rows[0]["reason"]


class TestElevenDigitAccount:
    def test_eleven_digit_account_dropped(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 11112222333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | evidence |
| 444455556666 | arn:aws:rds:eu-west-1:444455556666:db:billing | rds-instance | 11.9 | affected | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 1
        assert "12-digit" in result.dropped_rows[0]["reason"]


class TestInaccessibleRow:
    """E1.5 cause 2 / design §3.3 access-denied detection."""

    def test_inaccessible_row_for_one_account_others_still_enriched(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | engine detail |
| 444455556666 | arn:aws:rds:eu-west-1:444455556666:db:billing | rds-instance | unknown | inaccessible | AccessDenied: no association for 444455556666 |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 2
        statuses = {r["account"]: r["status"] for r in result.rows}
        assert statuses["111122223333"] == "affected"
        assert statuses["444455556666"] == "inaccessible"


class TestDependentsVerifiedMarker:
    """req §1a dependent-locus marker, design §3.3."""

    def test_dependents_verified_yes_sets_flag_true(self):
        markdown = _WELL_FORMED.replace(
            "## Recommended Actions", "## Dependents verified: yes\n\n## Recommended Actions"
        )
        result = parse_affected_resources(markdown)
        assert result.dependents_verified is True

    def test_dependents_verified_no_sets_flag_false(self):
        markdown = _WELL_FORMED.replace(
            "## Recommended Actions", "## Dependents verified: no\n\n## Recommended Actions"
        )
        result = parse_affected_resources(markdown)
        assert result.dependents_verified is False

    def test_dependents_verified_absent_sets_flag_false(self):
        result = parse_affected_resources(_WELL_FORMED)
        assert result.dependents_verified is False

    def test_dependents_verified_any_other_value_sets_flag_false(self):
        markdown = _WELL_FORMED.replace(
            "## Recommended Actions",
            "## Dependents verified: maybe\n\n## Recommended Actions",
        )
        result = parse_affected_resources(markdown)
        assert result.dependents_verified is False

    def test_as_lookups_carries_dependents_verified_true_onto_every_row(self):
        markdown = _WELL_FORMED.replace(
            "## Recommended Actions", "## Dependents verified: yes\n\n## Recommended Actions"
        )
        result = parse_affected_resources(markdown)
        lookups = result.as_lookups()
        assert all(lu.get("dependents_verified") is True for lu in lookups)

    def test_as_lookups_omits_dependents_verified_key_when_false(self):
        result = parse_affected_resources(_WELL_FORMED)
        lookups = result.as_lookups()
        assert all("dependents_verified" not in lu for lu in lookups)


class TestUnrecognisedStatusVocabulary:
    def test_unknown_status_value_maps_to_unknown_with_warning(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | PARTIALLY_AFFECTED | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert result.rows[0]["status"] == "unknown"
        assert any("unrecognised status" in w for w in result.warnings)

    def test_status_case_insensitive(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | AT_RISK | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.rows[0]["status"] == "at_risk"
        assert result.warnings == []


class TestSeparatorRowVariants:
    def test_separator_row_with_colons_alignment_handled(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|:---|:---:|---:|---|---|---|
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 1

    def test_missing_separator_row_still_parses(self):
        """A real agent may omit the '|---|---|' separator entirely."""
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
| 111122223333 | arn:aws:rds:eu-west-1:111122223333:db:orders | rds-instance | 11.9 | affected | evidence |
"""
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 1


class TestSectionExtraction:
    def test_stops_at_next_heading(self):
        """A well-formed table followed by another section must not bleed
        that section's content into the parsed rows."""
        markdown = _WELL_FORMED
        result = parse_affected_resources(markdown)
        assert all("Upgrade before the deadline" not in str(r) for r in result.rows)

    def test_heading_case_insensitive(self):
        markdown = _WELL_FORMED.replace("## Affected resources", "## AFFECTED RESOURCES")
        result = parse_affected_resources(markdown)
        assert result.error is None
        assert len(result.rows) == 3


class TestPropertyRowConservation:
    """Property test (task 1's explicit requirement): for any valid table,
    len(rows) + len(dropped_rows) == data rows in input."""

    @given(
        st.lists(
            st.tuples(
                st.text(min_size=0, max_size=15),  # account (may or may not be valid)
                st.text(min_size=0, max_size=30),  # resource_arn (may or may not be valid)
                st.text(min_size=1, max_size=15).filter(lambda s: "|" not in s),
                st.text(min_size=1, max_size=10).filter(lambda s: "|" not in s),
                st.sampled_from(["affected", "at_risk", "not_affected", "inaccessible", "unknown", "bogus"]),
                st.text(min_size=1, max_size=20).filter(lambda s: "|" not in s and "\n" not in s),
            ),
            min_size=1,
            max_size=8,
        )
    )
    def test_row_conservation(self, rows_data):
        # Sanitize account/resource_arn to avoid '|' or newlines corrupting
        # the table structure itself (that's a separate, already-covered
        # malformed-input case, not what this property targets).
        safe_rows = [
            (
                a.replace("|", "").replace("\n", "")[:15],
                r.replace("|", "").replace("\n", "")[:30] or "x",
                rt,
                cv,
                status,
                ev,
            )
            for a, r, rt, cv, status, ev in rows_data
        ]
        lines = [
            "## Affected resources",
            "",
            "| account | resource_arn | resource_type | current_version | status | evidence |",
            "|---|---|---|---|---|---|",
        ]
        for a, r, rt, cv, status, ev in safe_rows:
            lines.append(f"| {a} | {r} | {rt} | {cv} | {status} | {ev} |")
        markdown = "\n".join(lines)

        result = parse_affected_resources(markdown)

        if result.error is not None:
            # Hard failure only legitimately occurs when every row was
            # invalid — confirm that's genuinely true rather than trusting
            # the error blindly.
            assert result.rows == []
            every_row_was_actually_invalid = all(
                not (_ACCOUNT_RE_LOCAL(a) and r.startswith("arn:")) for a, r, *_ in safe_rows
            )
            assert every_row_was_actually_invalid
        else:
            assert len(result.rows) + len(result.dropped_rows) == len(safe_rows)


def _ACCOUNT_RE_LOCAL(value: str) -> bool:
    import re as _re
    return bool(_re.fullmatch(r"\d{12}", value))
