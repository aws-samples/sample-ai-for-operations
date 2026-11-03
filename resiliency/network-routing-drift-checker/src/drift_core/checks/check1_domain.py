# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 1 — attachment in the wrong routing domain (design.md D§4.1, requirements §5, §6)."""

from __future__ import annotations

from drift_core.checks import EvaluationContext
from drift_core.checks.cloudwan_policy import expected_segment
from drift_core.finding import Finding
from drift_core.snapshot import tag_value

_CLOUDWAN_EVALUATED_STATES = {"AVAILABLE", "UPDATING"}
_TGW_EVALUATED_STATES = {"available", "modifying"}


def check_cloudwan(ctx: EvaluationContext) -> list[Finding]:
    cw = ctx.cloudwan
    if not cw:
        return []
    findings: list[Finding] = []
    policy = cw.get("policy") or {}
    for att in cw.get("attachments") or []:
        if (att.get("state") or "").upper() not in _CLOUDWAN_EVALUATED_STATES:
            continue
        aid = att["attachment_id"]
        common = dict(region=att.get("edge_location") or "global", identity=(aid,))
        context = {"attachment_type": att.get("attachment_type"), "tags": att.get("tags") or {},
                   "core_network_id": cw.get("core_network_id")}
        if att.get("proposed_segment_change"):
            findings.append(Finding(check="informational", kind="cloudwan-segment-change-pending",
                                    severity="informational", context=context,
                                    message=f"Attachment {aid} has a pending segment change awaiting acceptance.",
                                    **common))
            continue
        status, value = expected_segment(policy, att)
        actual = att.get("segment_name")
        if status == "segment":
            if (actual or "").lower() != str(value).lower():
                findings.append(Finding(
                    check="check1", kind="cloudwan-wrong-segment", severity="drift",
                    expected={"segment": value}, observed={"segment": actual}, context=context,
                    message=f"Attachment {aid} is in segment '{actual}' but the policy assigns '{value}'.",
                    **common))
        elif status == "no-match":
            findings.append(Finding(check="informational", kind="cloudwan-no-matching-rule",
                                    severity="informational", observed={"segment": actual}, context=context,
                                    message=f"Attachment {aid} matches no attachment-policy rule.", **common))
        elif status == "unsupported":
            findings.append(Finding(check="system", kind="cloudwan-rule-not-evaluated", severity="system",
                                    context={**context, "rule_number": value},
                                    message=(f"Attachment {aid}: policy rule {value} uses a construct this checker "
                                             "does not evaluate; segment not verified."), **common))
        # status == "nfg": network function groups are out of scope for v1 (requirements §13 item 8).
    return findings


def check_tgw(ctx: EvaluationContext) -> list[Finding]:
    findings: list[Finding] = []
    key = ctx.environment_tag_key
    for region, snap in sorted(ctx.regions.items()):
        tables = {rt["route_table_id"]: rt for rt in snap.get("route_tables") or []}
        untagged_tables: dict[str, list[str]] = {}
        for att in snap.get("attachments") or []:
            assoc = att.get("association") or {}
            if (assoc.get("state") or "").lower() != "associated":
                continue
            if (att.get("state") or "").lower() not in _TGW_EVALUATED_STATES:
                continue
            aid, rtb_id = att["attachment_id"], assoc["route_table_id"]
            table = tables.get(rtb_id)
            table_env = tag_value(table.get("tags") or {}, key) if table else None
            att_env = tag_value(att.get("tags") or {}, key)
            context = {"tgw_id": att.get("tgw_id"), "route_table_id": rtb_id,
                       "resource_type": att.get("resource_type"), "resource_id": att.get("resource_id"),
                       "tag_key": key}
            if table_env is None:
                untagged_tables.setdefault(rtb_id, []).append(aid)
                continue
            if att_env is None:
                findings.append(Finding(
                    check="informational", kind="untagged-attachment", severity="informational", region=region,
                    identity=(aid,), context=context,
                    message=f"Attachment {aid} has no '{key}' tag; its routing domain cannot be verified."))
                continue
            if att_env.lower() != table_env.lower():
                findings.append(Finding(
                    check="check1", kind="tgw-wrong-route-table", severity="drift", region=region,
                    identity=(aid,), expected={key: att_env}, observed={"route_table": rtb_id, key: table_env},
                    context=context,
                    message=(f"Attachment {aid} ({key}={att_env}) is associated with route table {rtb_id} "
                             f"({key}={table_env}).")))
        for rtb_id, attachment_ids in sorted(untagged_tables.items()):
            # One finding per untagged table (requirements §6). The ID is keyed on
            # (kind, region, route-table-id) only; the attachment list is in `observed` so that
            # adding or removing an attachment changes payload_hash (KNOWN, changed) but not the ID.
            findings.append(Finding(
                check="informational", kind="untagged-route-table", severity="informational", region=region,
                identity=(rtb_id,), observed={"attachments": sorted(attachment_ids)},
                context={"route_table_id": rtb_id, "tag_key": key},
                message=(f"Route table {rtb_id} has no '{key}' tag; {len(attachment_ids)} associated "
                         "attachment(s) not verified.")))
    return findings


def run(ctx: EvaluationContext) -> list[Finding]:
    return check_cloudwan(ctx) + check_tgw(ctx)
