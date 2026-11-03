# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 2 for Transit Gateway — prefix leak against the isolation matrix (tasks.md 2.2, design.md D§4.2).

Intent: `tgw_isolation` in the intent file. Keys and members are route-table IDs or values of the
Environment tag (case-insensitive). A table may always see itself; anything not listed is not allowed.

- A table is governed when its tag value (first) or its ID is a matrix key. Tables the matrix does
  not name are not evaluated by this check (the matrix is an opt-in list, not a default deny).
- A route's source domain is its next-hop attachment's tag value; for an untagged attachment, the
  route table it is associated with (its tag value and ID). A source with neither cannot be placed
  in a domain and is skipped (check 1 already reports the missing tags).
- Blackhole routes are excluded (check 3 owns them). One finding per (table, prefix, source attachment).
"""

from __future__ import annotations

from typing import Any

from drift_core.checks import EvaluationContext
from drift_core.finding import Finding, canonical_prefix
from drift_core.snapshot import tag_value


def _table_keys(table: dict[str, Any], tag_key: str) -> list[str]:
    keys = []
    value = tag_value(table.get("tags") or {}, tag_key)
    if value:
        keys.append(value.lower())
    keys.append(table["route_table_id"].lower())
    return keys


def _source_keys(attachment: dict[str, Any] | None, tables: dict[str, dict[str, Any]], tag_key: str) -> set[str]:
    if not attachment:
        return set()
    value = tag_value(attachment.get("tags") or {}, tag_key)
    if value:
        return {value.lower()}
    assoc = attachment.get("association") or {}
    table = tables.get(assoc.get("route_table_id", ""))
    return set(_table_keys(table, tag_key)) if table else set()


def run(ctx: EvaluationContext) -> list[Finding]:
    matrix: dict[str, list[str]] = (ctx.intent or {}).get("tgw_isolation") or {}
    if not matrix:
        return []
    key = ctx.environment_tag_key
    findings: list[Finding] = []
    for region, snap in sorted(ctx.regions.items()):
        attachments = {a["attachment_id"]: a for a in snap.get("attachments") or []}
        tables = {t["route_table_id"]: t for t in snap.get("route_tables") or []}
        for table in snap.get("route_tables") or []:
            keys = _table_keys(table, key)
            matrix_key = next((k for k in keys if k in matrix), None)
            if matrix_key is None:
                continue
            allowed = set(matrix[matrix_key]) | set(keys)
            rtb = table["route_table_id"]
            for route in table.get("routes") or []:
                if (route.get("state") or "").lower() != "active":
                    continue
                prefix = canonical_prefix(route.get("prefix", ""))
                for dest in route.get("attachments") or []:
                    aid = dest.get("attachment_id", "")
                    sources = _source_keys(attachments.get(aid), tables, key)
                    if not sources or sources & allowed:
                        continue
                    findings.append(Finding(
                        check="check2", kind="tgw-prefix-leak", severity="drift", region=region,
                        identity=(rtb, prefix, aid),
                        expected={"allowed": sorted(allowed)}, observed={"source_domain": sorted(sources)},
                        context={"platform": "tgw", "tgw_id": table.get("tgw_id"), "route_table_id": rtb,
                                 "matrix_key": matrix_key, "prefix": prefix, "source_attachment": aid,
                                 "source_resource_type": dest.get("resource_type"), "route_type": route.get("type")},
                        message=(f"Route table {rtb} ('{matrix_key}') has route {prefix} via {aid} "
                                 f"(domain {', '.join(sorted(sources))}), which the isolation matrix does not "
                                 "allow it to see.")))
    return findings
