# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: reconciliation rung 1, the in-data leg check.

On each NAT interface the translated leg (internet side) and the untranslated leg (workload side) carry the
same bytes, and every record carries a NAT address. The check compares the translated leg with everything
else on the interface (untranslated plus unmatched records). Well below 1: records with no known NAT address,
so a NAT address is missing from the filter. Well above 1: internet-side traffic with no workload leg
(unsolicited inbound to the NAT address, or a non-NAT address in the filter).
"""

from __future__ import annotations

from .nat_scope import nat_scope
from .reconcile import DIAGNOSES, diagnose_ratio


def nat_leg_check(
    rows: list[dict], nat_addresses: list[str], nat_interface_ids: list[str], tolerance: float = 0.05
) -> dict:
    scoped = nat_scope(rows, nat_addresses, nat_interface_ids)

    def entry(t: int, u: int, x: int) -> dict:
        other = u + x
        ratio = round(t / other, 6) if other else None
        d = diagnose_ratio(ratio, tolerance, both_legs_possible=False)
        return {
            "translated_bytes": t,
            "untranslated_bytes": u,
            "unmatched_bytes": x,
            "ratio": ratio,
            "diagnosis": d,
            "explanation": DIAGNOSES[d],
        }

    per = {
        i: {
            **entry(v["translated_bytes"], v["untranslated_bytes"], v["unmatched_bytes"]),
            "unsolicited_bytes": v.get("unsolicited_bytes", 0),
        }
        for i, v in scoped["by_interface"].items()
    }
    return {
        "overall": {
            **entry(
                scoped["translated"]["total_bytes"],
                scoped["untranslated"]["total_bytes"],
                scoped["unmatched"]["total_bytes"],
            ),
            # internet-side records with no translation (scans of the NAT address): reported, never compared
            "unsolicited_bytes": scoped["unsolicited"]["total_bytes"],
        },
        "by_interface": per,
        "tolerance": tolerance,
        "nat_addresses_used": scoped["nat_addresses"],
    }
