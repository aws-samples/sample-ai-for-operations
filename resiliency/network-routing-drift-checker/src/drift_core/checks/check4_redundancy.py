# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 4 — Direct Connect redundancy pairs (tasks.md 2.3, design.md D§4.4).

Per declared pair (both members are VIF IDs):
- member not found         -> redundancy-member-missing (drift). If a Region was not evaluated this
                              run the VIF may simply not have been collected -> redundancy-member-unverified
                              (system), never drift.
- VIF not `available`      -> redundancy-member-down
- VIF available, a BGP peer not `up` -> redundancy-bgp-down, one per peer. Not emitted for a VIF that is
                              already down: its peers are down by consequence, and member-down says it.
- both members unhealthy   -> redundancy-pair-down, in addition to the member findings.
A fully healthy pair produces nothing.
"""

from __future__ import annotations

from drift_core.checks import EvaluationContext
from drift_core.checks.resources import vif_health, vifs
from drift_core.finding import Finding


def run(ctx: EvaluationContext) -> list[Finding]:
    pairs = (ctx.intent or {}).get("dx_redundancy_pairs") or []
    if not pairs:
        return []
    known = vifs(ctx)
    findings: list[Finding] = []
    for pair in pairs:
        name, members = pair["name"], pair["members"]
        unhealthy, verified = 0, True
        for member in members:
            hit = known.get(member.lower())
            common = {"context": {"pair": name, "members": members, "vif_id": member}}
            if hit is None:
                unhealthy += 1
                if ctx.regions_not_evaluated:
                    verified = False
                    findings.append(Finding(
                        check="system", kind="redundancy-member-unverified", severity="system", region="global",
                        identity=(name, member), message=(
                            f"Redundancy pair '{name}': VIF {member} was not found, but Regions "
                            f"{', '.join(sorted(ctx.regions_not_evaluated))} were not evaluated."), **common))
                else:
                    findings.append(Finding(
                        check="check4", kind="redundancy-member-missing", severity="drift", region="global",
                        identity=(name, member), expected={"vif": "exists"}, observed={"vif": "not found"},
                        message=f"Redundancy pair '{name}': VIF {member} does not exist in any evaluated Region.",
                        **common))
                continue
            region, vif = hit
            healthy, detail = vif_health(vif)
            if vif.get("state") != "available":
                unhealthy += 1
                findings.append(Finding(
                    check="check4", kind="redundancy-member-down", severity="drift", region=region,
                    identity=(member,), expected={"state": "available"}, observed={"state": vif.get("state")},
                    message=f"Redundancy pair '{name}': VIF {member} is {vif.get('state')}.", **common))
                continue
            for peer in vif.get("bgp_peers") or []:
                if peer.get("bgp_status") != "up":
                    findings.append(Finding(
                        check="check4", kind="redundancy-bgp-down", severity="drift", region=region,
                        identity=(member, peer.get("peer_id") or peer.get("address_family") or "peer"),
                        expected={"bgp_status": "up"}, observed={"bgp_status": peer.get("bgp_status")},
                        context={**common["context"], "address_family": peer.get("address_family")},
                        message=(f"Redundancy pair '{name}': BGP peer {peer.get('peer_id')} "
                                 f"({peer.get('address_family')}) on VIF {member} is {peer.get('bgp_status')}.")))
            if not healthy:
                unhealthy += 1
        if unhealthy == len(members) and verified:
            findings.append(Finding(
                check="check4", kind="redundancy-pair-down", severity="drift", region="global", identity=(name,),
                expected={"healthy_members": ">= 1"}, observed={"healthy_members": 0},
                context={"pair": name, "members": members},
                message=f"Redundancy pair '{name}': both members are down or missing; there is no working path."))
    return findings
