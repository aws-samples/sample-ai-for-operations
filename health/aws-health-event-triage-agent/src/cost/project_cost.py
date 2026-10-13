# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Cost projection — precision function for the Phase 3 ProjectCost workflow
step (src/inventory/handler.py). Uses real Price List API pricing and
resource facts from the impact inventory (design §3.4.1). Never calls the
LLM; never an agent tool.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from src.cost.vcpu_map import map_instance_class_to_vcpu

HOURS_PER_MONTH = 730

# Services this Build phase can project; unknowns return {"unknown": True, ...}
_SUPPORTED_SERVICES = {"EKS", "RDS", "AURORA"}


def _hours_to_deadline(deadline: str | None, now: date | None = None) -> int:
    """Return whole hours from now to the deadline date, or 0 if past/None."""
    if not deadline:
        return 0
    ref = now or datetime.now(timezone.utc).date()
    try:
        dl = date.fromisoformat(deadline[:10])
    except ValueError:
        return 0
    delta_days = (dl - ref).days
    return max(delta_days, 0) * 24


def _project_eks_resource(resource: dict, pricing_lookup, horizon_hours: int) -> dict | None:
    """Project cost for a single EKS cluster resource.

    Increment = extended-support hourly rate - standard hourly rate.
    """
    standard = pricing_lookup("AmazonEKS", "ClusterUsage")
    extended = pricing_lookup("AmazonEKS", "ExtendedSupportUsage")

    if standard.get("unitPrice") is None or extended.get("unitPrice") is None:
        return None

    increment_per_hour = extended["unitPrice"] - standard["unitPrice"]
    monthly_increment = round(increment_per_hour * HOURS_PER_MONTH, 2)
    to_deadline = round(increment_per_hour * horizon_hours, 2)
    twelve_month = round(increment_per_hour * HOURS_PER_MONTH * 12, 2)

    return {
        "resource_id": resource.get("cluster_name", resource.get("identifier", "unknown")),
        "account_id": resource.get("account_id", ""),
        "service": "EKS",
        "monthly_increment": monthly_increment,
        "to_deadline": to_deadline,
        "twelve_month": twelve_month,
        "confidence": "list_price" if extended["source"] == "pricelist" else "usage_based",
    }


def _project_rds_resource(resource: dict, pricing_lookup, horizon_hours: int) -> dict | None:
    """Project cost for a single RDS/Aurora instance resource.

    Uses vCPU count × per-vCPU-hour extended support rate. Multi-AZ doubles
    the vCPU count (standby replica also incurs the surcharge).
    """
    instance_class = resource.get("instance_class", "")
    vcpu = map_instance_class_to_vcpu(instance_class)
    if vcpu is None:
        return None

    multi_az_multiplier = 2 if resource.get("multi_az") else 1
    effective_vcpu = vcpu * multi_az_multiplier

    year1_2 = pricing_lookup("AmazonRDS", "ExtendedSupportYear1-2")
    if year1_2.get("unitPrice") is None:
        return None

    rate = year1_2["unitPrice"]
    monthly_increment = round(rate * effective_vcpu * HOURS_PER_MONTH, 2)
    to_deadline = round(rate * effective_vcpu * horizon_hours, 2)
    twelve_month = round(rate * effective_vcpu * HOURS_PER_MONTH * 12, 2)

    return {
        "resource_id": resource.get("identifier", "unknown"),
        "account_id": resource.get("account_id", ""),
        "service": "RDS",
        "monthly_increment": monthly_increment,
        "to_deadline": to_deadline,
        "twelve_month": twelve_month,
        "confidence": "list_price" if year1_2["source"] == "pricelist" else "usage_based",
    }


def project_cost(
    inventory: dict,
    pricing_lookup=None,
    horizon: dict | None = None,
) -> dict:
    """Project organization-wide and per-account cost from an impact inventory.

    Pure precision function — never calls the LLM. Uses real pricing (via the
    injected pricing_lookup callable) and resource facts from the inventory
    (design §3.4.1). Returns {"unknown": True, "reason": ...} when no resource
    in the inventory can be projected.

    Args:
        inventory: The ImpactInventory dict from build_impact_inventory
            (must have a 'resources' list; each resource dict should include
            'service' or fields identifying EKS vs RDS, plus 'account_id').
        pricing_lookup: Optional callable(service, dimension) -> pricing dict
            (defaults to get_pricing bound to region from config). Injectable
            for tests.
        horizon: Optional dict with 'deadline' (ISO date) and 'now' (date) for
            the "to_deadline" projection window.

    Returns:
        CostProjection dict with keys: per_resource, per_account, org_total,
        monthly_increment, to_deadline, twelve_month, assumptions, confidence.
        Or {"unknown": True, "reason": str} when nothing is projectable.
    """
    if pricing_lookup is None:
        from src.cost.pricing import get_pricing as _get_pricing
        from src import config as _config
        def pricing_lookup(service, dimension):
            return _get_pricing(service, dimension, _config.AWS_REGION)

    resources = inventory.get("resources", [])
    if not resources:
        return {"unknown": True, "reason": "No resources in the impact inventory to project cost for."}

    horizon = horizon or {}
    deadline = horizon.get("deadline")
    now = horizon.get("now")
    horizon_hours = _hours_to_deadline(deadline, now)

    per_resource: list[dict] = []
    for resource in resources:
        # Heuristic service detection: EKS resources have cluster_name/version;
        # RDS resources have identifier/engine/instance_class.
        if "cluster_name" in resource or "fargate_profiles" in resource:
            projected = _project_eks_resource(resource, pricing_lookup, horizon_hours)
        elif "instance_class" in resource or "engine" in resource:
            projected = _project_rds_resource(resource, pricing_lookup, horizon_hours)
        else:
            projected = None

        if projected is not None:
            per_resource.append(projected)

    if not per_resource:
        return {
            "unknown": True,
            "reason": "No projectable resources found (unsupported service or missing pricing data).",
        }

    per_account: dict[str, dict] = {}
    for r in per_resource:
        acct = r["account_id"] or "unknown"
        bucket = per_account.setdefault(acct, {"monthly_increment": 0.0, "to_deadline": 0.0, "twelve_month": 0.0})
        bucket["monthly_increment"] = round(bucket["monthly_increment"] + r["monthly_increment"], 2)
        bucket["to_deadline"] = round(bucket["to_deadline"] + r["to_deadline"], 2)
        bucket["twelve_month"] = round(bucket["twelve_month"] + r["twelve_month"], 2)

    org_monthly = round(sum(b["monthly_increment"] for b in per_account.values()), 2)
    org_to_deadline = round(sum(b["to_deadline"] for b in per_account.values()), 2)
    org_twelve_month = round(sum(b["twelve_month"] for b in per_account.values()), 2)

    confidences = {r["confidence"] for r in per_resource}
    if confidences == {"list_price"}:
        overall_confidence = "list_price"
    elif "unknown" in confidences:
        overall_confidence = "unknown"
    else:
        overall_confidence = "usage_based"

    unprojected_count = len(resources) - len(per_resource)
    assumptions = [
        "24x7 usage (730 hours/month)",
        "No customer-specific negotiated discounts or Savings Plans applied — list price only",
        "USD currency",
        "No manual upgrade performed before the deadline",
    ]
    if unprojected_count > 0:
        assumptions.append(
            f"{unprojected_count} resource(s) excluded from the total — service or pricing data unavailable"
        )

    return {
        "unknown": False,
        "per_resource": per_resource,
        "per_account": per_account,
        "org_total": {
            "monthly_increment": org_monthly,
            "to_deadline": org_to_deadline,
            "twelve_month": org_twelve_month,
        },
        "monthly_increment": org_monthly,
        "to_deadline": org_to_deadline,
        "twelve_month": org_twelve_month,
        "assumptions": assumptions,
        "confidence": overall_confidence,
    }
