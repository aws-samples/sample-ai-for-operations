# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: published rates times observed volumes, as context for architecture options.

This is evidence, not a bill and not a recommendation. Options are listed side by side without ranking.
Rates come from ``get_prices`` (or the fixture); nothing is hard-coded here.
"""

from __future__ import annotations

GB = 1_000_000_000


def _gb(b: int) -> float:
    return round(b / GB, 3)


def _line(label: str, bytes_: int, rate: float | None, rate_name: str) -> dict:
    cost = None if rate is None else round(bytes_ / GB * rate, 2)
    return {
        "item": label,
        "bytes": bytes_,
        "gb": _gb(bytes_),
        "rate_per_gb": rate,
        "rate_name": rate_name,
        "indicative_cost": cost,
    }


def price_context(volumes: dict[str, int], rates: dict, evidence: dict | None = None) -> dict:
    """``volumes``: path-class bytes for the window (counted once). ``evidence`` carries the findings
    that justify each option: ``{"gateway_route_bytes", "interface_endpoint_bytes", "cross_region_bytes",
    "internet_nat_by_bucket": {bucket: bytes}}``.
    """
    evidence = evidence or {}
    nat = rates.get("nat_processing_per_gb")
    lines = [
        _line(
            "internet via NAT gateway (processing)",
            volumes.get("internet-nat", 0),
            nat,
            "nat_processing_per_gb",
        ),
        _line(
            "gateway endpoint",
            volumes.get("gateway-endpoint", 0),
            rates.get("gateway_endpoint_per_gb"),
            "gateway_endpoint_per_gb",
        ),
        _line(
            "interface endpoint (processing)",
            volumes.get("interface-endpoint", 0),
            rates.get("interface_endpoint_per_gb"),
            "interface_endpoint_per_gb",
        ),
        _line(
            "Transit Gateway (processing)",
            volumes.get("transit-gateway", 0),
            rates.get("transit_gateway_per_gb"),
            "transit_gateway_per_gb",
        ),
        _line(
            "cross-AZ within VPC (each direction billed)",
            volumes.get("intra-vpc-cross-az", 0),
            rates.get("inter_az_per_gb"),
            "inter_az_per_gb",
        ),
        _line(
            "cross-Region",
            volumes.get("cross-region", 0),
            rates.get("inter_region_per_gb"),
            "inter_region_per_gb",
        ),
    ]
    options = []
    gw = evidence.get("gateway_route_bytes", 0)
    if gw:
        options.append(
            {
                "option": "Add or associate a gateway endpoint for S3 and DynamoDB",
                "justifying_flows_bytes": gw,
                "current_rate": {"name": "nat_processing_per_gb", "per_gb": nat},
                "alternative_rate": {
                    "name": "gateway_endpoint_per_gb",
                    "per_gb": rates.get("gateway_endpoint_per_gb"),
                },
                "processing_charge_difference": _diff(gw, nat, rates.get("gateway_endpoint_per_gb")),
                "would_change": "the path and the per-GB processing charge for this volume",
                "would_not_change": "traffic to other Regions, other services, or anything that is not S3 or DynamoDB",
            }
        )
    ie = evidence.get("interface_endpoint_bytes", 0)
    if ie:
        options.append(
            {
                "option": "Make clients use the existing interface endpoint (private DNS, subnet placement, SDK endpoint settings)",
                "justifying_flows_bytes": ie,
                "current_rate": {"name": "nat_processing_per_gb", "per_gb": nat},
                "alternative_rate": {
                    "name": "interface_endpoint_per_gb",
                    "per_gb": rates.get("interface_endpoint_per_gb"),
                },
                "processing_charge_difference": _diff(ie, nat, rates.get("interface_endpoint_per_gb")),
                "would_change": "the path for this service's traffic",
                "would_not_change": "endpoint hourly charges, which exist whether or not it is used",
            }
        )
    xr = evidence.get("cross_region_bytes", 0)
    if xr:
        options.append(
            {
                "option": "Reach the other-Region bucket or table through its own Region, or replicate it locally",
                "justifying_flows_bytes": xr,
                "current_rate": {"name": "nat_processing_per_gb", "per_gb": nat},
                "alternative_rate": {
                    "name": "inter_region_per_gb",
                    "per_gb": rates.get("inter_region_per_gb"),
                },
                "would_change": "where the processing and transfer charges arise",
                "would_not_change": "the need to move the data between Regions",
            }
        )
    by_bucket = evidence.get("internet_nat_by_bucket", {})
    if by_bucket:
        options.append(
            {
                "option": "Egress filtering or central inspection for internet-bound traffic",
                "justifying_flows_bytes": sum(by_bucket.values()),
                "volume_by_destination_bucket": dict(
                    sorted(by_bucket.items(), key=lambda kv: (-kv[1], kv[0]))
                ),
                "current_rate": {"name": "nat_processing_per_gb", "per_gb": nat},
                "alternative_rate": {
                    "name": "transit_gateway_per_gb",
                    "per_gb": rates.get("transit_gateway_per_gb"),
                },
                "would_change": "where internet-bound traffic is inspected and how many hops it takes",
                "would_not_change": "traffic that never leaves private paths (endpoints, VPC-to-VPC)",
            }
        )
    xaz = volumes.get("intra-vpc-cross-az", 0)
    if xaz:
        options.append(
            {
                "option": "Place chatty client and server pairs in the same Availability Zone",
                "justifying_flows_bytes": xaz,
                "current_rate": {"name": "inter_az_per_gb", "per_gb": rates.get("inter_az_per_gb")},
                "alternative_rate": {"name": "same_az", "per_gb": 0.0},
                "would_change": "cross-AZ transfer for the pairs that move",
                "would_not_change": "resilience requirements that need more than one Availability Zone",
            }
        )
    return {
        "region": rates.get("region"),
        "rate_source": rates.get("source"),
        "lines": lines,
        "options": options,
        "note": "Indicative figures from published rates; they are not an invoice and no option is ranked.",
    }


def _diff(bytes_: int, current: float | None, alt: float | None) -> float | None:
    if current is None or alt is None:
        return None
    return round(bytes_ / GB * (current - alt), 2)
