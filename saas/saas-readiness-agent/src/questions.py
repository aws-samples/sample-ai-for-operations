# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# ruff: noqa: E501

"""Canonical adaptive question catalog for the SaaS Readiness Agent.

Customers answer practical, persona-oriented AQ questions in their own words.
The agent classifies each answer into one or more internal BQ signals. Only the
closed BQ options below affect deterministic scoring; raw prose never does.
"""

from __future__ import annotations

from typing import Any

QUESTION_CATALOG_VERSION = 2

QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "AQ-001",
        "phase": 1,
        "priority": "essential",
        "persona": "Product Manager or Founder",
        "prompt": (
            "What does your product do, who buys and uses it, how many customer "
            "organizations use it today, and what must it support next?"
        ),
        "probes": [
            "Are customers mainly small businesses, mid-market, enterprise, or developers?",
            "What is the most important milestone or pressure in the next 6–12 months?",
        ],
        "controls": ["SBR-01", "SBR-06"],
        "scoring_ids": {
            "BQ-005": {
                "label": "business stage",
                "options": ["pre_launch", "early_customers", "scaling", "mature", "unknown"],
            },
            "BQ-006": {
                "label": "target segment",
                "options": ["smb", "mid_market", "enterprise", "developers", "mixed", "unknown"],
            },
            "BQ-013": {
                "label": "growth pressure",
                "options": [
                    "onboarding",
                    "tenant_scale",
                    "cost_margin",
                    "compliance_residency",
                    "reliability",
                    "enterprise_requirements",
                    "none_stated",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": (
            "Capture business context and priority; do not infer technical maturity."
        ),
    },
    {
        "id": "AQ-002",
        "phase": 1,
        "priority": "essential",
        "persona": "Product Manager or Finance Lead",
        "prompt": (
            "How do you charge customers, what packages or tiers do you offer, and does "
            "measured usage affect what they pay?"
        ),
        "probes": [
            "Is pricing flat, per user, usage-based, tiered, or a combination?",
            "If usage grows, does billing or a tier change happen automatically?",
        ],
        "controls": ["SBR-02", "CAM-02", "CAM-04"],
        "scoring_ids": {
            "BQ-007": {
                "label": "pricing model",
                "options": [
                    "flat_subscription",
                    "seat_based",
                    "usage_based",
                    "tiered",
                    "hybrid",
                    "not_finalized",
                    "unknown",
                ],
            },
            "BQ-022": {
                "label": "commercial tiers",
                "options": ["implemented", "planned", "none", "unknown"],
            },
            "BQ-023": {
                "label": "metering requirement",
                "options": ["required_now", "planned", "not_required", "unknown"],
            },
        },
        "reasoning_hints": "Separate pricing intent from implemented metering and tier controls.",
    },
    {
        "id": "AQ-003",
        "phase": 1,
        "priority": "essential",
        "persona": "Founder, Product Manager, or Architect",
        "prompt": (
            "Do customers receive one centrally operated product and release process, "
            "or do they need separate versions, environments, and regular engineering attention?"
        ),
        "probes": [
            "Are customer-specific changes time-limited exceptions or long-lived forks?",
            "Who owns the end-to-end service experience?",
        ],
        "controls": ["SBR-05", "SBR-06", "DPA-03"],
        "scoring_ids": {
            "BQ-014": {
                "label": "service operating model",
                "options": [
                    "centralized_service",
                    "mostly_centralized",
                    "customer_specific_operations",
                    "hosted_software",
                    "unknown",
                ],
            }
        },
        "reasoning_hints": "Infer service behavior; never ask the customer to label itself SaaS.",
    },
    {
        "id": "AQ-004",
        "phase": 2,
        "priority": "essential",
        "persona": "Platform Engineering or Architect",
        "prompt": (
            "Think about two customers using the product today. Do they use the same "
            "application and databases, or does each customer have a separate setup?"
        ),
        "probes": [
            "When adding a customer, do you create an AWS account, application, or database?",
            "Which parts are shared and which are dedicated?",
        ],
        "controls": ["TAI-01"],
        "scoring_ids": {
            "BQ-001": {
                "label": "tenancy model",
                "options": ["pooled", "silo", "hybrid", "unknown"],
            }
        },
        "reasoning_hints": "The agent derives pooled, silo, or hybrid; the customer does not.",
    },
    {
        "id": "AQ-005",
        "phase": 2,
        "priority": "essential",
        "persona": "Platform Engineering or DevOps Lead",
        "prompt": (
            "Using your most recent customer as an example, how were they registered, "
            "set up, configured, and given access? Which steps required people?"
        ),
        "probes": [
            "How long did it take from agreement to first useful login?",
            "Is there one authoritative place that records customer status, plan, and configuration?",
        ],
        "controls": ["TLO-01", "TLO-02", "SBR-03"],
        "scoring_ids": {
            "BQ-004": {
                "label": "onboarding automation",
                "options": [
                    "fully_automated",
                    "partially_automated",
                    "manual",
                    "not_started",
                    "unknown",
                ],
            },
            "BQ-016": {
                "label": "tenant registry",
                "options": [
                    "complete_system",
                    "partial_system",
                    "manual_tracker",
                    "scattered",
                    "none",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Use a recent real onboarding, not an intended future process.",
    },
    {
        "id": "AQ-006",
        "phase": 2,
        "priority": "essential",
        "persona": "Platform Engineering or Product Operations",
        "prompt": (
            "How do you change a customer's plan or configuration, and what happens when "
            "a customer leaves and their access and data must be removed?"
        ),
        "probes": [
            "Are plan changes repeatable or does an engineer make one-off changes?",
            "Is retention and deletion automated, defined but manual, or handled case by case?",
        ],
        "controls": ["TLO-03", "TLO-04"],
        "scoring_ids": {
            "BQ-015": {
                "label": "offboarding process",
                "options": [
                    "automated_with_policy",
                    "defined_manual",
                    "ad_hoc",
                    "none",
                    "unknown",
                ],
            },
            "BQ-024": {
                "label": "tier and configuration changes",
                "options": [
                    "automated",
                    "repeatable_manual",
                    "ad_hoc",
                    "not_applicable",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Treat offboarding and plan changes as separate lifecycle signals.",
    },
    {
        "id": "AQ-007",
        "phase": 3,
        "priority": "essential",
        "persona": "Engineering Lead or Architect",
        "prompt": (
            "Trace one customer request from sign-in to data access and background work: "
            "where is customer identity established, how is it carried, and what enforces access?"
        ),
        "probes": [
            "Does customer identity reach APIs, services, queues, jobs, and database access?",
            "Is enforcement centralized or repeated independently in application code?",
        ],
        "controls": ["ITC-01", "ITC-02", "ITC-03", "TAI-02"],
        "scoring_ids": {
            "BQ-002": {
                "label": "tenant identity source",
                "options": [
                    "authoritative_signed_claim",
                    "authoritative_server_lookup",
                    "trusted_routing_mapping",
                    "caller_supplied_identifier",
                    "inconsistent",
                    "none",
                    "unknown",
                ],
            },
            "BQ-003": {
                "label": "tenant context propagation",
                "options": [
                    "all_sync_async_paths",
                    "sync_only",
                    "inconsistent",
                    "edge_only",
                    "none",
                    "unknown",
                ],
            },
            "BQ-026": {
                "label": "authorization enforcement",
                "options": [
                    "centralized_tenant_aware",
                    "distributed_tenant_checks",
                    "login_or_role_only",
                    "inconsistent",
                    "none",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Authentication alone is not tenant isolation.",
    },
    {
        "id": "AQ-008",
        "phase": 3,
        "priority": "essential",
        "persona": "Engineering Lead, Architect, or Security Lead",
        "prompt": (
            "Where does customer data live, what prevents one customer from reading "
            "another's data, and how are support or administrator paths restricted?"
        ),
        "probes": [
            "Is isolation enforced by accounts, databases, schemas, policies, or row filters?",
            "Can support tools or machine credentials bypass normal customer boundaries?",
        ],
        "controls": ["TAI-02", "TAI-03", "ITC-05"],
        "scoring_ids": {
            "BQ-017": {
                "label": "data isolation boundary",
                "options": [
                    "dedicated_account",
                    "dedicated_database",
                    "dedicated_schema",
                    "shared_enforced",
                    "mixed_enforced",
                    "shared_filter_only",
                    "none",
                    "unknown",
                ],
            },
            "BQ-027": {
                "label": "privileged access scope",
                "options": [
                    "tenant_scoped_audited",
                    "partially_scoped",
                    "broad_global",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "A tenant_id column or separate login is not proof of isolation.",
    },
    {
        "id": "AQ-009",
        "phase": 3,
        "priority": "extended",
        "persona": "Security, Compliance, or Product Lead",
        "prompt": (
            "Do current or planned customers require dedicated environments, data in a "
            "specific country, or certifications that change how the product must operate?"
        ),
        "probes": [
            "Are dedicated customers managed through the same release and operating process?",
            "Do you expect these requirements to grow in the next 12 months?",
        ],
        "controls": ["TAI-05", "TAI-06"],
        "scoring_ids": {
            "BQ-010": {
                "label": "special isolation requirements",
                "options": ["required_now", "planned", "none_known", "unknown"],
            },
            "BQ-025": {
                "label": "dedicated delivery model",
                "options": [
                    "same_managed_pipeline",
                    "separate_process",
                    "not_required",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Ask conditionally; do not turn this into a compliance audit.",
    },
    {
        "id": "AQ-010",
        "phase": 4,
        "priority": "essential",
        "persona": "DevOps, SRE, or Platform Lead",
        "prompt": (
            "Walk through the last production release: what was automated, how was it "
            "tested and rolled back, and did every customer remain on a governed version?"
        ),
        "probes": [
            "Does deployment use a pipeline, approvals, staged rollout, and automated rollback?",
            "Do any customers remain on long-lived older or custom versions?",
        ],
        "controls": ["DPA-02", "DPA-03", "DPA-05"],
        "scoring_ids": {
            "BQ-009": {
                "label": "release process",
                "options": [
                    "automated_with_rollback",
                    "pipeline_approval_and_rollback",
                    "pipeline_no_rollback",
                    "manual",
                    "unknown",
                ],
            },
            "BQ-018": {
                "label": "version model",
                "options": [
                    "same_version",
                    "time_bounded_release_waves",
                    "long_lived_exceptions",
                    "custom_forks",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Use the last real release rather than target-state claims.",
    },
    {
        "id": "AQ-011",
        "phase": 4,
        "priority": "essential",
        "persona": "SRE, DevOps, or Engineering Lead",
        "prompt": (
            "If one customer has a traffic spike or production problem, what limits the "
            "impact, and how quickly can you identify and communicate who is affected?"
        ),
        "probes": [
            "Are there per-customer limits, alerts, logs, metrics, or traces?",
            "Can operators see customer health centrally or must they inspect services separately?",
        ],
        "controls": [
            "TAI-04",
            "ITC-04",
            "OOR-01",
            "OOR-02",
            "OOR-03",
            "OOR-04",
            "OOR-05",
        ],
        "scoring_ids": {
            "BQ-008": {
                "label": "noisy-neighbour controls",
                "options": [
                    "automatic_per_tenant",
                    "partial_limits",
                    "manual_response",
                    "none",
                    "not_applicable_no_shared_resources",
                    "unknown",
                ],
            },
            "BQ-011": {
                "label": "tenant-aware operations",
                "options": [
                    "tenant_logs_metrics_traces_and_alerts",
                    "some_tenant_signals",
                    "service_or_infrastructure_only",
                    "none",
                    "no_production_operations",
                    "unknown",
                ],
            },
            "BQ-019": {
                "label": "central operational view",
                "options": ["centralized", "fragmented", "none", "unknown"],
            },
        },
        "reasoning_hints": "Separate prevention, detection, diagnosis, and customer impact.",
    },
    {
        "id": "AQ-012",
        "phase": 5,
        "priority": "essential",
        "persona": "Finance Lead or Engineering Lead",
        "prompt": (
            "Can you estimate what it costs to serve an individual customer, and would "
            "you know if one customer's consumption threatened margin or other customers?"
        ),
        "probes": [
            "Do accounts, tags, telemetry, or another model allocate dedicated and shared costs?",
            "How often is cost-per-customer reviewed and acted on?",
        ],
        "controls": ["CAM-01", "CAM-03", "CAM-05", "CAM-06"],
        "scoring_ids": {
            "BQ-020": {
                "label": "cost-per-tenant model",
                "options": [
                    "accurate_per_tenant",
                    "estimated_from_tenant_usage",
                    "dedicated_costs_only",
                    "rough_manual",
                    "none",
                    "unknown",
                ],
            },
            "BQ-021": {
                "label": "cost allocation basis",
                "options": [
                    "accounts_or_tenant_tags",
                    "partial_grouping",
                    "none",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "A rough defensible estimate is different from no visibility.",
    },
    {
        "id": "AQ-013",
        "phase": 5,
        "priority": "essential",
        "persona": "Product, Finance, or Engineering Lead",
        "prompt": (
            "What usage information do you track for each customer, where is it visible, "
            "and does it support product decisions, limits, cost analysis, or billing?"
        ),
        "probes": [
            "Can customers see their own usage without asking support?",
            "Does measured usage feed billing automatically or through a manual process?",
        ],
        "controls": ["CAM-02", "CAM-03", "CAM-06"],
        "scoring_ids": {
            "BQ-012": {
                "label": "tenant usage metering",
                "options": [
                    "billing_integrated",
                    "tracked_manual_billing",
                    "partial_tenant_metrics",
                    "none",
                    "not_required",
                    "unknown",
                ],
            }
        },
        "reasoning_hints": "Metering, telemetry, cost attribution, and billing are distinct.",
    },
    {
        "id": "AQ-014",
        "phase": 5,
        "priority": "essential",
        "persona": "Product Manager or Customer Success Lead",
        "prompt": (
            "How do you know customers activate, receive value, remain healthy, and influence "
            "the roadmap—and who owns that end-to-end outcome?"
        ),
        "probes": [
            "Do you measure time-to-value, adoption, retention, or churn risk?",
            "Is feedback reviewed systematically and tied to product or service decisions?",
        ],
        "controls": ["SBR-03", "SBR-04", "SBR-05"],
        "scoring_ids": {
            "BQ-028": {
                "label": "customer outcome measurement",
                "options": [
                    "product_telemetry_and_risk_alerts",
                    "metrics_reviewed_regularly",
                    "surveys_or_manual_review",
                    "none",
                    "pre_customer",
                    "unknown",
                ],
            },
            "BQ-029": {
                "label": "customer feedback loop",
                "options": [
                    "feeds_product_decisions",
                    "collected_not_systematic",
                    "none",
                    "pre_customer",
                    "unknown",
                ],
            },
        },
        "reasoning_hints": "Customer outcomes are part of operating SaaS as a service.",
    },
]

# Exact option-to-control mappings. Customer claims are capped at partial;
# only explicit reviewed or technical evidence can produce met.
ANSWER_CONTROL_RULES: dict[str, dict[str, tuple[tuple[str, str], ...]]] = {
    "BQ-001": {
        "pooled": (("TAI-01", "partial"),),
        "silo": (("TAI-01", "partial"),),
        "hybrid": (("TAI-01", "partial"),),
    },
    "BQ-002": {
        "authoritative_signed_claim": (("ITC-01", "partial"),),
        "authoritative_server_lookup": (("ITC-01", "partial"),),
        "trusted_routing_mapping": (("ITC-01", "partial"),),
        "caller_supplied_identifier": (("ITC-01", "missing"),),
        "inconsistent": (("ITC-01", "missing"),),
        "none": (("ITC-01", "missing"),),
    },
    "BQ-003": {
        "all_sync_async_paths": (("ITC-02", "partial"),),
        "sync_only": (("ITC-02", "partial"),),
        "inconsistent": (("ITC-02", "missing"),),
        "edge_only": (("ITC-02", "missing"),),
        "none": (("ITC-02", "missing"),),
    },
    "BQ-004": {
        "fully_automated": (("TLO-02", "partial"),),
        "partially_automated": (("TLO-02", "partial"),),
        "manual": (("TLO-02", "missing"),),
        "not_started": (("TLO-02", "missing"),),
    },
    "BQ-007": {
        "flat_subscription": (("SBR-02", "partial"),),
        "seat_based": (("SBR-02", "partial"),),
        "usage_based": (("SBR-02", "partial"),),
        "tiered": (("SBR-02", "partial"),),
        "hybrid": (("SBR-02", "partial"),),
        "not_finalized": (("SBR-02", "missing"),),
    },
    "BQ-008": {
        "automatic_per_tenant": (("TAI-04", "partial"), ("OOR-03", "partial")),
        "partial_limits": (("TAI-04", "partial"), ("OOR-03", "partial")),
        "manual_response": (("TAI-04", "missing"), ("OOR-03", "missing")),
        "none": (("TAI-04", "missing"), ("OOR-03", "missing")),
        "not_applicable_no_shared_resources": (("TAI-04", "not_applicable"), ("OOR-03", "not_applicable")),
    },
    "BQ-009": {
        "automated_with_rollback": (("DPA-02", "partial"), ("DPA-05", "partial")),
        "pipeline_approval_and_rollback": (("DPA-02", "partial"), ("DPA-05", "partial")),
        "pipeline_no_rollback": (("DPA-02", "partial"), ("DPA-05", "missing")),
        "manual": (("DPA-02", "missing"), ("DPA-05", "missing")),
    },
    "BQ-010": {
        "required_now": (("TAI-06", "partial"),),
        "planned": (("TAI-06", "partial"),),
        "none_known": (("TAI-06", "not_applicable"),),
    },
    "BQ-011": {
        "tenant_logs_metrics_traces_and_alerts": (("ITC-04", "partial"), ("OOR-01", "partial"), ("OOR-02", "partial"), ("OOR-05", "partial")),
        "some_tenant_signals": (("ITC-04", "partial"), ("OOR-01", "partial"), ("OOR-02", "partial"), ("OOR-05", "partial")),
        "service_or_infrastructure_only": (("ITC-04", "missing"), ("OOR-01", "missing"), ("OOR-02", "missing"), ("OOR-05", "missing")),
        "none": (("ITC-04", "missing"), ("OOR-01", "missing"), ("OOR-02", "missing"), ("OOR-05", "missing")),
        "no_production_operations": (("OOR-02", "not_applicable"), ("OOR-05", "not_applicable")),
    },
    "BQ-012": {
        "billing_integrated": (("CAM-02", "partial"), ("CAM-03", "partial"), ("CAM-06", "partial")),
        "tracked_manual_billing": (("CAM-02", "partial"), ("CAM-03", "partial"), ("CAM-06", "partial")),
        "partial_tenant_metrics": (("CAM-02", "partial"), ("CAM-03", "partial"), ("CAM-06", "partial")),
        "none": (("CAM-02", "missing"), ("CAM-03", "missing"), ("CAM-06", "missing")),
        "not_required": (("CAM-02", "not_applicable"),),
    },
    "BQ-013": {
        "onboarding": (("SBR-06", "partial"),),
        "tenant_scale": (("SBR-06", "partial"),),
        "cost_margin": (("SBR-06", "partial"),),
        "compliance_residency": (("SBR-06", "partial"),),
        "reliability": (("SBR-06", "partial"),),
        "enterprise_requirements": (("SBR-06", "partial"),),
        "none_stated": (("SBR-06", "missing"),),
    },
    "BQ-014": {
        "centralized_service": (("SBR-05", "partial"), ("SBR-06", "partial"), ("DPA-03", "partial")),
        "mostly_centralized": (("SBR-05", "partial"), ("SBR-06", "partial"), ("DPA-03", "partial")),
        "customer_specific_operations": (("SBR-05", "missing"), ("SBR-06", "missing"), ("DPA-03", "missing")),
        "hosted_software": (("SBR-05", "missing"), ("SBR-06", "missing"), ("DPA-03", "missing")),
    },
    "BQ-015": {
        "automated_with_policy": (("TLO-04", "partial"),),
        "defined_manual": (("TLO-04", "partial"),),
        "ad_hoc": (("TLO-04", "missing"),),
        "none": (("TLO-04", "missing"),),
    },
    "BQ-016": {
        "complete_system": (("TLO-01", "partial"),),
        "partial_system": (("TLO-01", "partial"),),
        "manual_tracker": (("TLO-01", "missing"),),
        "scattered": (("TLO-01", "missing"),),
        "none": (("TLO-01", "missing"),),
    },
    "BQ-017": {
        "dedicated_account": (("TAI-02", "partial"), ("TAI-03", "partial")),
        "dedicated_database": (("TAI-02", "partial"), ("TAI-03", "partial")),
        "dedicated_schema": (("TAI-02", "partial"), ("TAI-03", "partial")),
        "shared_enforced": (("TAI-02", "partial"), ("TAI-03", "partial")),
        "mixed_enforced": (("TAI-02", "partial"), ("TAI-03", "partial")),
        "shared_filter_only": (("TAI-02", "missing"), ("TAI-03", "missing")),
        "none": (("TAI-02", "missing"), ("TAI-03", "missing")),
    },
    "BQ-018": {
        "same_version": (("DPA-03", "partial"),),
        "time_bounded_release_waves": (("DPA-03", "partial"),),
        "long_lived_exceptions": (("DPA-03", "missing"),),
        "custom_forks": (("DPA-03", "missing"),),
    },
    "BQ-019": {
        "centralized": (("OOR-04", "partial"),),
        "fragmented": (("OOR-04", "partial"),),
        "none": (("OOR-04", "missing"),),
    },
    "BQ-020": {
        "accurate_per_tenant": (("CAM-03", "partial"), ("CAM-05", "partial"), ("CAM-06", "partial")),
        "estimated_from_tenant_usage": (("CAM-03", "partial"), ("CAM-05", "partial"), ("CAM-06", "partial")),
        "dedicated_costs_only": (("CAM-03", "partial"), ("CAM-05", "partial")),
        "rough_manual": (("CAM-03", "partial"), ("CAM-05", "missing"), ("CAM-06", "missing")),
        "none": (("CAM-03", "missing"), ("CAM-05", "missing"), ("CAM-06", "missing")),
    },
    "BQ-021": {
        "accounts_or_tenant_tags": (("CAM-01", "partial"),),
        "partial_grouping": (("CAM-01", "partial"),),
        "none": (("CAM-01", "missing"),),
    },
    "BQ-022": {
        "implemented": (("CAM-04", "partial"),),
        "planned": (("CAM-04", "partial"),),
        "none": (("CAM-04", "not_applicable"),),
    },
    "BQ-024": {
        "automated": (("TLO-03", "partial"),),
        "repeatable_manual": (("TLO-03", "partial"),),
        "ad_hoc": (("TLO-03", "missing"),),
        "not_applicable": (("TLO-03", "not_applicable"),),
    },
    "BQ-025": {
        "same_managed_pipeline": (("TAI-05", "partial"),),
        "separate_process": (("TAI-05", "missing"),),
        "not_required": (("TAI-05", "not_applicable"),),
    },
    "BQ-026": {
        "centralized_tenant_aware": (("ITC-03", "partial"), ("TAI-02", "partial")),
        "distributed_tenant_checks": (("ITC-03", "partial"), ("TAI-02", "partial")),
        "login_or_role_only": (("ITC-03", "missing"), ("TAI-02", "missing")),
        "inconsistent": (("ITC-03", "missing"), ("TAI-02", "missing")),
        "none": (("ITC-03", "missing"), ("TAI-02", "missing")),
    },
    "BQ-027": {
        "tenant_scoped_audited": (("ITC-05", "partial"),),
        "partially_scoped": (("ITC-05", "partial"),),
        "broad_global": (("ITC-05", "missing"),),
    },
    "BQ-028": {
        "product_telemetry_and_risk_alerts": (("SBR-03", "partial"), ("SBR-04", "partial")),
        "metrics_reviewed_regularly": (("SBR-03", "partial"), ("SBR-04", "partial")),
        "surveys_or_manual_review": (("SBR-03", "partial"), ("SBR-04", "partial")),
        "none": (("SBR-03", "missing"), ("SBR-04", "missing")),
        "pre_customer": (("SBR-03", "not_applicable"), ("SBR-04", "not_applicable")),
    },
    "BQ-029": {
        "feeds_product_decisions": (("SBR-04", "partial"), ("SBR-05", "partial")),
        "collected_not_systematic": (("SBR-04", "partial"),),
        "none": (("SBR-04", "missing"),),
        "pre_customer": (("SBR-04", "not_applicable"),),
    },
}


def get_phase_questions(phase: int, exclude_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Return questions for one phase, excluding completed presentation IDs."""

    excluded = exclude_ids or set()
    return [question for question in QUESTIONS if question["phase"] == phase and question["id"] not in excluded]


def get_essential_questions(exclude_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Return essential questions across all personas."""

    excluded = exclude_ids or set()
    return [question for question in QUESTIONS if question["priority"] == "essential" and question["id"] not in excluded]


def get_all_questions(exclude_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Return every adaptive question."""

    excluded = exclude_ids or set()
    return [question for question in QUESTIONS if question["id"] not in excluded]


PHASES: dict[int, dict[str, Any]] = {
    1: {"name": "Product and Business Context", "persona": "Product or Founder"},
    2: {"name": "Customer Lifecycle and Architecture", "persona": "Platform or Architect"},
    3: {"name": "Identity, Isolation, and Requirements", "persona": "Architecture or Security"},
    4: {"name": "Delivery and Operations", "persona": "Platform, DevOps, or SRE"},
    5: {"name": "Economics and Customer Outcomes", "persona": "Finance, Product, or Customer Success"},
}
for phase_id, phase in PHASES.items():
    phase["question_count"] = len([question for question in QUESTIONS if question["phase"] == phase_id])


def _build_scoring_questions() -> list[dict[str, Any]]:
    """Project AQ topics onto stable BQ signals for deterministic CLI use."""

    projected: dict[str, dict[str, Any]] = {}
    for question in QUESTIONS:
        for signal_id, definition in question.get("scoring_ids", {}).items():
            projected[signal_id] = {
                "id": signal_id,
                "presentation_id": question["id"],
                "priority": question["priority"],
                "persona": question["persona"],
                "prompt": question["prompt"],
                "options": list(definition.get("options", ())),
                "controls": list(question.get("controls", ())),
            }
    return [projected[key] for key in sorted(projected, key=lambda item: int(item.split("-")[-1]))]


SCORING_QUESTIONS = _build_scoring_questions()
