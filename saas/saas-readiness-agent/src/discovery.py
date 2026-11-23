# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Read-only AWS discovery adapter.

This module is the only place in the project that calls AWS APIs. Every call
here is Describe/List/Get/Simulate — nothing mutates a customer resource. That
matches the Level 0 (observe/report) trust boundary the assessment operates
under: see iam-permission-boundary.md and security-policies.md for the policy
this module is written to satisfy.

Two-stage inspection model (from the design notes):
  Stage 1 (cheap classification) - identity, account/org shape, VPC layout,
    IaC signal, tagging signal. Always attempted when discovery is enabled,
    because these calls are cheap and do not depend on knowing what else is
    deployed.
  Stage 2 (conditional deepening) - only calls a service's Describe/List API
    after a presence probe suggests the account actually uses that service.
    This avoids scanning ~10 services blind and keeps the assessment bounded.

Every discovery function degrades gracefully instead of raising:
  - Missing boto3 -> a single `unknown` evidence item, no AWS calls attempted.
  - Denied permission (ClientError) -> `unknown` evidence for the controls
    that permission would have supported, plus a recorded permission gap.
  - Any other AWS/network error -> the same graceful `unknown` treatment.

The output of `run_aws_discovery` is a `facts` dict shaped exactly like the
`facts` object the CLI/MCP callers can also supply by hand in the assessment
input JSON (`services`, `signals`, `missing_permissions`). That means the
scoring logic in agent.py does not need to know whether a fact came from a
live AWS call or from a human-supplied JSON file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

try:
    from src.config import RuntimeLimits, load_limits
    from src.observability import get_logger
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from config import RuntimeLimits, load_limits  # type: ignore[import-not-found, no-redef]
    from observability import get_logger  # type: ignore[import-not-found, no-redef]

_LOGGER = get_logger("discovery")


@dataclass(frozen=True)
class Evidence:
    """Discovery's own Evidence record.

    This intentionally mirrors the shape of agent.Evidence field-for-field
    rather than importing it, because agent.py imports this module (to reach
    run_aws_discovery), so importing agent.Evidence back here would create a
    circular import at module-load time. agent.py's explicit_evidence() only
    needs Mapping-shaped dicts, and Evidence.from_mapping() there normalizes
    whatever it receives, so a structurally-identical dataclass here is
    exactly as usable as importing the "real" one would be. If either shape
    changes, keep both in sync.
    """

    control_id: str
    status: str = "unknown"
    confidence: str = "low"
    evidence_state: str = "unknown"
    summary: str = "No evidence supplied."
    source: str = "unknown"
    timestamp: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# Read-only IAM actions needed for a minimum-effort assessment. These map to
# Stage 1 classification plus the cheapest Stage 2 presence probes. Keeping
# this list read-only-only is a hard requirement, not a style preference: see
# iam-permission-boundary.md "BLOCKED by Default" for what must never appear
# here.
MINIMUM_READ_ONLY_ACTIONS: tuple[str, ...] = (
    "sts:GetCallerIdentity",
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeTags",
    "ec2:DescribeVolumes",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "lambda:ListFunctions",
    "ecs:ListClusters",
    "eks:ListClusters",
    "cognito-idp:ListUserPools",
    "secretsmanager:ListSecrets",
    "rds:DescribeDBInstances",
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
    "s3:ListAllMyBuckets",
    "apigateway:GET",
    "route53:ListHostedZones",
    # Edge tier (per-tenant routing signals for multi-tenant SaaS). CloudFront
    # is a global service, so ListDistributions works from any region; ACM
    # and WAF back per-tenant custom-domain/TLS and edge protection. These are
    # read-only List calls and stay inside the observe/report boundary. See
    # discover_edge_presence() for how they map to ITC-01 / TLO-02 / TAI-04/05.
    "cloudfront:ListDistributions",
    "acm:ListCertificates",
    "wafv2:ListWebACLs",
    "elasticloadbalancing:DescribeLoadBalancers",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:ListMetrics",
    "logs:DescribeLogGroups",
    "cloudtrail:DescribeTrails",
    "cloudformation:ListStacks",
    "tag:GetResources",
    "tag:GetTagKeys",
    # Agentic-SaaS surfaces (discover_agentic_surfaces). Read-only List calls.
    "bedrock-agentcore:ListAgentRuntimes",
    "bedrock-agentcore:ListGateways",
    "s3vectors:ListVectorBuckets",
    "s3vectors:ListIndexes",
)

# Enhanced mode adds account-structure and cost visibility. These actions are
# more sensitive (org-wide, billing) so they are opt-in via
# scope.access_mode == "enhanced_assessment" rather than the default.
ENHANCED_READ_ONLY_ACTIONS: tuple[str, ...] = MINIMUM_READ_ONLY_ACTIONS + (
    "iam:SimulatePrincipalPolicy",
    "organizations:ListAccounts",
    "organizations:DescribeOrganization",
    "ce:GetCostAndUsage",
    "ce:GetTagsOrValues",
    "controltower:ListLandingZones",
)

# Maps a denied read-only action to the rubric controls it would have
# supported. When simulate_principal_policy reports a denial, every affected
# control becomes `unknown` evidence instead of silently staying unassessed.
PERMISSION_CONTROL_MAP: dict[str, tuple[str, ...]] = {
    "apigateway:GET": ("ITC-01", "TAI-04"),
    "ce:GetCostAndUsage": ("CAM-01", "CAM-03", "CAM-05", "CAM-06"),
    "ce:GetTagsOrValues": ("CAM-01",),
    "cloudformation:ListStacks": ("DPA-01",),
    "cloudtrail:DescribeTrails": ("ITC-05", "OOR-05"),
    "cloudwatch:DescribeAlarms": ("OOR-02", "OOR-04", "CAM-05"),
    "cloudwatch:ListMetrics": ("OOR-01", "OOR-03", "CAM-06"),
    "cognito-idp:ListUserPools": ("ITC-01",),
    "controltower:ListLandingZones": ("TAI-01", "DPA-04"),
    "dynamodb:DescribeTable": ("TAI-03", "TLO-01"),
    "dynamodb:ListTables": ("TAI-03", "CAM-06", "TLO-01"),
    "ec2:DescribeInstances": ("TAI-03", "OOR-01", "OOR-03", "CAM-06"),
    "ec2:DescribeSecurityGroups": ("TAI-02", "TAI-03"),
    "ec2:DescribeSubnets": ("TAI-02", "DPA-04"),
    "ec2:DescribeTags": ("CAM-01", "DPA-01"),
    "ec2:DescribeVolumes": ("TAI-03", "CAM-06"),
    "ec2:DescribeVpcs": ("TAI-02", "DPA-04"),
    "ecs:ListClusters": ("TAI-04", "DPA-02", "OOR-03"),
    "eks:ListClusters": ("TAI-04", "DPA-02", "OOR-03"),
    "elasticloadbalancing:DescribeLoadBalancers": ("TAI-04", "OOR-04"),
    "iam:SimulatePrincipalPolicy": ("TAI-02", "ITC-03", "ITC-05"),
    "lambda:ListFunctions": ("TAI-04", "DPA-02", "CAM-06"),
    "logs:DescribeLogGroups": ("ITC-04", "OOR-01", "OOR-05"),
    "organizations:DescribeOrganization": ("TAI-01", "DPA-04"),
    "organizations:ListAccounts": ("TAI-01", "DPA-04", "CAM-01"),
    "rds:DescribeDBInstances": ("TAI-03", "CAM-06"),
    "route53:ListHostedZones": ("DPA-04",),
    # Edge-tier signals for multi-tenant SaaS: per-tenant routing/custom domains
    # (CloudFront), per-tenant TLS provisioning (ACM), edge blast-radius controls
    # (WAF). Suggestive of tenant context at the edge and repeatable per-tenant
    # onboarding; never proof on their own.
    "cloudfront:ListDistributions": ("ITC-01", "TLO-02", "TAI-05"),
    "acm:ListCertificates": ("TLO-02", "TLO-03"),
    "wafv2:ListWebACLs": ("TAI-04",),
    "s3:ListAllMyBuckets": ("TAI-03", "CAM-06"),
    "secretsmanager:ListSecrets": ("TAI-06", "DPA-01"),
    "sts:GetCallerIdentity": ("TAI-01",),
    "resourcegroupstaggingapi:GetResources": ("CAM-01", "DPA-01"),
    "resourcegroupstaggingapi:GetTagKeys": ("CAM-01",),
    "tag:GetResources": ("CAM-01", "DPA-01"),
    "tag:GetTagKeys": ("CAM-01",),
    "bedrock-agentcore:ListAgentRuntimes": ("ITC-02",),
    "bedrock-agentcore:ListGateways": ("ITC-02",),
    "s3vectors:ListVectorBuckets": ("TAI-03",),
    "s3vectors:ListIndexes": ("TAI-03",),
}

# Heuristic keywords used to decide whether a resource name, tag key, or
# CloudWatch dimension is plausibly tenant-aware. These are suggestive, not
# confirmatory: a name match lowers to `evidence_state="suggestive"` rather
# than `"confirmed"`, per the rubric's rule that naming alone never proves
# isolation or tenant context.
TENANT_HINT_KEYWORDS: tuple[str, ...] = (
    "tenant",
    "tenantid",
    "tenant_id",
    "customerid",
    "customer_id",
    "accountid",
    "account_id",
    "org_id",
    "orgid",
)

COST_ALLOCATION_HINT_KEYWORDS: tuple[str, ...] = (
    "tenant",
    "customer",
    "tier",
    "product",
    "team",
    "cost-center",
    "cost_center",
)


class ClientFactory(Protocol):
    """Anything that can hand back a boto3-shaped client for a service name.

    Defined as a Protocol (structural typing) so tests can inject a fake
    factory returning stub clients without importing boto3/botocore at all.
    """

    def client(self, service_name: str) -> Any: ...


class Boto3ClientFactory:
    """Default factory that lazily creates real boto3 clients.

    Import of boto3 is deferred to construction time, not module import time,
    so the rest of the codebase (and its tests) can run with zero AWS SDK
    dependency installed. If boto3 is missing, callers should catch
    ModuleNotFoundError from the constructor and treat discovery as
    unavailable, exactly as the previous permission-only preflight did.
    """

    def __init__(self, limits: RuntimeLimits | None = None) -> None:
        import boto3  # type: ignore[import-untyped]  # noqa: F401 - optional dependency
        from botocore.config import Config  # type: ignore[import-untyped]

        resolved = limits if limits is not None else load_limits()
        self._boto3 = boto3
        # Retry transient throttling and network errors inside the SDK so a
        # single blip does not turn a control into `unknown`. Values come from
        # AWS_DISCOVERY_MAX_ATTEMPTS / AWS_DISCOVERY_RETRY_MODE.
        self._config = Config(
            retries={
                "max_attempts": resolved.aws_max_attempts,
                "mode": resolved.aws_retry_mode,
            }
        )

    def client(self, service_name: str) -> Any:
        return self._boto3.client(service_name, config=self._config)


def client_error_code(error: Any) -> str:
    """Extract the AWS error code from a botocore ClientError, defensively."""

    response = getattr(error, "response", {})
    if isinstance(response, Mapping):
        error_block = response.get("Error", {})
        if isinstance(error_block, Mapping):
            return str(error_block.get("Code", "ClientError"))
    return "ClientError"


def _call(
    factory: ClientFactory,
    service_name: str,
    method_name: str,
    control_ids: tuple[str, ...],
    **kwargs: Any,
) -> tuple[Any | None, Evidence | None, str | None]:
    """Call one read-only AWS API and normalize every failure mode.

    Returns a (result, evidence_on_failure, denied_action) triple. Exactly
    one of `result` or `evidence_on_failure` is populated. This is the single
    choke point every discovery function goes through, so permission denials,
    throttling, and unexpected errors are all handled the same way instead of
    each caller re-implementing try/except.

    Deliberately does not import botocore.exceptions to distinguish error
    types. boto3/botocore are listed in requirements.txt, but discovery is
    written to degrade gracefully when they are absent, and
    a strict isinstance() check against ClientError would force this module
    to require botocore just to classify a failure, which defeats the point
    of graceful degradation when boto3/botocore is not installed. Instead,
    this duck-types on the `.response["Error"]["Code"]` shape that botocore's
    ClientError always has - the same shape test fakes can use without any
    AWS SDK installed.
    """

    action = f"{service_name}:{method_name[0].upper()}{method_name[1:]}".replace("_", "")
    try:
        client = factory.client(service_name)
        method = getattr(client, method_name)
        return method(**kwargs), None, None
    except AssertionError:
        # Never swallow test-fixture "unexpected call" assertions; letting
        # these propagate is what makes FakeClientFactory in test_discovery.py
        # useful for catching accidental extra AWS calls.
        raise
    except Exception as exc:  # noqa: BLE001 - intentionally broad; see docstring
        code = client_error_code(exc) if hasattr(exc, "response") else type(exc).__name__
        # AccessDenied/UnauthorizedOperation-style codes are a real permission
        # gap worth recording. Other errors (throttling, a missing resource,
        # network failure) still degrade gracefully but are not reported as
        # a permission gap since retrying with more access would not help.
        denied = code.lower() in {
            "accessdenied",
            "accessdeniedexception",
            "unauthorizedoperation",
            "authfailure",
            "notauthorized",
        }
        _LOGGER.warning(
            "aws_discovery_call_failed",
            extra={
                "service": service_name,
                "action": action,
                "error_code": code,
                "permission_denied": denied,
            },
        )
        evidence = Evidence(
            control_id=control_ids[0] if control_ids else "TAI-01",
            status="unknown",
            confidence="low",
            evidence_state="unknown",
            summary=(
                f"{service_name}.{method_name} returned {code}; "
                "the related controls were not assessed."
            ),
            source="aws-discovery",
            metadata={"error_code": code, "service": service_name},
        )
        return None, evidence, (action if denied else None)


class DiscoveryAccumulator:
    """Collects evidence, denied actions, services, and signals across calls.

    Plain mutable collector rather than a dataclass because discovery runs as
    a sequence of independent steps that each append a little state; a
    dataclass with in-place mutation would not read any more clearly here.
    """

    def __init__(self) -> None:
        self.evidence: list[Evidence] = []
        self.denied_actions: list[str] = []
        self.services: set[str] = set()
        self.signals: dict[str, dict[str, Any]] = {}
        self.observations: list[str] = []

    def record(
        self, result: Any, failure: Evidence | None, denied_action: str | None
    ) -> Any | None:
        if failure is not None:
            self.evidence.append(failure)
        if denied_action:
            self.denied_actions.append(denied_action)
        return result

    def set_signal(self, name: str, **fields: Any) -> None:
        self.signals[name] = {"inspected": True, **fields}


def discover_identity_and_permissions(
    factory: ClientFactory, enhanced: bool, acc: DiscoveryAccumulator
) -> str | None:
    """Stage 1: resolve caller identity and simulate the read-only action set.

    This is the permission preflight the project already had. It stays first
    in the pipeline because every later Stage 2 call depends on knowing which
    actions are actually allowed for this principal.
    """

    identity, failure, denied = _call(factory, "sts", "get_caller_identity", ("TAI-01",))
    acc.record(identity, failure, denied)
    if not identity:
        return None

    arn = str(identity.get("Arn", ""))
    actions = ENHANCED_READ_ONLY_ACTIONS if enhanced else MINIMUM_READ_ONLY_ACTIONS

    simulation, failure, denied = _call(
        factory,
        "iam",
        "simulate_principal_policy",
        ("TAI-02", "ITC-03", "ITC-05"),
        PolicySourceArn=arn,
        ActionNames=list(actions),
    )
    acc.record(simulation, failure, denied)
    if not simulation:
        return arn

    for result in simulation.get("EvaluationResults", []):
        action = str(result.get("EvalActionName", ""))
        decision = str(result.get("EvalDecision", "")).lower()
        if not action or decision == "allowed":
            continue
        acc.denied_actions.append(action)
        for control_id in PERMISSION_CONTROL_MAP.get(action, ("TAI-01",)):
            acc.evidence.append(
                Evidence(
                    control_id=control_id,
                    status="unknown",
                    confidence="low",
                    evidence_state="unknown",
                    summary=f"Not assessed because read-only permission {action} was not allowed.",
                    source="permission-preflight",
                    metadata={"missing_permission": action, "decision": decision},
                )
            )
    return arn


def discover_iac_signal(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 1: CloudFormation stack presence as an infrastructure-automation signal.

    Feeds the existing `iac` signal name in agent.py's inference rules
    (DPA-01), so no scoring code needs to change to consume this.

    Note: list_stacks without StackStatusFilter includes DELETE_COMPLETE stacks
    which can mask real stacks in pagination. We explicitly filter for active
    statuses in the API call to avoid this.
    """

    # Explicitly request only active stacks — avoids the common issue where
    # hundreds of deleted stacks fill the response and real stacks are missed.
    active_statuses = [
        "CREATE_COMPLETE",
        "CREATE_IN_PROGRESS",
        "UPDATE_COMPLETE",
        "UPDATE_IN_PROGRESS",
        "UPDATE_ROLLBACK_COMPLETE",
        "IMPORT_COMPLETE",
        "IMPORT_IN_PROGRESS",
        "ROLLBACK_COMPLETE",
    ]
    response, failure, denied = _call(
        factory, "cloudformation", "list_stacks", ("DPA-01",),
        StackStatusFilter=active_statuses,
    )
    acc.record(response, failure, denied)
    if response is None:
        return

    stacks = response.get("StackSummaries", [])
    acc.set_signal("iac", detected=bool(stacks), confirmed=True, stack_count=len(stacks))
    if stacks:
        acc.observations.append(
            f"Detected {len(stacks)} active CloudFormation stack(s), "
            "suggesting IaC-managed infrastructure."
        )


def discover_tagging_signal(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Inspect tag keys plus a bounded tagged-resource sample.

    Resource Groups Tagging API returns tagged resources, not an inventory of
    every resource that should have a tag. This function therefore detects
    evidence of a tag strategy, but never treats an absent matching key as
    proof that the account lacks cost allocation coverage.
    """

    tag_keys: list[str] = []
    resource_tags: list[dict[str, Any]] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        tag_key_kwargs: dict[str, Any] = {"PaginationToken": token} if token else {}
        response, failure, denied = _call(
            factory,
            "resourcegroupstaggingapi",
            "get_tag_keys",
            ("CAM-01",),
            **tag_key_kwargs,
        )
        acc.record(response, failure, denied)
        if response is None:
            return
        tag_keys.extend(str(key).lower() for key in response.get("TagKeys", []))
        token = str(response.get("PaginationToken", "")).strip() or None
        if token is None or token in seen_tokens:
            break
        seen_tokens.add(token)

    # Inspect at most 500 tagged resources. This is enough to find useful
    # signals without claiming exhaustive account-wide coverage or creating
    # an unbounded discovery operation in a customer account.
    token = None
    seen_tokens.clear()
    while len(resource_tags) < 500:
        resource_kwargs: dict[str, Any] = {"ResourcesPerPage": 100}
        if token:
            resource_kwargs["PaginationToken"] = token
        response, failure, denied = _call(
            factory,
            "resourcegroupstaggingapi",
            "get_resources",
            ("CAM-01",),
            **resource_kwargs,
        )
        acc.record(response, failure, denied)
        if response is None:
            break
        mappings = response.get("ResourceTagMappingList", [])
        if isinstance(mappings, list):
            resource_tags.extend(
                dict(mapping) for mapping in mappings if isinstance(mapping, Mapping)
            )
        token = str(response.get("PaginationToken", "")).strip() or None
        if token is None or token in seen_tokens:
            break
        seen_tokens.add(token)

    observed_keys = {
        key for key in tag_keys if key and not key.startswith("aws:")
    }
    for mapping in resource_tags:
        for tag in mapping.get("Tags", []):
            if isinstance(tag, Mapping):
                key = str(tag.get("Key", "")).lower()
                if key and not key.startswith("aws:"):
                    observed_keys.add(key)
    matched = sorted(
        key
        for key in observed_keys
        if any(hint in key for hint in COST_ALLOCATION_HINT_KEYWORDS)
    )
    acc.set_signal(
        "cost_allocation_tags",
        detected=bool(matched),
        confirmed=False,
        matched_tag_keys=matched[:10],
        tag_key_count=len(tag_keys),
        tagged_resource_sample_count=len(resource_tags),
        coverage_complete=False,
    )
    if matched:
        acc.observations.append(
            "Observed tag keys suggestive of cost or tenant grouping in a bounded tagged-resource "
            f"sample: {', '.join(matched[:5])}."
        )
    else:
        acc.observations.append(
            "No tenant, customer, tier, product, team, or cost-center tag key was observed in "
            "the inspected tag-key inventory and bounded tagged-resource sample. This does not "
            "prove that resources are untagged or that cost allocation is absent."
        )


def discover_vpc_topology(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 1: VPC and security-group counts as a coarse isolation-boundary signal.

    A VPC count alone never proves isolation (the rubric is explicit that
    deployment shape is not isolation), so this only ever produces
    `evidence_state="suggestive"` observations, never a `met` control result.
    """

    vpcs, failure, denied = _call(factory, "ec2", "describe_vpcs", ("TAI-02", "DPA-04"))
    acc.record(vpcs, failure, denied)
    if vpcs is not None:
        vpc_count = len(vpcs.get("Vpcs", []))
        acc.observations.append(f"Detected {vpc_count} VPC(s) in the current region.")

    groups, failure, denied = _call(
        factory, "ec2", "describe_security_groups", ("TAI-02", "TAI-03")
    )
    acc.record(groups, failure, denied)
    if groups is not None:
        acc.services.add("ec2")


def discover_account_topology(
    factory: ClientFactory, enhanced: bool, acc: DiscoveryAccumulator
) -> None:
    """Stage 1 (enhanced mode only): AWS Organizations shape as a tenancy-model signal.

    Skipped entirely in minimum_read_only mode because organizations:* is not
    in MINIMUM_READ_ONLY_ACTIONS - asking for it would just produce a denial.
    """

    if not enhanced:
        return

    accounts, failure, denied = _call(
        factory, "organizations", "list_accounts", ("TAI-01", "DPA-04")
    )
    acc.record(accounts, failure, denied)
    if accounts is None:
        return

    account_count = len(accounts.get("Accounts", []))
    acc.set_signal(
        "multi_account_org",
        detected=account_count > 1,
        confirmed=True,
        account_count=account_count,
    )
    if account_count > 1:
        acc.observations.append(
            f"AWS Organizations reports {account_count} member accounts, "
            "consistent with an account-per-tenant or account-per-environment pattern."
        )


def discover_compute_presence(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 2: cheap presence probes for the most common SaaS compute services."""

    functions, failure, denied = _call(
        factory, "lambda", "list_functions", ("TAI-04", "DPA-02"), MaxItems=1
    )
    acc.record(functions, failure, denied)
    if functions is not None and functions.get("Functions"):
        acc.services.add("lambda")

    ecs_clusters, failure, denied = _call(factory, "ecs", "list_clusters", ("TAI-04", "DPA-02"))
    acc.record(ecs_clusters, failure, denied)
    if ecs_clusters is not None and ecs_clusters.get("clusterArns"):
        acc.services.add("ecs")

    eks_clusters, failure, denied = _call(factory, "eks", "list_clusters", ("TAI-04", "DPA-02"))
    acc.record(eks_clusters, failure, denied)
    if eks_clusters is not None and eks_clusters.get("clusters"):
        acc.services.add("eks")

    instances, failure, denied = _call(
        factory, "ec2", "describe_instances", ("TAI-03", "OOR-01"), MaxResults=5
    )
    acc.record(instances, failure, denied)
    if instances is not None and any(r.get("Instances") for r in instances.get("Reservations", [])):
        acc.services.add("ec2")


def discover_data_layer_presence(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 2: data-store presence, plus a tenant-registry heuristic on DynamoDB.

    DynamoDB is inspected slightly more deeply than a presence check: a
    sample table's key schema is checked for a tenant-shaped partition key,
    which is the strongest signal this project can get from a read-only API
    without seeing application code. It still only produces `partial`
    (never `met`) evidence, consistent with the rubric's warning that a
    partition-key name alone does not prove enforcement.
    """

    tables, failure, denied = _call(
        factory, "dynamodb", "list_tables", ("TAI-03", "TLO-01"), Limit=10
    )
    acc.record(tables, failure, denied)
    table_names = list(tables.get("TableNames", [])) if tables else []
    if table_names:
        acc.services.add("dynamodb")

    registry_like = [
        name
        for name in table_names
        if any(hint in name.lower() for hint in ("tenant", "customer", "account"))
    ]
    tenant_key_detected = False
    if table_names:
        # Sample only the first matching (or first overall) table rather than
        # every table, to keep this a cheap Stage 2 probe rather than a full
        # schema audit.
        sample_name = registry_like[0] if registry_like else table_names[0]
        description, failure, denied = _call(
            factory, "dynamodb", "describe_table", ("TAI-03",), TableName=sample_name
        )
        acc.record(description, failure, denied)
        if description:
            key_schema = description.get("Table", {}).get("KeySchema", [])
            tenant_key_detected = any(
                any(
                    hint in str(key.get("AttributeName", "")).lower()
                    for hint in TENANT_HINT_KEYWORDS
                )
                for key in key_schema
            )

    acc.set_signal(
        "tenant_registry",
        detected=bool(registry_like) or tenant_key_detected,
        confirmed=False,
        matched_table_names=registry_like[:5],
        tenant_shaped_partition_key=tenant_key_detected,
    )

    rds_instances, failure, denied = _call(
        factory, "rds", "describe_db_instances", ("TAI-03", "CAM-06"), MaxRecords=20
    )
    acc.record(rds_instances, failure, denied)
    if rds_instances is not None and rds_instances.get("DBInstances"):
        acc.services.add("rds")
        engines = {str(item.get("Engine", "")) for item in rds_instances["DBInstances"]}
        if "aurora-postgresql" in engines or "postgres" in engines:
            acc.services.add("postgresql")
        if engines.intersection({"aurora-mysql", "mysql"}):
            acc.services.add("mysql")

    buckets, failure, denied = _call(factory, "s3", "list_buckets", ("TAI-03", "CAM-06"))
    acc.record(buckets, failure, denied)
    if buckets is not None and buckets.get("Buckets"):
        acc.services.add("s3")


def discover_identity_layer_presence(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 2: Cognito and Secrets Manager presence, feeding ITC-01 and TAI-06/DPA-01."""

    pools, failure, denied = _call(
        factory, "cognito-idp", "list_user_pools", ("ITC-01",), MaxResults=10
    )
    acc.record(pools, failure, denied)
    if pools is not None and pools.get("UserPools"):
        acc.services.add("cognito")

    secrets, failure, denied = _call(
        factory, "secretsmanager", "list_secrets", ("TAI-06", "DPA-01"), MaxResults=10
    )
    acc.record(secrets, failure, denied)
    if secrets is not None and secrets.get("SecretList"):
        acc.services.add("secretsmanager")


def discover_edge_presence(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 2: CloudFront / ACM / WAF as per-tenant *edge* signals.

    A scalable multi-tenant SaaS platform usually fronts its tenants at the
    edge: a custom domain + TLS certificate per tenant (often via CloudFront
    SaaS Manager, i.e. multi-tenant distributions + distribution tenants),
    with WAF for edge protection. Observing these is *suggestive* of:
      - tenant context established at request entry / the edge  -> ITC-01
      - a repeatable per-tenant onboarding/provisioning flow     -> TLO-02/TLO-03
      - deliberate pooled vs dedicated isolation tiers           -> TAI-05
      - edge blast-radius / noisy-neighbor protection            -> TAI-04
    It never *proves* any of them, so this only sets the `edge_multi_tenancy`
    signal (confirmed=False) and never a `met` control, consistent with the
    rubric's rule that deployment shape is not isolation.

    Region notes: CloudFront is a global service, so list_distributions works
    from any region. wafv2 is queried with Scope="REGIONAL" (WAFs on ALB /
    API Gateway origins). CLOUDFRONT-scope WebACLs require a us-east-1 client,
    which this region-agnostic factory does not target, so edge-attached WAFs
    may be under-counted — treated as a caveat, not a false negative.
    """

    # CloudFront distributions — the core edge signal.
    distributions: list[Any] = []
    dist_resp, failure, denied = _call(
        factory, "cloudfront", "list_distributions", ("ITC-01", "TLO-02", "TAI-05")
    )
    acc.record(dist_resp, failure, denied)
    if dist_resp is not None:
        distributions = list(dist_resp.get("DistributionList", {}).get("Items", []) or [])
        if distributions:
            acc.services.add("cloudfront")

    # CloudFront SaaS Manager (multi-tenant distributions) detection is
    # best-effort: list_distribution_tenants exists only on newer botocore.
    # Guard with hasattr so an older SDK degrades *silently* instead of
    # emitting a misleading `unknown` evidence item via _call.
    saas_manager_tenants = 0
    try:
        cf_client = factory.client("cloudfront")
        # dir() (not hasattr) so a stub/fake client without this operation is
        # skipped cleanly: real boto3 clients expose operations via dir(),
        # older SDKs and test fakes do not, and neither path raises here.
        if "list_distribution_tenants" in dir(cf_client):
            tenants_resp = cf_client.list_distribution_tenants()
            saas_manager_tenants = len(
                tenants_resp.get("DistributionTenantList", [])
                or tenants_resp.get("Items", [])
                or []
            )
    except AssertionError:
        raise  # let test-fixture "unexpected call" assertions surface
    except Exception:  # noqa: BLE001 - missing API/permission degrades silently
        saas_manager_tenants = 0

    # Per-tenant TLS certs (ACM). A large cert count or wildcard certs is a
    # common per-tenant / pooled-tier custom-domain pattern.
    cert_count = 0
    acm_resp, failure, denied = _call(
        factory, "acm", "list_certificates", ("TLO-02", "TLO-03"), MaxItems=100
    )
    acc.record(acm_resp, failure, denied)
    if acm_resp is not None:
        certs = list(acm_resp.get("CertificateSummaryList", []) or [])
        cert_count = len(certs)
        if certs:
            acc.services.add("acm")

    # Edge protection (WAFv2, regional scope — see region notes above).
    waf_detected = False
    waf_resp, failure, denied = _call(
        factory, "wafv2", "list_web_acls", ("TAI-04",), Scope="REGIONAL", Limit=100
    )
    acc.record(waf_resp, failure, denied)
    if waf_resp is not None:
        web_acls = list(waf_resp.get("WebACLs", []) or [])
        waf_detected = bool(web_acls)
        if web_acls:
            acc.services.add("waf")

    detected = bool(distributions) or saas_manager_tenants > 0
    acc.set_signal(
        "edge_multi_tenancy",
        detected=detected,
        confirmed=False,
        distribution_count=len(distributions),
        saas_manager_tenant_count=saas_manager_tenants,
        saas_manager_detected=saas_manager_tenants > 0,
        acm_certificate_count=cert_count,
        edge_waf_detected=waf_detected,
    )
    if detected:
        detail = f"{len(distributions)} CloudFront distribution(s)"
        if saas_manager_tenants:
            detail += f" and {saas_manager_tenants} SaaS Manager distribution tenant(s)"
        acc.observations.append(
            f"Detected {detail}; per-tenant custom-domain/TLS at the edge is suggestive of "
            "SaaS multi-tenancy but does not by itself prove tenant isolation or context."
        )


def discover_agentic_multitenancy_signals(
    factory: ClientFactory, acc: DiscoveryAccumulator
) -> None:
    """Stage 2: agentic-SaaS surfaces - Bedrock AgentCore presence and per-tenant
    vector-store agent memory.

    Two brand-new services (`bedrock-agentcore-control`, `s3vectors`) that older
    SDKs may not know. Each is probed only after confirming its client can be
    constructed, so an SDK that has never heard of the service degrades silently
    with no evidence rather than emitting a misleading `unknown`.

    Signals:
      - `agentic_platform` (informational, NOT scored): AgentCore runtimes or
        gateways present. Presence alone is not tenant-isolation evidence, so
        this only annotates the report. The three agentic isolation behaviors
        the workshop calls out - server-side session-ID binding, MCP-gateway
        tenant propagation, and per-tenant token metering - are application/
        config behaviors that a control-plane list cannot confirm, so the
        observation tells the human to assess them directly. (Per-tenant token
        metering, when present, is already picked up by the CloudWatch
        `tenant_telemetry` signal in discover_observability_signals.)
      - `agent_memory_isolation` (scored -> TAI-03, suggestive): emitted ONLY
        when a per-tenant-named vector index is found (the silo memory pattern,
        e.g. an S3 Vectors index whose name carries a tenant identifier). It is
        never emitted as a negative, so a SaaS that isolates by other means (or
        uses no vector memory) is never penalized here.

    Response field names for these new services are parsed defensively with
    fallbacks; an unexpected shape degrades to "no detection", never a crash.
    """

    def _service_available(name: str) -> bool:
        try:
            factory.client(name)
        except AssertionError:
            raise  # let test-fixture "unexpected call" assertions surface
        except Exception:  # noqa: BLE001 - service absent in this SDK: degrade silently
            return False
        return True

    # --- Amazon Bedrock AgentCore presence (informational only) ---
    runtime_count = 0
    gateway_count = 0
    if _service_available("bedrock-agentcore-control"):
        runtimes, failure, denied = _call(
            factory, "bedrock-agentcore-control", "list_agent_runtimes", ("ITC-02",), maxResults=20
        )
        acc.record(runtimes, failure, denied)
        if runtimes is not None:
            runtime_count = len(
                runtimes.get("agentRuntimes", runtimes.get("agentRuntimeSummaries", [])) or []
            )
        gateways, failure, denied = _call(
            factory, "bedrock-agentcore-control", "list_gateways", ("ITC-02",), maxResults=20
        )
        acc.record(gateways, failure, denied)
        if gateways is not None:
            gateway_count = len(gateways.get("items", gateways.get("gatewaySummaries", [])) or [])

    if runtime_count or gateway_count:
        acc.services.add("bedrock-agentcore")
        acc.set_signal(
            "agentic_platform",
            detected=True,
            confirmed=False,
            agent_runtime_count=runtime_count,
            gateway_count=gateway_count,
        )
        acc.observations.append(
            f"Detected Amazon Bedrock AgentCore usage ({runtime_count} runtime(s), "
            f"{gateway_count} gateway(s)). Agentic tenant-isolation surfaces - server-side "
            "session-ID binding, MCP-gateway tenant propagation, and per-tenant token metering - "
            "are application/config behaviors a control-plane list cannot confirm; assess them "
            "directly."
        )

    # --- Per-tenant vector-store agent memory (S3 Vectors) -> TAI-03 ---
    if _service_available("s3vectors"):
        buckets_resp, failure, denied = _call(
            factory, "s3vectors", "list_vector_buckets", ("TAI-03",), maxResults=20
        )
        acc.record(buckets_resp, failure, denied)
        bucket_names = (
            [str(b.get("vectorBucketName", "")) for b in buckets_resp.get("vectorBuckets", []) or []]
            if buckets_resp is not None
            else []
        )
        if bucket_names:
            acc.services.add("s3vectors")

        per_tenant_indexes: list[str] = []
        for bucket_name in bucket_names[:5]:  # bound the probe - a few buckets is enough of a sample
            idx_resp, failure, denied = _call(
                factory,
                "s3vectors",
                "list_indexes",
                ("TAI-03",),
                vectorBucketName=bucket_name,
                maxResults=50,
            )
            acc.record(idx_resp, failure, denied)
            if idx_resp is None:
                continue
            for index in idx_resp.get("indexes", []) or []:
                index_name = str(index.get("indexName", ""))
                if any(hint in index_name.lower() for hint in TENANT_HINT_KEYWORDS):
                    per_tenant_indexes.append(index_name)

        # Only ever a POSITIVE signal: emitted when per-tenant indexes exist, so a
        # non-agentic (or differently-isolated) SaaS is never penalized. A shared
        # vector store is surfaced as an observation for the human, not a score.
        if per_tenant_indexes:
            acc.set_signal(
                "agent_memory_isolation",
                detected=True,
                confirmed=False,
                matched_index_names=per_tenant_indexes[:5],
            )
            acc.observations.append(
                f"Detected {len(per_tenant_indexes)} per-tenant-named vector index(es) in S3 "
                "Vectors, suggestive of tenant-isolated agent memory (silo model); index naming "
                "alone does not prove FGAC or credential-level enforcement."
            )


def discover_observability_signals(factory: ClientFactory, acc: DiscoveryAccumulator) -> None:
    """Stage 2: CloudWatch alarms/metrics and log groups as tenant-telemetry signals.

    Feeds the existing `tenant_alarms` and `tenant_telemetry` signal names
    (OOR-02, OOR-01, ITC-04), so agent.py's inference rules pick this up with
    no changes required there.
    """

    alarms, failure, denied = _call(
        factory, "cloudwatch", "describe_alarms", ("OOR-02",), MaxRecords=50
    )
    acc.record(alarms, failure, denied)
    if alarms is not None:
        alarm_items = alarms.get("MetricAlarms", []) + alarms.get("CompositeAlarms", [])
        any_alarms = bool(alarm_items)
        tenant_alarms = [
            item
            for item in alarm_items
            if any(hint in str(item.get("AlarmName", "")).lower() for hint in TENANT_HINT_KEYWORDS)
        ]
        acc.set_signal(
            "tenant_alarms",
            detected=bool(tenant_alarms),
            confirmed=False,
            any_alarms=any_alarms,
            matched_alarm_count=len(tenant_alarms),
        )

    metrics, failure, denied = _call(factory, "cloudwatch", "list_metrics", ("OOR-01", "ITC-04"))
    acc.record(metrics, failure, denied)
    if metrics is not None:
        tenant_dimensions = [
            dimension.get("Name", "")
            for metric in metrics.get("Metrics", [])
            for dimension in metric.get("Dimensions", [])
            if any(hint in str(dimension.get("Name", "")).lower() for hint in TENANT_HINT_KEYWORDS)
        ]
        acc.set_signal(
            "tenant_telemetry",
            detected=bool(tenant_dimensions),
            confirmed=False,
            matched_dimension_names=list(dict.fromkeys(tenant_dimensions))[:10],
        )

    logs_response, failure, denied = _call(
        factory, "logs", "describe_log_groups", ("ITC-04", "OOR-01"), limit=50
    )
    acc.record(logs_response, failure, denied)
    if logs_response is not None and logs_response.get("logGroups"):
        acc.observations.append(
            f"Detected {len(logs_response['logGroups'])} CloudWatch log group(s); "
            "application-level tenant dimensions inside log content were not inspected."
        )


def discover_cost_signal(
    factory: ClientFactory, enhanced: bool, acc: DiscoveryAccumulator
) -> None:
    """Stage 2 (enhanced mode only): confirm Cost Explorer is reachable for cost controls.

    This intentionally does not attempt to join cost data with tenant
    consumption data (that requires application telemetry no AWS API can
    supply); it only confirms the billing data source itself is reachable,
    which is a prerequisite for CAM-01/CAM-03/CAM-05/CAM-06.
    """

    if not enhanced:
        return

    from datetime import date, timedelta

    end = date.today()
    start = end - timedelta(days=7)
    response, failure, denied = _call(
        factory,
        "ce",
        "get_cost_and_usage",
        ("CAM-01", "CAM-03"),
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
    )
    acc.record(response, failure, denied)
    if response is not None:
        acc.observations.append(
            "Cost Explorer is reachable; cost-per-tenant analysis still requires "
            "joining this with tenant consumption data."
        )


def run_aws_discovery(
    scope: Any,
    client_factory: ClientFactory | None = None,
) -> tuple[dict[str, Any], tuple[Evidence, ...], tuple[str, ...]]:
    """Run the full Stage 1 + Stage 2 read-only discovery pipeline.

    Returns (facts, evidence, observations):
      - facts: shaped like the `facts` object accepted directly in assessment
        input JSON (`services`, `signals`, `missing_permissions`), so it can
        be merged with caller-supplied facts using the same merge_facts logic
        the rest of the project already uses.
      - evidence: unknown-status Evidence for anything discovery could not
        assess (missing boto3, denied permission, unexpected AWS error).
      - observations: short human-readable strings describing what discovery
        found, for inclusion in the report's "What Was Observed" section.

    `client_factory` is dependency-injected so unit tests can supply a fake
    without installing boto3/botocore. When omitted, a real Boto3ClientFactory
    is constructed; if boto3 is not installed, discovery degrades to a single
    `unknown` evidence item and empty facts, matching the previous behavior.
    """

    enhanced = getattr(scope, "access_mode", "minimum_read_only") == "enhanced_assessment"
    acc = DiscoveryAccumulator()

    if client_factory is None:
        try:
            client_factory = Boto3ClientFactory()
        except ModuleNotFoundError:
            return (
                {
                    "signals": {
                        "aws_discovery": {
                            "inspected": True,
                            "detected": False,
                            "error": "boto3_missing",
                        }
                    }
                },
                (
                    Evidence(
                        control_id="TAI-01",
                        status="unknown",
                        confidence="low",
                        evidence_state="unknown",
                        summary=(
                            "AWS discovery was requested, but optional dependency "
                            "boto3 is not installed. No AWS APIs were called."
                        ),
                        source="aws-discovery",
                    ),
                ),
                (),
            )

    discover_identity_and_permissions(client_factory, enhanced, acc)
    discover_iac_signal(client_factory, acc)
    discover_tagging_signal(client_factory, acc)
    discover_vpc_topology(client_factory, acc)
    discover_account_topology(client_factory, enhanced, acc)
    discover_compute_presence(client_factory, acc)
    discover_data_layer_presence(client_factory, acc)
    discover_identity_layer_presence(client_factory, acc)
    discover_edge_presence(client_factory, acc)
    discover_agentic_multitenancy_signals(client_factory, acc)
    discover_observability_signals(client_factory, acc)
    discover_cost_signal(client_factory, enhanced, acc)

    facts: dict[str, Any] = {
        "signals": {"aws_discovery": {"inspected": True, "detected": True}, **acc.signals},
    }
    if acc.services:
        facts["services"] = sorted(acc.services)
    if acc.denied_actions:
        facts["missing_permissions"] = list(dict.fromkeys(acc.denied_actions))

    return facts, tuple(acc.evidence), tuple(acc.observations)
