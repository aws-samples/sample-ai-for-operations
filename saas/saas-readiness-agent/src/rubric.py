# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Static SaaS readiness rubric data.

The active agent keeps logic in src/agent.py and static assessment content here.
This is intentionally data-only so the project stays easy to review.
"""

MATURITY_SCALE = {
    0: "Not established",
    1: "Initial / ad hoc",
    2: "Emerging",
    3: "Repeatable",
    4: "Scalable",
    5: "Optimized",
}

SOURCES = {
    "AWS_SAAS_LENS": {
        "title": "AWS Well-Architected SaaS Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/saas-lens.html",
    },
    "AWS_SAAS_LENS_PILLARS": {
        "title": "SaaS Lens pillars page",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/the-pillars-of-the-well-architected-framework.html",
    },
    "AWS_SAAS_ARCH_FUNDAMENTALS": {
        "title": "AWS SaaS Architecture Fundamentals",
        "url": "https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/saas-architecture-fundamentals.html",
    },
    "AWS_CONTROL_APP_PLANE": {
        "title": "Control plane vs. application plane",
        "url": "https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/control-plane-vs.-application-plane.html",
    },
    "AWS_SAAS_VS_MSP": {
        "title": "SaaS vs. Managed Service Provider",
        "url": "https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/saas-vs.-managed-service-provider-msp.html",
    },
    "AWS_TENANT_ISOLATION": {
        "title": "SaaS Tenant Isolation Strategies",
        "url": "https://d1.awsstatic.com/whitepapers/saas-tenant-isolation-strategies.pdf",
    },
    "AWS_SAAS_STORAGE_STRATEGIES": {
        "title": "AWS SaaS Storage Strategies",
        "url": "https://docs.aws.amazon.com/whitepapers/latest/multi-tenant-saas-storage-strategies/multi-tenant-saas-storage-strategies.html",
    },
    "AWS_SAAS_JOURNEY": {
        "title": "AWS SaaS Journey Framework",
        "url": "https://docs.aws.amazon.com/whitepapers/latest/saas-journey-framework/saas-journey-framework.html",
    },
    "AWS_SAAS_FACTORY_MAP": {
        "title": "AWS SaaS Factory MAP",
        "url": "https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/events/approved/documents/aws-saas-factory-map.pdf",
    },
    "AWS_SAAS_LENS_EXPENDITURE": {
        "title": "SaaS Lens expenditure awareness",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/expenditure-awareness.html",
    },
    "AWS_COST_PER_TENANT_VISIBILITY": {
        "title": "Optimizing Cost Per Tenant Visibility in SaaS Solutions",
        "url": "https://aws.amazon.com/blogs/apn/optimizing-cost-per-tenant-visibility-in-saas-solutions/",
    },
}

DIMENSIONS = [
    {
        "id": "TAI",
        "name": "Tenant Architecture and Isolation",
        "weight": 0.20,
        "why": "Tenant isolation is foundational to SaaS. The assessment checks whether one tenant can affect another tenant's data, performance, or security boundary.",
        "customer_question": "Can this platform safely support more tenants, enterprise tenants, and compliance-sensitive tenants without cross-tenant risk?",
        "controls": [
            {
                "id": "TAI-01",
                "title": "Tenancy model is explicit and consistent with the AWS footprint.",
                "why": "Recommendations depend on whether the customer is silo, pooled, or hybrid.",
                "recommendation": "Document the intended tenancy model and map it to account, network, compute, data, and storage boundaries.",
                "sources": ["AWS_SAAS_ARCH_FUNDAMENTALS", "AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "TAI-02",
                "title": "Isolation boundary exists for the default tenant model.",
                "why": "Authentication, authorization, and RBAC are not isolation; isolation is tenant-context-based resource access control.",
                "recommendation": "Define isolation boundaries for compute, network, identity, and data. Prove tenant-context-based access control for shared resources.",
                "sources": ["AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES", "AWS_SAAS_LENS"],
            },
            {
                "id": "TAI-03",
                "title": "Data access isolation is enforced through tenant context.",
                "why": "A column, tag, login token, or role name does not prove isolation.",
                "recommendation": "Use service-appropriate tenant data isolation: partition keys, row-level security, schema/database separation, scoped IAM/KMS controls, or a shared data-access layer.",
                "sources": ["AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES", "AWS_SAAS_LENS"],
            },
            {
                "id": "TAI-04",
                "title": "Noisy-neighbor and blast-radius controls exist for shared resources.",
                "why": "Shared infrastructure needs controls so one tenant's load, storage, I/O, or connection pattern does not degrade service for others.",
                "recommendation": "Add tenant-aware throttling, quotas, concurrency limits, capacity controls, resource limits, and high-impact tenant alerts.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "TAI-05",
                "title": "Stronger isolation tiers are deliberate and centrally managed.",
                "why": "Dedicated tenant deployments are valid SaaS only when they stay inside one managed product lifecycle.",
                "recommendation": "Define premium or compliance isolation tiers and keep dedicated environments under the same control-plane and release process.",
                "sources": ["AWS_SAAS_ARCH_FUNDAMENTALS", "AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "TAI-06",
                "title": "Compliance, geography, and data-protection requirements map to tenancy and isolation.",
                "why": "Compliance and residency needs can change tenancy model, tiering, deployment geography, and data isolation.",
                "recommendation": "Map compliance, residency, geography, and data-protection requirements to tenant tiers, regions, isolation boundaries, and data controls.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_TENANT_ISOLATION"],
            },
        ],
    },
    {
        "id": "ITC",
        "name": "Identity and Tenant Context",
        "weight": 0.15,
        "why": "SaaS systems need to know which tenant each request belongs to and carry that context through application, async, support, and data-access paths.",
        "customer_question": "Can the platform prove every request, job, event, and data access is associated with the correct tenant?",
        "controls": [
            {
                "id": "ITC-01",
                "title": "Tenant identity is established at authentication or request entry.",
                "why": "The platform cannot enforce tenant-specific behavior unless tenant identity is established early.",
                "recommendation": "Define the authoritative tenant identity source and establish tenant context at the edge.",
                "sources": ["AWS_SAAS_LENS", "AWS_SAAS_ARCH_FUNDAMENTALS"],
            },
            {
                "id": "ITC-02",
                "title": "Tenant context is propagated across APIs, services, jobs, and events.",
                "why": "Tenant context often gets lost after the first API hop, creating isolation, audit, support, and metering gaps.",
                "recommendation": "Standardize tenant-context propagation for requests, events, background jobs, and admin operations.",
                "sources": ["AWS_SAAS_LENS", "AWS_SAAS_ARCH_FUNDAMENTALS"],
            },
            {
                "id": "ITC-03",
                "title": "Authorization and data-access paths consume tenant context.",
                "why": "A tenant claim is only useful if downstream authorization and data-access code actually uses it.",
                "recommendation": "Centralize tenant authorization and data-access enforcement in shared middleware, policies, or data-access libraries.",
                "sources": ["AWS_SAAS_LENS", "AWS_TENANT_ISOLATION"],
            },
            {
                "id": "ITC-04",
                "title": "Tenant context appears in logs, metrics, traces, or audit records.",
                "why": "Tenant-aware telemetry is needed to troubleshoot tenant incidents and correlate usage, cost, and performance.",
                "recommendation": "Add tenant-safe identifiers to logs, metrics, traces, and audit records with privacy controls.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "ITC-05",
                "title": "Admin, support, and machine-to-machine access remains tenant-scoped.",
                "why": "Many SaaS isolation incidents happen through privileged support or admin paths.",
                "recommendation": "Tenant-scope admin, support, and machine-to-machine access with least-privilege roles and break-glass audit.",
                "sources": ["AWS_SAAS_LENS", "AWS_TENANT_ISOLATION"],
            },
        ],
    },
    {
        "id": "TLO",
        "name": "Tenant Lifecycle and Onboarding",
        "weight": 0.15,
        "why": "SaaS scale depends on repeatable tenant onboarding, configuration, tier changes, and offboarding through a control plane.",
        "customer_question": "What happens when the customer goes from 10 tenants to 100 or 1,000?",
        "controls": [
            {
                "id": "TLO-01",
                "title": "A control-plane tenant registry or tenant metadata source exists.",
                "why": "A SaaS control plane needs a reliable source for tenant identity, tier, configuration, status, and lifecycle.",
                "recommendation": "Define a tenant registry containing tenant identity, tier, configuration, lifecycle status, and operational metadata.",
                "sources": ["AWS_CONTROL_APP_PLANE", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "TLO-02",
                "title": "Tenant onboarding and provisioning use a repeatable control-plane workflow.",
                "why": "Manual onboarding increases time-to-value, error rate, and operational cost as tenant count grows.",
                "recommendation": "Automate tenant onboarding through a control-plane workflow coordinating registration, identity, configuration, billing setup, and provisioning.",
                "sources": ["AWS_CONTROL_APP_PLANE", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "TLO-03",
                "title": "Tenant tier, plan, and configuration changes are repeatable.",
                "why": "Manual tier upgrades become a growth and customer-experience bottleneck.",
                "recommendation": "Model tenant tiers and configuration so plan changes drive provisioning, limits, features, and support workflows.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "TLO-04",
                "title": "Tenant offboarding, data retention, and deletion are defined.",
                "why": "Poor offboarding creates security, compliance, cost, and support risk.",
                "recommendation": "Document and automate tenant suspension, offboarding, retention, and deletion paths.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS"],
            },
            {
                "id": "TLO-05",
                "title": "Tenant lifecycle status is observable and recoverable.",
                "why": "A repeatable service needs to know where tenant lifecycle actions fail and how to resume safely.",
                "recommendation": "Add lifecycle workflow status, retries, alerts, rollback, and recovery paths.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS_PILLARS"],
            },
        ],
    },
    {
        "id": "OOR",
        "name": "Observability and Operational Readiness",
        "weight": 0.15,
        "why": "SaaS operations require tenant-aware visibility, not only generic infrastructure dashboards.",
        "customer_question": "When one tenant has a problem or causes a problem, can the team detect it, explain it, and contain it?",
        "controls": [
            {
                "id": "OOR-01",
                "title": "Logs, metrics, and traces include tenant-aware dimensions.",
                "why": "Tenant-aware telemetry diagnoses tenant-specific performance, errors, adoption, and cost behavior.",
                "recommendation": "Instrument critical paths with tenant-safe IDs and tenant or tier dimensions in logs, metrics, and traces.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "OOR-02",
                "title": "Alarms or SLOs reflect tenant or tier impact.",
                "why": "Fleet averages hide tenant pain. SaaS teams need impact-aware operations.",
                "recommendation": "Add tenant and tier-aware alarms or SLOs for critical journeys and high-impact resources.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "OOR-03",
                "title": "Noisy-neighbor detection exists for shared compute, API, and data layers.",
                "why": "SaaS platforms need to know which tenant is stressing shared resources before other tenants are affected.",
                "recommendation": "Add tenant usage dimensions, quotas, throttling, storage/capacity policies, and noisy-neighbor runbooks.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_TENANT_ISOLATION", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "OOR-04",
                "title": "A centralized operational view exists across the assessed scope.",
                "why": "Running SaaS as a service requires shared visibility across product, support, operations, engineering, and storage layers.",
                "recommendation": "Create a centralized operational view for tenant health, critical journeys, storage trends, and platform dependencies.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS_PILLARS", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "OOR-05",
                "title": "Incident impact analysis and support handoff use tenant context.",
                "why": "SaaS operations should reduce time to detect, explain, and communicate tenant impact.",
                "recommendation": "Make incidents identify affected tenants, tier or SLA exposure, customer communication needs, and remediation status.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS_PILLARS"],
            },
        ],
    },
    {
        "id": "DPA",
        "name": "Deployment and Platform Automation",
        "weight": 0.15,
        "why": "SaaS maturity depends on repeatable releases, consistent environments, and limited tenant-specific drift.",
        "customer_question": "Can the team ship and operate the product consistently as tenant count grows?",
        "controls": [
            {
                "id": "DPA-01",
                "title": "Infrastructure and environment setup use repeatable automation.",
                "why": "Repeatable environments reduce drift, speed onboarding, and make improvements measurable.",
                "recommendation": "Start with IaC for tenant-critical resources and onboarding or deployment paths.",
                "sources": ["AWS_SAAS_ARCH_FUNDAMENTALS", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "DPA-02",
                "title": "Application deployment uses a controlled release pipeline.",
                "why": "SaaS providers need controlled releases to maintain service quality and reduce tenant-specific failures.",
                "recommendation": "Standardize deployment pipelines with promotion, approval, rollback, and release visibility.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS_PILLARS"],
            },
            {
                "id": "DPA-03",
                "title": "Same-version discipline is maintained across tenants and tiers.",
                "why": "Long-lived customer-specific versions or schemas erode service efficiency.",
                "recommendation": "Govern versions, release waves, and schema or data migrations. Reduce long-lived tenant-specific forks.",
                "sources": ["AWS_SAAS_ARCH_FUNDAMENTALS", "AWS_SAAS_JOURNEY", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "DPA-04",
                "title": "Environment, account, and region promotion are consistent.",
                "why": "Inconsistent environments make defects, onboarding issues, and operational surprises more likely.",
                "recommendation": "Define a standard environment, account, and region blueprint with promotion rules.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_ARCH_FUNDAMENTALS"],
            },
            {
                "id": "DPA-05",
                "title": "Deployment safety includes rollback, staged rollout, migration safety, and tenant validation.",
                "why": "SaaS releases must protect many tenants at once, including storage/schema changes in pooled models.",
                "recommendation": "Use staged deployments, rollback criteria, canaries, migration runbooks, and tests for tenant isolation, context, tier behavior, and data changes.",
                "sources": ["AWS_SAAS_LENS_PILLARS", "AWS_SAAS_JOURNEY", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "DPA-06",
                "title": "Agility goals and release-cycle measures are defined.",
                "why": "Agility is a SaaS business and operating goal, not just an engineering preference.",
                "recommendation": "Track release frequency, lead time, rollback rate, onboarding cycle time, and customer time-to-value.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_LENS_PILLARS"],
            },
        ],
    },
    {
        "id": "CAM",
        "name": "Cost Attribution and Metering Readiness",
        "weight": 0.10,
        "why": "SaaS businesses need tenant-level cost and usage visibility to make pricing, tiering, margin, and noisy-neighbor decisions.",
        "customer_question": "Can the customer connect tenant behavior to cost, usage, pricing, and margin?",
        "controls": [
            {
                "id": "CAM-01",
                "title": "Cost allocation tags or equivalent grouping exist for tenant/tier/product views.",
                "why": "Tags and accounts can attribute dedicated cost, but pooled resources need additional consumption telemetry.",
                "recommendation": "Use cost tags, accounts, cost categories, CUR, and telemetry-based attribution for pooled resources.",
                "sources": ["AWS_SAAS_LENS_EXPENDITURE", "AWS_COST_PER_TENANT_VISIBILITY", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "CAM-02",
                "title": "Billing metering events exist for pricing-relevant tenant usage.",
                "why": "Usage-based pricing without billing-grade metering is a business and customer-trust risk.",
                "recommendation": "Define billable usage events with tenant, tier, timestamp, unit, and billing-period context.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP", "AWS_COST_PER_TENANT_VISIBILITY"],
            },
            {
                "id": "CAM-03",
                "title": "Cost-per-tenant or unit economics can be estimated.",
                "why": "SaaS scaling can hide margin problems.",
                "recommendation": "Join tenant or tier consumption data with AWS cost data, starting with dedicated tenant stacks and top shared services.",
                "sources": ["AWS_SAAS_LENS_EXPENDITURE", "AWS_COST_PER_TENANT_VISIBILITY", "AWS_SAAS_JOURNEY"],
            },
            {
                "id": "CAM-04",
                "title": "Commercial tiers map to personas, technical limits, features, or service behavior.",
                "why": "SaaS packaging should be reflected in the platform, otherwise tier promises become manual work.",
                "recommendation": "Map each tier to personas, limits, features, isolation level, support model, telemetry, and billing expectations.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "CAM-05",
                "title": "Cost anomalies and high-consumption tenants can be detected.",
                "why": "High consumption creates margin risk and can indicate noisy-neighbor or tier-fit problems.",
                "recommendation": "Connect cloud spend, tenant usage, storage/compute/API consumption, and commercial tier context in anomaly workflows.",
                "sources": ["AWS_SAAS_LENS_EXPENDITURE", "AWS_COST_PER_TENANT_VISIBILITY", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
            {
                "id": "CAM-06",
                "title": "Highest-cost shared components have a tenant consumption model.",
                "why": "The customer needs visibility into the largest pooled-cost drivers first.",
                "recommendation": "Identify top shared cost drivers and add tenant consumption metrics or defensible proxies.",
                "sources": ["AWS_COST_PER_TENANT_VISIBILITY", "AWS_SAAS_LENS_EXPENDITURE", "AWS_SAAS_STORAGE_STRATEGIES"],
            },
        ],
    },
    {
        "id": "SBR",
        "name": "Service Model and Business Readiness",
        "weight": 0.10,
        "why": "SaaS is a service business, not only an architecture pattern.",
        "customer_question": "Is the customer running a scalable SaaS service, or just hosting software?",
        "controls": [
            {
                "id": "SBR-01",
                "title": "Business stage, target segment/persona, and next growth pressure are known.",
                "why": "Severity depends on stage and target customer profile.",
                "recommendation": "Clarify business stage, target segment or persona, and the next SaaS milestone before prioritizing platform work.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "SBR-02",
                "title": "Packaging, pricing, and architecture are coherent.",
                "why": "Pricing affects metering, limits, isolation, support, and cost visibility.",
                "recommendation": "Align tiers and pricing with metering, onboarding, limits, isolation, and support expectations.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "SBR-03",
                "title": "Time-to-value, activation, onboarding efficiency, and adoption are measured.",
                "why": "SaaS success depends on customers reaching value quickly and continuing to use the service.",
                "recommendation": "Define activation milestones and track onboarding success, onboarding cycle time, feature usage, and time-to-value.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "SBR-04",
                "title": "Retention, churn, expansion, and customer feedback loops exist.",
                "why": "A SaaS operating model needs feedback loops that influence product, support, pricing, and roadmap decisions.",
                "recommendation": "Create lightweight retention, expansion, feedback, and customer-success loops that influence roadmap and onboarding improvements.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
            {
                "id": "SBR-05",
                "title": "Unified SaaS operating model and service ownership are clear.",
                "why": "Automating customer installs or managing separate customer environments does not by itself create a SaaS model.",
                "recommendation": "Define one SaaS operating model across lifecycle, operations, support, metering, analytics, release management, and same-version discipline.",
                "sources": ["AWS_SAAS_VS_MSP", "AWS_SAAS_JOURNEY", "AWS_SAAS_ARCH_FUNDAMENTALS"],
            },
            {
                "id": "SBR-06",
                "title": "MVS or GA readiness assumptions, tradeoffs, and SaaS tenets are explicit.",
                "why": "MVS means minimum viable service, not just minimum product functionality.",
                "recommendation": "Document early adopters, included tiers, minimum operational experience, feedback loop, launch success metrics, and known tradeoffs.",
                "sources": ["AWS_SAAS_JOURNEY", "AWS_SAAS_FACTORY_MAP"],
            },
        ],
    },
]

QUESTIONS = [
    # 30 fixed questions: 15 "essential" + 15 "extended".
    # Essential questions (1-15) resolve environment classification and the
    # highest-weighted foundational controls. Extended questions (16-30)
    # deepen specific dimensions for a comprehensive assessment.
    #
    # The agent should default to offering the 15 essential questions, and
    # offer the full 30 only if the customer opts for comprehensive mode.

    # --- Business Context (affects how everything is weighted) ---
    {"id": "BQ-001", "priority": "essential", "prompt": "What stage is the business at? (e.g., pre-launch, early customers, scaling, mature)", "options": ["pre-launch", "early customers", "scaling", "mature", "unknown"], "controls": ["SBR-01", "SBR-06"]},
    {"id": "BQ-002", "priority": "essential", "prompt": "Who's the target segment? (e.g., SMB, mid-market, enterprise)", "options": ["SMB", "mid-market", "enterprise", "developers", "unknown"], "controls": ["SBR-01", "CAM-04", "TAI-06"]},
    {"id": "BQ-003", "priority": "essential", "prompt": "What's the pricing model? (e.g., flat subscription, usage-based, seat-based, tiered)", "options": ["flat subscription", "usage-based", "seat-based", "tiered", "not finalized", "unknown"], "controls": ["CAM-02", "CAM-03", "CAM-06", "SBR-02"]},
    {"id": "BQ-004", "priority": "essential", "prompt": "What's the intended tenancy model? (e.g., fully pooled/multi-tenant, siloed per-tenant, hybrid)", "options": ["pooled", "silo", "hybrid", "unknown"], "controls": ["TAI-01", "TAI-02", "TAI-03"]},
    {"id": "BQ-005", "priority": "essential", "prompt": "What's the next growth pressure? (e.g., need to onboard enterprise customers, scale tenant count, pass a compliance audit)", "options": [], "controls": ["SBR-06", "TAI-06", "TLO-02"]},

    # --- Tenant Architecture & Isolation ---
    {"id": "BQ-006", "priority": "essential", "prompt": "Is the tenancy model documented anywhere, and does it match how resources are actually deployed (shared vs. dedicated per tenant)?", "options": ["yes documented and matches", "partially", "not documented", "unknown"], "controls": ["TAI-01"]},
    {"id": "BQ-007", "priority": "essential", "prompt": "How is tenant data isolated — separate databases/schemas per tenant, row-level security with tenant ID, IAM/KMS scoping, or something else?", "options": [], "controls": ["TAI-02", "TAI-03"]},
    {"id": "BQ-008", "priority": "essential", "prompt": "Do you have any controls to stop one tenant from overloading shared resources (rate limits, quotas, per-tenant throttling)?", "options": ["yes", "partially", "no", "unknown"], "controls": ["TAI-04"]},
    {"id": "BQ-009", "priority": "extended", "prompt": "Do any tenants get dedicated/isolated infrastructure (e.g., for compliance)? If so, is it still managed through the same release process as everyone else?", "options": ["yes same release process", "yes but separate process", "no dedicated tenants", "unknown"], "controls": ["TAI-05", "DPA-05"]},
    {"id": "BQ-010", "priority": "extended", "prompt": "Do any tenants have compliance or data-residency requirements that affect where/how their data is stored?", "options": ["yes", "no", "planned", "unknown"], "controls": ["TAI-05", "TAI-06", "DPA-04"]},

    # --- Identity & Tenant Context ---
    {"id": "BQ-011", "priority": "essential", "prompt": "Where is 'which tenant is this request for' first established — auth token/JWT claim, subdomain, API key, something else?", "options": [], "controls": ["ITC-01", "ITC-03"]},
    {"id": "BQ-012", "priority": "essential", "prompt": "Does that tenant ID get passed along through internal service calls, background jobs, and async events — or does it sometimes get dropped after the first hop?", "options": ["consistently passed", "sometimes dropped", "not standardized", "unknown"], "controls": ["ITC-02", "ITC-05"]},
    {"id": "BQ-013", "priority": "essential", "prompt": "Does your authorization/data-access code actually check tenant ID before returning data, or does it rely on things like separate logins/roles per tenant?", "options": ["yes checks tenant ID", "relies on separate logins/roles", "mixed", "unknown"], "controls": ["ITC-03", "TAI-02"]},
    {"id": "BQ-014", "priority": "extended", "prompt": "Do admin/support staff or machine-to-machine credentials have tenant-scoped access, or do they have broad/global access?", "options": ["tenant-scoped", "broad/global", "mixed", "unknown"], "controls": ["ITC-05"]},

    # --- Tenant Lifecycle & Onboarding ---
    {"id": "BQ-015", "priority": "essential", "prompt": "Is there a system of record (database, table, config service) that tracks each tenant's identity, plan/tier, and status?", "options": ["yes complete", "partial", "no", "unknown"], "controls": ["TLO-01"]},
    {"id": "BQ-016", "priority": "essential", "prompt": "Is onboarding a new tenant automated, or manual/scripted by a human each time?", "options": ["fully automated", "partially automated", "manual", "unknown"], "controls": ["TLO-02"]},
    {"id": "BQ-017", "priority": "extended", "prompt": "Can a tenant's plan/tier be changed without an engineer manually intervening?", "options": ["yes self-service or automated", "requires engineer", "no tier changes supported", "unknown"], "controls": ["TLO-03", "TLO-04"]},
    {"id": "BQ-018", "priority": "extended", "prompt": "Is there a defined process for offboarding a tenant (data retention/deletion)?", "options": ["yes automated", "yes but manual", "no defined process", "unknown"], "controls": ["TLO-05"]},

    # --- Observability & Operational Readiness ---
    {"id": "BQ-019", "priority": "essential", "prompt": "Do your alarms/SLOs distinguish which tenant or tier is impacted, or are they all fleet-wide averages?", "options": ["tenant/tier-aware", "fleet-wide only", "partially", "unknown"], "controls": ["OOR-01", "OOR-02"]},
    {"id": "BQ-020", "priority": "extended", "prompt": "Is there a centralized dashboard showing tenant health across the system?", "options": ["yes", "partially", "no", "unknown"], "controls": ["OOR-03", "OOR-05"]},
    {"id": "BQ-021", "priority": "extended", "prompt": "When there's an incident, can you quickly tell which tenants were affected?", "options": ["yes", "partially", "no", "unknown"], "controls": ["OOR-02", "OOR-05", "TAI-04"]},

    # --- Deployment & Platform Automation ---
    {"id": "BQ-022", "priority": "extended", "prompt": "Do you use a CI/CD pipeline with approvals/rollback for deploying app code (not just infra)?", "options": ["yes with approvals and rollback", "yes basic pipeline", "no", "unknown"], "controls": ["DPA-02", "DPA-03"]},
    {"id": "BQ-023", "priority": "extended", "prompt": "Do all tenants run the same software version, or do some run older/custom forks?", "options": ["same version", "mostly same with exceptions", "multiple versions", "unknown"], "controls": ["DPA-05", "DPA-06"]},
    {"id": "BQ-024", "priority": "extended", "prompt": "Do you track release frequency, lead time, or rollback rate?", "options": ["yes", "partially", "no", "unknown"], "controls": ["DPA-06"]},

    # --- Cost Attribution & Metering ---
    {"id": "BQ-025", "priority": "essential", "prompt": "Do you have (or plan) billing/usage events tied to tenant + timestamp + unit, for usage-based pricing?", "options": ["yes in production", "planned", "no", "unknown"], "controls": ["CAM-02", "CAM-03"]},
    {"id": "BQ-026", "priority": "extended", "prompt": "Can you currently estimate cost-per-tenant, even roughly?", "options": ["yes accurately", "roughly", "no", "unknown"], "controls": ["CAM-03", "CAM-05", "CAM-06"]},
    {"id": "BQ-027", "priority": "extended", "prompt": "Do your commercial tiers map to specific technical limits/features in the product?", "options": ["yes clearly mapped", "partially", "no", "unknown"], "controls": ["CAM-04", "SBR-02"]},

    # --- Service Model & Business Readiness ---
    {"id": "BQ-028", "priority": "extended", "prompt": "Do you track time-to-value/activation for new tenants?", "options": ["yes", "partially", "no", "unknown"], "controls": ["SBR-03", "SBR-04"]},
    {"id": "BQ-029", "priority": "extended", "prompt": "Do you have retention/churn/feedback loops feeding back into product decisions?", "options": ["yes", "partially", "no", "unknown"], "controls": ["SBR-04", "SBR-05"]},
    {"id": "BQ-030", "priority": "essential", "prompt": "Is there one clearly-owned 'SaaS operating model,' or is this more like managed hosting per customer today?", "options": ["clear SaaS operating model", "moving toward SaaS", "managed hosting", "unknown"], "controls": ["SBR-01", "SBR-06"]},
]


def all_controls() -> list[dict]:
    """Return controls with dimension metadata attached."""
    controls = []
    for dimension in DIMENSIONS:
        for control in dimension["controls"]:
            enriched = dict(control)
            enriched["dimension_id"] = dimension["id"]
            enriched["dimension_name"] = dimension["name"]
            enriched["dimension_weight"] = dimension["weight"]
            enriched["dimension_why"] = dimension["why"]
            controls.append(enriched)
    return controls
