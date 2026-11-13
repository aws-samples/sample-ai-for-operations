# BYOC Infrastructure Discovery Agent

Answers AWS region, availability zone (AZ), AMI, instance-type, and Amazon EKS
metadata queries for **any AWS region — including regions not enabled in your
account** — by unifying account-independent public sources (SSM global-
infrastructure parameters, the AWS Price List API) with live read-only calls
into one trusted source.

Built for the Bring-Your-Own-Cloud (BYOC) case: when a customer arrives from a
region you have never enabled, you can still discover the foundational
infrastructure facts needed to deploy there, and get a **deployability verdict**
instead of just raw data.

> **Disclaimer:** This sample is provided for demonstration and educational
> purposes only and is not intended for production use without additional
> security review and testing. See [Scope and limitations](#scope-and-limitations)
> for the hardening you should add before deploying it in a production
> environment.

## Why this exists

Previously these facts were collected by ad-hoc CLI calls and documentation
scraping, then frozen into static files. Static files break the moment a
customer comes from a region you never enabled, and several live calls
(`describe-availability-zones`, `describe-instance-type-offerings`, regional SSM
AMI endpoints) do not work for non-enabled regions or are blocked by Service
Control Policies or unreachable endpoints. This agent resolves each fact through
an account-independent primary source first, falling back to live calls only as
enrichment.

## Architecture

- **Compute:** AWS Lambda (Python 3.12, ARM64), invoked programmatically by
  provisioning automation.
- **Reasoning:** a Strands agent backed by Amazon Bedrock. The model only routes
  queries and narrates verdicts/reconciliation — it never emits a region code,
  AZ ID, AMI ID, or verdict from its own knowledge.
- **Tools:** eleven pure-code tools split into *data retrieval* (call AWS /
  read bundled data) and *precision* (exact counting, filtering, verdict, and
  response assembly). No tool runs an LLM.

## Invocation contract

Input event (direct invoke or Amazon API Gateway body):

```json
{ "query": "Is eu-south-2 ready for an EKS node group on m6i.large?" }
```

The agent returns **structured JSON only**, in one of three shapes.

### Fact passthrough

```json
{
  "query_mode": "fact",
  "dataset": "availability_zones",
  "region": "ap-southeast-7",
  "result": {
    "azs": [{ "az_id": "apse7-az1" }, { "az_id": "apse7-az2" }, { "az_id": "apse7-az3" }],
    "az_names_available": false
  },
  "source": "ssm-global-infrastructure",
  "confidence": "high"
}
```

When AZ names cannot be obtained (region not enabled), only AZ **IDs** are
returned and `az_names_available` is `false`. AZ names are never fabricated.

### Readiness investigation

```json
{
  "query_mode": "readiness",
  "region": "eu-south-2",
  "target": { "instance_type": "m6i.large", "eks_version": "1.30" },
  "verdict": "blocked",
  "blockers": [
    {
      "code": "no-ami-published",
      "severity": "blocking",
      "reason": "No matching AMI is published in this region; the EKS API-server proxy cannot be provisioned."
    }
  ],
  "facts": {
    "availability_zones": { "azs": [{ "az_id": "eus2-az1" }], "az_names_available": false, "source": "ssm-global-infrastructure" },
    "ami": { "ami_available": false, "source": "ec2-live" }
  },
  "confidence": "medium"
}
```

`verdict` is one of `ready`, `degraded`, `blocked`, computed by a deterministic
precision tool — never by the model.

### Error

```json
{ "error": true, "error_type": "invalid_region", "message": "Region 'xx-fake-1' not found." }
```

## Data sources

| Dataset | Primary source (account-independent) | Live enrichment (region enabled) |
|---------|--------------------------------------|----------------------------------|
| Regions + long names | SSM `/aws/service/global-infrastructure/regions` | — |
| AZ IDs | SSM `.../regions/<r>/availability-zones` | `ec2:DescribeAvailabilityZones` adds AZ names |
| Service availability (Amazon EC2, Amazon EKS) | SSM `.../services/{ec2,eks}/regions` | — |
| Instance-type attributes | AWS Price List API `GetProducts` | `ec2:DescribeInstanceTypes` (precise arch/storage) |
| Instance-type offerings | AWS Price List API | `ec2:DescribeInstanceTypeOfferings` |
| AMIs | public SSM AMI parameter | `ec2:DescribeImages` |

### Curated (no public API) datasets

Bundled as versioned JSON in `src/data/`, each with `_source` and
`_last_updated` provenance:

| File | Contents | Source |
|------|----------|--------|
| `eks_ecr_registries.json` | Amazon EKS add-on ECR registry account per region | EKS add-on images documentation |
| `eni_max_pods.json` | ENI max pods per instance type | amazon-vpc-cni-k8s eni-max-pods list |
| `s3_location_constraints.json` | Amazon S3 CreateBucket LocationConstraint per region | S3 CreateBucket API documentation |
| `eks_eol_dates.json` | Amazon EKS Kubernetes version end-of-support dates | EKS Kubernetes versions documentation |

For authoritative ENI max-pods on a specific node, read the value live from the
node; the bundled table is a pre-calculation aid and may lag new instance types.

## Configuration

All configuration is via environment variables (see `src/config.py`). No values
are hardcoded.

| Variable | Default | Purpose |
|----------|---------|---------|
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Amazon Bedrock model (inference-profile ID) |
| `BEDROCK_REGION` | `us-east-1` | Bedrock region |
| `BEDROCK_MAX_TOKENS` | `4096` | Max response tokens |
| `BEDROCK_TEMPERATURE` | `0.2` | Low — this is a factual task |
| `GUARDRAIL_ID` / `GUARDRAIL_VERSION` | Set by the CDK stack | Amazon Bedrock Guardrail created by the stack. Unset only when running outside the stack, in which case no guardrail is applied |
| `GLOBAL_SOURCE_REGION` | `us-east-1` | Endpoint for account-independent SSM reads |
| `PRICING_REGION` | `us-east-1` | AWS Price List API endpoint |
| `CACHE_TTL_SECONDS` | `3600` | Cache lifetime |
| `CACHE_TMP_DIR` | `/tmp/byoc-cache` | On-disk cache tier |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `LIVE_CALL_CONNECT_TIMEOUT` / `LIVE_CALL_READ_TIMEOUT` / `LIVE_CALL_MAX_ATTEMPTS` | `3` / `5` / `2` | Fast-fail on unreachable regional endpoints |

Caching is **in-memory + `/tmp` only** — no paid store. The primary SSM/Pricing
calls are free, so a cache miss costs latency, not dollars.

## Development

```bash
make install-dev      # install runtime + dev dependencies into .venv
make test-all         # run all tests with coverage (>= 80% gate on tools)
make lint             # ruff
```

Tests: 86 passing, ~90% coverage. Unit tests mock all AWS clients; the
integration test exercises the non-enabled-region readiness flow.

## Scope and limitations

This is a reference sample, not a turnkey production service. It deliberately
leaves the following hardening to the adopter, and you should add it before any
production use:

- **Amazon Bedrock Guardrails policies.** The CDK stack always creates an
  Amazon Bedrock Guardrail and sets `GUARDRAIL_ID` and `GUARDRAIL_VERSION` on
  the function; there is no option to skip it. The guardrail configures only
  content filters (hate, insults, sexual, violence, misconduct at HIGH strength).
  It does not configure a prompt-attack filter, denied topics, or a
  sensitive-information (PII) filter. Add the policies your use case needs
  before production. If you run the agent outside the stack (for example,
  locally) without both variables set, no guardrail is applied.
- **Caller authentication and authorization.** The Lambda handler trusts any
  caller that can invoke it; there is no authentication in the sample. Front it
  with an authenticated ingress (IAM-authenticated SDK invoke, or Amazon API
  Gateway with an IAM/Amazon Cognito authorizer) and apply request throttling.
- **Input limits and abuse protection.** There is no query-length cap or
  per-caller rate limiting. Add input size limits, throttling, and Lambda
  reserved concurrency to bound cost and abuse.
- **Logging and audit.** Logs carry no caller identity; rely on AWS CloudTrail
  and (if fronted) API Gateway access logs for attribution. Add a
  customer-managed KMS key on the log group if your compliance regime requires
  it.
- **Network isolation.** The function runs in the Lambda-managed network. If
  your environment requires it, place it in a VPC with the appropriate endpoints
  and egress controls.
- **Dependency pinning.** `requirements.txt` uses minimum-version ranges so the
  sample picks up compatible security patches. For production, pin exact
  versions and manage upgrades through a lockfile and your own review cadence.

See [SECURITY.md](SECURITY.md) for the full STRIDE threat model and the
mitigation status of each item.

## Deployment

Requires AWS CDK v2 and Node.js 20+.

```bash
make deploy
# or:
cd infra && npm ci && npx cdk deploy --require-approval never
```

The Lambda code bundles via a local pip build (uses the project `.venv` when
present) and falls back to a container build, so a running Docker daemon is not
required. Configure the model or cache TTL at deploy time:

```bash
cd infra && npx cdk deploy -c modelId=us.anthropic.claude-sonnet-5-20250930-v1:0 -c cacheTtlSeconds=1800
```

> **Model IDs:** current Claude models on Amazon Bedrock are invoked through a
> region-prefixed **inference profile** (e.g. `us.anthropic.claude-sonnet-4-5-...`),
> not the bare on-demand model ID — the latter returns `ValidationException`.
> List what your account supports with:
> ```bash
> aws bedrock list-inference-profiles \
>   --query "inferenceProfileSummaries[?contains(inferenceProfileId,'sonnet')].[inferenceProfileId,inferenceProfileName]" \
>   --output table
> ```
> The stack grants `bedrock:InvokeModel` on both the inference-profile ARN and
> the underlying foundation-model ARN automatically.

The stack provisions the Lambda, a read-only execution role, an Amazon Bedrock
Guardrail, a structured log group, X-Ray active tracing, and CloudWatch alarms
for error rate (>5%) and P99 latency (>30s).

## Security

- The execution role is **read-only**. There are no mutating actions on any AWS
  environment, so no `MUTATING_ACTIONS.md` is required. The reference policy is
  in `infra/policies/execution-role-policy.json`.
- `Resource: "*"` appears only on read-only/telemetry actions
  (`pricing:GetProducts`, five enumerated `ec2:Describe*` actions, and
  `xray:Put*`) that do not support resource-level scoping. SSM reads are scoped
  to the `global-infrastructure` parameter ARN.
- The stack always creates an Amazon Bedrock Guardrail (content filters only)
  and wires it to the function. See [Scope and limitations](#scope-and-limitations)
  for the guardrail policies it does not configure.
- See [SECURITY.md](SECURITY.md) for the full threat model.

### Known build-time advisory

`npm audit` reports a high-severity advisory for `brace-expansion`, a transitive
dependency vendored inside `aws-cdk-lib`. It is a **build-time-only** DoS
advisory and does not ship to the Python Lambda runtime. It cannot be resolved
without forcing a CDK version change, so it is intentionally left as-is.

## Specification

The full spec (requirements, design, tasks) lives in
`.kiro/specs/byoc-infra-discovery/`.

## License

MIT — see [LICENSE](LICENSE).
