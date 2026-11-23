# Deployment Security Examples

These examples cover the deployment-side controls that `SECURITY.md` asks for.
They are starting points: review them against your organization's policies
before you deploy. The sample itself provisions no infrastructure.

## 1. Least-privilege IAM for AWS discovery

`docs/iam/` holds two IAM policies generated from the action lists in
`src/discovery.py`:

| File | Use it when |
|---|---|
| `discovery-minimum-policy.json` | Default single-account assessment (`MINIMUM_READ_ONLY_ACTIONS`) |
| `discovery-enhanced-policy.json` | `access_mode: enhanced_assessment`, adding AWS Organizations, Cost Explorer, Control Tower, and IAM policy simulation (`ENHANCED_READ_ONLY_ACTIONS`) |

Every action is a Describe, List, Get, or Simulate call. `Resource` is `*`
because most of these list operations do not support resource-level
permissions; none of them can change a resource. A unit test fails if the files
drift from the code. To regenerate them after changing the action lists:

```bash
python -m src.iam_policies --write
```

Attach the policy to the role or user whose credentials run discovery:

```bash
aws iam create-policy \
  --policy-name SaasReadinessDiscoveryReadOnly \
  --policy-document file://docs/iam/discovery-minimum-policy.json
aws iam attach-role-policy \
  --role-name <discovery-role> \
  --policy-arn arn:aws:iam::123456789012:policy/SaasReadinessDiscoveryReadOnly
```

Grant only one of the two policies. Do not add any write permissions; the agent
never needs them.

## 2. Caller authentication for AgentCore Runtime (threat T001)

The runtime trusts the `assessment_id` and `contributor_id` in each request.
Assessment IDs route state; they are not secrets. A deployment therefore needs
two things: callers must be **authenticated**, and each caller must be
**authorized** for the assessment they name.

### Authenticate callers with a JWT authorizer

Configure inbound authentication on the runtime with an OAuth 2.0 / OIDC
identity provider such as an Amazon Cognito user pool. Requests without a valid
token are rejected before the agent runs. Example `authorizerConfiguration` for
`CreateAgentRuntime` (see
[Authenticate and authorize with Inbound Auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-oauth.html)):

```json
{
  "authorizerConfiguration": {
    "customJWTAuthorizer": {
      "discoveryUrl": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration",
      "allowedClients": ["<app-client-id>"]
    }
  }
}
```

With the AgentCore CLI:

```bash
agentcore add runtime \
  --name SaasReadinessAgent \
  --language python \
  --protocol HTTP \
  --authorizer-type CUSTOM_JWT \
  --authorizer-configuration \
  '{"customJwtAuthorizer":{"discoveryUrl":"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration","allowedClients":["<app-client-id>"]}}'
```

### Enforce assessment membership

Authentication alone does not stop one authenticated caller from naming another
assessment's ID. Choose one of these:

- **One runtime per customer organization (simplest).** Deploy a separate
  runtime, Memory resource, and user pool (or app client) per customer, so every
  authenticated caller of that runtime belongs to the same organization and may
  see all of its assessments.
- **A membership check in front of the runtime.** Put an application layer
  (for example Amazon API Gateway with an AWS Lambda authorizer) between callers
  and the runtime. It validates the token, looks up which assessments the
  caller's identity may use, rejects any other `assessment_id`, and sets
  `contributor_id` from the authenticated identity instead of trusting the
  request body.

## 3. Amazon Bedrock Guardrail (threat T003)

`docs/examples/guardrail.json` defines a guardrail with a high-strength
prompt-attack filter on input, content filters, and sensitive-information
filters that block AWS keys and passwords and mask emails and phone numbers.
Create it and publish a version:

```bash
aws bedrock create-guardrail --cli-input-json file://docs/examples/guardrail.json
aws bedrock create-guardrail-version --guardrail-identifier <guardrail-id>
```

Then configure the agent with both values together:

```bash
export BEDROCK_GUARDRAIL_ID=<guardrail-id>
export BEDROCK_GUARDRAIL_VERSION=1
```

When both are set, the agent enables guardrail tracing and input and output
redaction on every model call. Test the guardrail with your expected prompts
and check for false positives before you deploy it.
