# network-routing-drift (AWS DevOps Agent skill)

Teaches AWS DevOps Agent how to investigate the NEW drift findings that the
network-routing-drift-checker hands over through its webhook:

- find the change (CloudTrail) or AWS Health event behind each finding;
- group findings into incidents and rank them by blast radius;
- end with the `nrdc-investigation/v1` JSON block the checker's callback parses.

The skill is read-only and advisory: evidence, hypotheses and `describe-`/`get-`/`list-`/`search-`
validation commands only.

## Prerequisites

- **Upload two skills to the Agent Space:** this one and the public
  [`aws-routing`](https://github.com/aws/tools-for-devops-agent/tree/main/skills/aws-routing)
  skill, which supplies the route-evaluation reasoning.
- **Give the Agent Space role in the networking account read access.** That is the primary-source
  role when the Agent Space is in the same account, or the secondary-source role otherwise.
  [`AIDevOpsAgentAccessPolicy`](https://docs.aws.amazon.com/devopsagent/latest/userguide/aws-devops-agent-security-devops-agent-iam-permissions.html)
  covers CloudTrail, AWS Health, Transit Gateway, Direct Connect and most Network Manager reads.
  Add these two actions, which it doesn't include (checked against policy version 11):
  ```json
  {"Effect": "Allow", "Action": ["networkmanager:GetNetworkRoutes", "networkmanager:GetCoreNetworkChangeEvents"], "Resource": "*"}
  ```
  Without the read access, the skill still answers, but with `low` confidence and "No evidence
  found".
- **An active CloudTrail trail** capturing management events in the evaluated Regions and in
  us-west-2 (Network Manager).

## Install

1. Run `scripts/package-skill.sh` from the repository root. It writes
   `dist/network-routing-drift.zip`.
2. In the Agent Space Operator Web App, open Knowledge → Skills → Add skill → Upload skill, and
   upload the zip. Leave the agent type at **Generic**: webhook investigations run as incident
   triage and RCA.
3. Repeat for `aws-routing`, or use Import from repository with its GitHub URL.

See [DevOps Agent Skills](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-devops-agent-skills.html)
for the upload limits (zip ≤ 6 MB, no `scripts/` directory).

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Activation, procedure, grouping, evidence and confidence rules, blast radius, boundaries, output template |
| `references/finding-kinds.md` | Every finding kind: meaning, family, where to start |
| `references/cloudtrail-event-map.md` | Family → CloudTrail event names |
| `references/health-event-map.md` | Family → AWS Health event families |
| `references/output-schema.json` | JSON Schema of the result block (identical to the checker's copy) |
| `evals/` | Trigger queries and functional evals (tools-for-devops-agent format) |

## Versioning

`metadata.version` in `SKILL.md` follows semver. A change to the output block is a major version and
must ship together with the matching checker version.
