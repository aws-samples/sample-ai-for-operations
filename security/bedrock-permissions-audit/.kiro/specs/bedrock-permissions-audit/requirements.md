# Amazon Bedrock Permissions Audit — Requirements

Master spec. This document is the source of truth for what the solution does.

## 1. Purpose

The tool answers one question, for one AWS account or a whole AWS Organization:

> Which long-lived credentials (IAM user access keys, root access keys, Amazon Bedrock API keys) can
> invoke Amazon Bedrock models today, how exposed is each one, and what should be done first?

It is a point-in-time, read-only review of IAM configuration. It assigns each credential a risk tier
and one recommended action. The preferred outcome of a finding is to replace the long-lived credential
with a short-lived one: IAM Identity Center for people, IAM roles for workloads. The tool does not
monitor usage and does not enforce anything.

Related AWS capabilities, which this tool does not replace:

| Capability | What it covers |
|---|---|
| IAM Access Analyzer (unused access) | Reports unused access keys, roles, and permissions |
| GuardDuty AI Protection (`Impact:IAMUser/CostHarvesting`, `AnomalousModelInvocation`) | Detects anomalous model invocation |
| `AWSCompromisedKeyQuarantineV3` | AWS managed policy that AWS attaches to access keys it detects as publicly exposed |
| AWS Organizations SCP examples for Amazon Bedrock | Example policies that restrict Amazon Bedrock |

## 2. Solution shape and the "why not an agent" decision

This is a **deterministic command-line tool**, not an AI agent. The job (enumerate principals,
evaluate permissions, score, rank, print) is the same fixed set of steps on every run; no step depends
on interpreting unstructured data or adapting the investigation path. The framework's use-case
validation (Filter 2, agentic reasoning) therefore routes it to automation. The framework is used for
its spec discipline, security review, and aws-samples release process; the agent-specific gates
(Amazon Bedrock Guardrails, system prompts, tool classification for an LLM) do not apply and the build
and release phases must not block on them.

AWS DevOps Agent was deliberately not used: the target customers do not have it.

## 3. Users and modes

**Primary user:** a customer's cloud security or platform team, running the tool from a laptop or a
CI job with their own credentials. A TAM may run it alongside the customer during an incident.

**Mode A: Organization-wide.** Run from the management account or a delegated administrator account.
The tool lists all active member accounts, assumes a read-only role in each, audits each account, and
merges the results into one ranked list with the account ID on each row. The account the credentials
belong to is audited directly, without assuming a role.

**Mode B: Single account.** Audits only the account the credentials belong to. Chosen with
`--single-account`, or automatically (with a printed notice) when the caller cannot list the
organization's accounts and the mode is `auto`. Same output format.

Mode B must work with no extra setup beyond read-only IAM permissions. Mode A uses a read-only
least-privilege role by default: `BedrockPermissionsAuditRole`, created by the shipped template
`infra/audit-role.yaml`. It must accept a customer-chosen role name. An administrator role such as
`OrganizationAccountAccessRole` is never the default and is not named in the shipped caller policy; a
customer can still pass it with `--role-name`, knowingly, for a short trial.
Forcing organization mode (`--mode org`) when the caller cannot list accounts is an error, not a
silent fallback.

## 4. Credentials in scope

Long-lived credentials only. Roles are out of scope: they issue temporary credentials and have
nothing to leak at rest.

| Credential | How it is found |
|---|---|
| IAM user access keys | `ListAccessKeys` for every user; last use from `GetAccessKeyLastUsed` |
| Root access keys | IAM credential report (`<root_account>` row). The report can be up to four hours old, and omits users created since; so nothing about IAM users, including MFA state (`ListMFADevices`), is taken from it |
| Amazon Bedrock long-term API keys | `ListServiceSpecificCredentials` for `bedrock.amazonaws.com`, listed account-wide. These can belong to **any** IAM user, not only the `BedrockAPIKey-*` users the console creates. The user name is never the discovery mechanism for a key |
| Claude Platform on AWS API keys | `ListServiceSpecificCredentials` per `AeaApiKey-*` user |

A `BedrockAPIKey-*` or `AeaApiKey-*` user is an "API key user". The user name is used for one purpose
only: to find an API key user that has no credential at all, which no credential listing can return.
If an API key user has no active credential left it is reported once as **orphaned**, because it was
never cleaned up and still carries a policy.

**Credential report age.** IAM may serve a credential report up to four hours old. Because the report
is used only for the root account's access keys, its age affects only those: a root access key created
since the report was generated would not appear. The tool records when each account's report was
generated, shows it in the per-account table (section 7), and warns when it is more than one hour old.

**Partial evaluation.** A role can lack `iam:ListServiceSpecificCredentials` while holding the rest of
the read-only policy. When the account-wide listing of Amazon Bedrock API keys is denied, the account
is not failed and is not silently reported without those keys. It is audited for everything else and
marked **partial**, with the reason, in the summary, the per-account table, and `findings.json`. Any
`BedrockAPIKey-*` or `AeaApiKey-*` user is then reported as orphaned, because its keys cannot be seen.
A partial account is counted separately from a failed one. Every other missing permission still fails
the account (section 5).

Users with no access key, no API key, and no API-key-user name (console-only users) are not in
scope.

Deactivating an access key does not invalidate its secret: anyone who can call `iam:UpdateAccessKey`
on the user can re-enable it, and it then works with the same permissions. An inactive access key
that would rate Critical or High if it were active is therefore reported (as Low, section 6) so that
it is visible by default. Every other inactive or expired credential is reported only with `--all`.
Who can re-enable a key is not evaluated. An inactive Amazon Bedrock or Claude Platform API key is
treated the same way, because it can be re-enabled with `iam:UpdateServiceSpecificCredential`.
Expired credentials cannot be re-enabled and stay Info.

**Known data gap:** IAM does not report when a long-term API key was last used. Those keys show
"unknown" for last use and are never labelled dormant on that basis.

## 5. Permission evaluation

For each in-scope principal, the tool determines what it **can** do, using
`iam:SimulatePrincipalPolicy`. This accounts for inline policies, attached managed policies, group
policies, and permission boundaries, and costs nothing.

Actions tested (all configurable):

| Group | Actions | Why it matters |
|---|---|---|
| Invoke | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock:Converse`, `bedrock:ConverseStream`, `bedrock:CallWithBearerToken`, `bedrock-mantle:CallWithBearerToken` | Any one allowed means the principal "can invoke" Amazon Bedrock models. Both bearer-token actions matter because API keys work through two endpoints |
| Escalation | `aws-marketplace:Subscribe`, `bedrock:CreateMarketplaceModelEndpoint`, `iam:CreateServiceSpecificCredential` | Allows enabling more models, or creating new API keys that outlive a rotated access key |
| Canary | `bedrock:DeleteCustomModel`, `bedrock:PutModelInvocationLoggingConfiguration`, `bedrock:DeleteGuardrail`, `bedrock:CreateProvisionedModelThroughput`, `bedrock:DeleteAgent`, `bedrock:DeleteKnowledgeBase` | **All** allowed on `*` means the principal effectively holds `bedrock:*`, without simulating every Amazon Bedrock action. They are unrelated management actions on purpose: one of them alone is granted by narrower managed policies such as `AmazonBedrockLimitedAccess`, which lists explicit actions and is not `bedrock:*`. An empty list never claims `bedrock:*` |

Escalation actions that IAM normally grants on a specific user (`iam:CreateServiceSpecificCredential`)
are also tested against the principal's own ARN, since a test against `*` alone would miss them.

**Broad versus scoped.** A grant is **broad** if an invoke action is allowed on `*`, or on enough sample
model and inference-profile ARNs that it is effectively unrestricted (for example a policy on every
foundation model). It is **scoped** if only some sample ARNs are allowed, and the allowed Regions are
recorded. Sample ARNs cover every Region plus several model providers and inference-profile forms,
because the simulator matches resource ARNs as strings.

A fixed sample cannot know every model, so the sample also includes the resources that the user's own
identity-based policies name. The Resource entries of Allow statements that cover the invoke actions
are read from the user's inline, attached managed and group policies, and each is tested, so a model
outside the sample (a policy that allows only `amazon.titan-text-lite-v1`, say) is found and reported
as scoped. The policy documents are read in memory only to extract resource names; they are never
stored or written to any output. If a policy names Amazon Bedrock resources and every one of them is
denied without an explicit deny, the grant is `unknown` and the principal is shown for manual review,
because a condition, a permissions boundary or an unlisted action may be hiding access. An explicit
deny is a definite answer and gives `none`. Principals with a broad grant need no policy reads.

Results are recorded per action as allowed / explicit deny / implicit deny, with the names of the
policies that matched (never policy contents) and any condition keys the simulator had no value for.

**Known limitations (stated in the output and README):**

* The simulator does not evaluate Service Control Policies or Resource Control Policies. A principal
  reported as "can invoke" may be blocked at the organization level.
* "Cannot invoke" is not a guarantee. A statement that allows access only under a condition the
  simulator has no value for (source IP, MFA session, some tags) is reported as not allowing access.
  Such principals are hidden unless `--all` is given, so they can be missed. The reverse also holds:
  a grant conditioned on request context can simulate as allowed, so the tool may over-report. The
  condition keys the simulator had no value for are recorded per action in `findings.json`
  (`missing_context`), so the customer can judge whether a condition narrows real-world reach.
* A principal is judged on its own identity-based permissions only. A key whose own policy grants
  nothing beyond `sts:AssumeRole`, but which can assume a role that can invoke Amazon Bedrock, is
  reported as unable to invoke. Following one hop of `AssumeRole` is a candidate for a later version.

The root user is not subject to IAM policies and is treated as allowed for everything without
simulation. A principal whose simulation fails for a transient reason is reported with grant
`unknown`. A missing-permission or expired-credential error fails the account instead, because it
would affect every principal; the one exception is the account-wide API key listing, which marks the
account partial (section 4) because the rest of that account's findings remain valid.

## 6. Risk ranking

Dormancy is weighted heavily: a credential that no workload uses is the least likely to be noticed if
it is used unexpectedly. `N` is the dormancy threshold in days (default 90, configurable). A credential is **dormant** if it was never
used or has been unused for at least `N` days, and **old** if it is at least `N` days old.

Rules apply in order and the first match wins:

| # | Condition | Tier |
|---|---|---|
| 1 | Root account with an active access key | Critical |
| 2 | Orphaned API key user | Medium |
| 3 | Credential inactive or expired. An inactive IAM access key (not root), or an inactive Amazon Bedrock or Claude Platform API key, that would rate Critical or High if it were active is **Low**; the reasons say it is inactive but works again if re-enabled, name the call that does it, and give what it would rate. Everything else, including root keys and expired credentials, is Info | Low or Info |
| 4 | Permissions could not be evaluated | Info, but always shown |
| 5 | Can invoke Amazon Bedrock **and** holds an admin-class policy, or has the canary action, or has an escalation action | Critical |
| 6 | Can invoke **and** the credential is dormant, or old, or (access keys only) the user has no MFA | High |
| 7 | API key on an API key user, unless the simulator found no access at all | High |
| 8 | Can invoke with a broad grant | Medium |
| 9 | Can invoke with a scoped grant | Low |
| 10 | Otherwise | Info |

MFA is ignored for API keys because a bearer token cannot use it. Dormancy is ignored for API keys
because their last use is unknown. Admin-class policies are configurable and default to
`AdministratorAccess`, `PowerUserAccess`, and `AmazonBedrockFullAccess`.

Order: tier, then (within Low) an inactive key that would rate Critical if re-enabled, then one that
would rate High, then every other finding; then root first, then dormant first, then older first, then
wider Region coverage, then account and principal name for stability.

Info rows are hidden unless `--all` is given, with one exception: a principal that could not be
evaluated is always shown, because hiding it would make an incomplete audit look clean. The summary
counts hidden Info findings by cause: an active credential that cannot invoke Amazon Bedrock, and an
inactive or expired credential.

Each row carries the reasons for its tier and **one recommended action** chosen by rule, for example:
delete the root access key; delete a dormant key (stating how long it was unused); remove the escalation
action and move the workload to a role; delete or rotate an API key and deny both bearer-token actions;
delete an orphaned API key user; replace an IAM user with a role; delete an inactive access key that
could be re-enabled.

## 7. Output

Report only. The tool never modifies anything.

1. **Terminal report:** a table of ranked findings (tier, account, principal, credential type, masked
   key ID, key age, last used, MFA, grant), each followed by its recommended action and **all** of its
   reasons (none are dropped), then a summary: accounts scanned, partial and failed with reasons,
   principals evaluated, count per tier, number of hidden Info findings with the count for each cause
   (for example "3 Info findings hidden (1 cannot invoke Amazon Bedrock, 2 expired or inactive
   credentials)"), a per-account table, warnings, and the limitations.

   For an inactive key reported as Low, the reasons that follow "If re-enabled it would rate <Tier>:"
   are printed indented under that line, so the evidence for the would-be tier reads as part of it.

   "Last used" comes from IAM and reflects the key's most recent call to **any** AWS service, not
   necessarily Amazon Bedrock. It is a dormancy signal, not evidence of Amazon Bedrock use. The same
   applies to the Region recorded with it.

   **Per-account table.** One row per audited account (`ok` or `partial`): account ID, name, status,
   principals evaluated, count of visible findings per tier, and when the credential report was
   generated. Rows sort by Critical count, then High count, then account ID, so the account to start
   with comes first. Mode B prints the same table with one row. Mode A findings tend to concentrate in
   a few accounts, and this shows where without filtering the CSV.
2. **`findings.csv`:** one row per credential, spreadsheet-ready. Cell values that a spreadsheet could
   execute as a formula are neutralised.
3. **`findings.json`:** the same findings with per-action simulation results, matching policy names,
   the run summary, the limitations, and a schema version. Each finding has `if_reactivated_tier`:
   `"CRITICAL"` or `"HIGH"` for an inactive access key reported because it would rate that if
   re-enabled, otherwise null. The CSV has a matching last column. The run summary carries the
   per-account table (`run.accounts`), the partial accounts with their reasons, and, per account, when
   the credential report was generated. `run.hidden_info_by_reason` counts the hidden Info findings by
   cause (`cannot_invoke`, `inactive_or_expired`); the counts sum to `run.hidden_info`.
4. **`remediation/`:** generated, ready-to-review policy documents and a `README.txt`:
   * an SCP denying Amazon Bedrock invocation to IAM users and to the account root user (roles and
     IAM Identity Center users are unaffected), with a configurable exception list;
   * an SCP restricting Amazon Bedrock to the Regions and models the customer names, written only
     when the customer names at least one;
   * an identity policy denying use of Amazon Bedrock API keys through both endpoints and creation of
     new ones.

   Every statement ID begins with `ReviewBeforeApplying` (AWS rejects unknown top-level policy keys,
   so the marker lives in the statement). The documents are suggestions: the tool never applies them.

Access key IDs are masked (`...abcd`) everywhere unless the user passes `--unmask`. Output defaults to
`./bedrock-audit-<UTC timestamp>/`, created owner-only (directory `0700`, files `0600`). Nothing is
sent anywhere.

## 8. Non-functional requirements

* **Read-only.** Every AWS API call is a read (`Get*`, `List*`, credential report, `Simulate*`) plus
  `sts:AssumeRole` for member accounts. The one call that is not a pure read,
  `iam:GenerateCredentialReport`, only refreshes the report IAM itself retains. The shipped IAM policy
  grants only these. No mutating action exists in the code, and a build gate proves it.
* **No LLM, no network beyond AWS APIs, no telemetry.**
* **Scale.** An organization of 500 accounts with 100 users each completes in under 30 minutes on a
  laptop with bounded cross-account parallelism, using adaptive retry on throttling.
* **Resumable.** Each completely audited account is checkpointed. `--resume` skips those accounts
  and regenerates the same outputs an uninterrupted run would produce. A checkpoint is ignored if any
  setting that affects scoring has changed. Failed and partial accounts are always retried, so a
  permission fixed between runs is picked up. Existing results are
  never overwritten without `--resume`.
* **Partial failure is a result, not a crash.** An account whose role cannot be assumed, or whose
  credential report times out, is listed in the summary with the reason; the others are still
  reported. An account audited without its Amazon Bedrock API keys (section 4) is listed separately as
  partial, with its findings still reported.
* **Exit codes.** `0` success including partial account failures; `2` configuration or credential
  error before any account was audited; `3` no account could be audited.
* **Regions.** Credential and policy data is global. "Last used region" comes from IAM. Region exposure
  is the set of Amazon Bedrock Regions in which a scoped grant was allowed, from a bundled and
  overridable list. Only the commercial partition is supported.
* **Configuration.** Thresholds, role name, action sets, admin policies, Region and model lists,
  output directory, and parallelism come from a TOML file and/or flags; nothing is hard-coded.
* **Runs with Python 3.12+ and boto3 only**, installable with `pip`.
* **Credential handling.** Uses the standard AWS credential chain; never reads key secrets. No API the
  tool calls returns a secret access key or API key value, only key IDs, metadata and timestamps.
* **Hostile input.** IAM names are attacker-influenced text. Control characters are stripped from
  everything printed, and spreadsheet formulas are neutralised in the CSV.
* **Logging.** Structured JSON lines on stderr. Anything shaped like an access key ID or API key is
  redacted.

## 9. Hard boundaries

1. The tool MUST NOT call any AWS API that creates, modifies, or deletes anything (beyond the credential
   report refresh and `AssumeRole`).
2. The tool MUST NOT invoke any Amazon Bedrock model or any other LLM.
3. The tool MUST NOT transmit findings or metadata off the host.
4. The tool MUST NOT require permissions beyond the documented read-only policy.
5. The tool MUST NOT claim an SCP- or RCP-aware verdict; the SCP and RCP limitation, and the
   `AssumeRole` limitation, are printed on every run.
6. Generated remediation documents are suggestions and MUST be marked "review before applying".
7. Output MUST NOT contain policy documents, only policy names.

## 10. Success criteria

* A customer with only read-only credentials can run Mode B and get a ranked list in one command.
* From a management account, with the dedicated role deployed to the member accounts by one
  StackSet, Mode A audits every active member account with no further setup. When the default role is
  missing in an account, that account's failure says so and how to fix it.
* Every Critical and High finding in a seeded test organization is found, and no principal without
  Amazon Bedrock permissions is ranked above Info (precision and recall both 100% on the fixture set).
* A dormant key with Amazon Bedrock access ranks above an actively used key with identical permissions.
* An Amazon Bedrock API key is detected and ranked even when its user has no IAM access key, and even
  when it belongs to a user that is not named `BedrockAPIKey-*`.
* A root access key always appears as the first row.
* Terminal output, CSV, and JSON contain the same set of findings (same count, same tiers).
* The security review for release finds no mutating IAM action anywhere in the code or shipped policy.

## 11. Acceptance scenarios

Implemented as automated tests against moto and recorded or rule-faithful fakes; no live account is
needed to run them.

| ID | Scenario | Expected |
|---|---|---|
| E1 | Org with 3 accounts; one role assumption fails | 2 accounts audited, 1 listed as failed with reason; exit code 0 |
| E2 | Caller lacks `organizations:ListAccounts` | Falls back to Mode B with an explicit notice; `--mode org` is an error |
| E3 | User with `AdministratorAccess` and an active key | Critical |
| E4 | `bedrock:InvokeModel` on `*`, key unused 200 days, MFA present | High (dormant) |
| E5 | Same as E4 but key used yesterday and 10 days old | Medium (broad grant) |
| E6 | `bedrock:InvokeModel` scoped to one model ARN, fresh key, MFA | Low |
| E7 | User with only `s3:GetObject` | Info; hidden without `--all` |
| E8 | Explicit deny on `bedrock:*` plus an allow | Info (deny wins); a deny that omits `bedrock-mantle:*` still reports the open endpoint |
| E9 | API key user with an API key, no access key | High or above; recommended action names the API key |
| E10 | Orphaned API key user with no active credential | Medium |
| E11 | Credential report shows an active root access key | Critical, first row |
| E12 | `aws-marketplace:Subscribe` plus `bedrock:InvokeModel` | Critical |
| E13 | `--resume` after a run where one account failed | Completed accounts not re-queried; result equals an uninterrupted run |
| E14 | Permission boundary that denies `bedrock:*` over an allow | Info |
| E15 | Threshold set to 30 days | A 10-day-old key used yesterday stays Medium; a key unused 45 days becomes High |
| E16 | Static check of the source and shipped IAM documents | No non-read action, no dynamic dispatch, no shell-out, no network library, no AI SDK |
| E17 | User with `AdministratorAccess` and only inactive access keys, run without `--all`. Also an inactive, not expired Amazon Bedrock API key on a user with broad access | Each key is Low, with a "Delete inactive ... key" action and a reason that it would rate Critical or High if re-enabled; `if_reactivated_tier` is set. An inactive key with no Amazon Bedrock access, an expired API key, and an inactive root key remain Info |
| E18 | A policy allows only a model that is not in the bundled sample (`amazon.titan-text-lite-v1`) | Grant is scoped to the Regions named, and the principal is ranked, not hidden. A policy that names an Amazon Bedrock model but is denied for every probe (no explicit deny) gives grant `unknown`, shown for review |
| E19 | A user holding `AmazonBedrockLimitedAccess` | Not described as holding `bedrock:*`. Allowing only some of the canary actions never claims it; allowing all of them does |
| E20 | Any run, including a principal ranked High or Critical by identity policy | The SCP/RCP and `AssumeRole` limitation text appears in the terminal output and in `findings.json` `limitations`, so the documented blind spots cannot silently drop out of the output. The CSV stays one header row plus data |
| E21 | Org of 3 accounts; `iam:ListServiceSpecificCredentials` denied in one | That account is `partial` with the reason, counted apart from failed accounts; the other two are `ok`; the partial account's access-key and root-key findings are still reported; `BedrockAPIKey-*` users in it show as orphaned; exit code 0. On `--resume` the partial account is audited again |
| E22 | A credential report generated more than an hour before the audit | The account carries a warning naming the generation time; the per-account table and `findings.json` show it |
| E23 | Findings spread over several accounts | The per-account table sorts by Critical, then High, then account ID, and counts only visible findings |
| E24 | A user with `AdministratorAccess` and an inactive access key, terminal report without `--all` | Every reason is printed, including the admin-class policy; the reasons after "If re-enabled it would rate Critical:" are indented under that line |
| E25 | Hidden Info findings from different causes: one active user who cannot invoke, two inactive or expired credentials | The summary line lists `1 cannot invoke Amazon Bedrock, 2 expired or inactive credentials`; `run.hidden_info_by_reason` holds the same counts, and they sum to `hidden_info` |
| E26 | Static check of `infra/audit-role.yaml` | `TrustedPrincipalArn` is required (no default) and its pattern accepts only an IAM role or user ARN, so an empty value is rejected; the trust policy names that principal and never an account root; `ExternalId` stays optional |
| E27 | Static check of the default role and `infra/caller-policy.json` | The default `role_name` is `BedrockPermissionsAuditRole`; the caller policy allows `sts:AssumeRole` only on that role and names no administrator role or wildcard role. A failed assumption of the default role carries a hint to deploy `infra/audit-role.yaml` or pass `--role-name` |

## 12. Out of scope

* Applying remediation (deleting keys, attaching policies). Report-only by decision.
* SCP and RCP evaluation. Documented limitation; a candidate for a later version.
* Following `sts:AssumeRole`. One hop (does the principal's policy allow assuming a role, and can that
  role invoke Amazon Bedrock) is the first candidate for a later version.
* Grouping one person's credentials across accounts into a single identity view. Needs rules for
  matching names that do not yet exist; a candidate for a later version.
* Resource-based policies on Amazon Bedrock resources that grant access to a principal in another
  account. Identity-based policies drive most Amazon Bedrock access.
* Correlating with CloudTrail invocation history or GuardDuty findings. GuardDuty AI Protection
  detects anomalous model invocation; the README lists it as a related capability.
* HTML or Markdown executive report. Terminal, CSV and JSON only.
* Decoding Amazon Bedrock API keys.
* Roles and federated identities.
* AWS GovCloud (US) and China partitions.
