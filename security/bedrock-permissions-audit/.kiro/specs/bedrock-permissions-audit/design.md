# Amazon Bedrock Permissions Audit — Design

Master spec. Describes the intended architecture of the command-line tool defined in
`requirements.md`. Implementation details that do not change intent live in code and the README.

## 1. Overview

A single Python package, `bedrock_permissions_audit`, installed with `pip`, exposing the command
`bedrock-audit`. It is a pipeline of read-only stages, run once per account:

```
                 ┌──────────────┐
  credentials ──▶│  accounts    │  Mode A: ListAccounts, then AssumeRole per member account
  (default       │  (discover)  │  Mode B: the caller's account only
   chain)        └──────┬───────┘
                        │  one session per account; bounded thread pool (runner)
                        ▼
                 ┌──────────────┐   credential report (root keys only), users, MFA, access
                 │  collectors  │   keys, last use, attached and group policies, API keys
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐   SimulatePrincipalPolicy, three passes
                 │  evaluator   │
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐   pure functions: tier, reasons, recommendation, order
                 │  scoring     │
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐   terminal report, findings.csv, findings.json,
                 │  output      │   remediation/, summary
                 └──────────────┘
        .checkpoints/ ◀── one file per successfully audited account
```

No LLM anywhere. No outbound network except AWS API endpoints.

## 2. Package layout

```
src/bedrock_permissions_audit/
├── cli.py              # argparse entry point; flags override the TOML file
├── app.py              # one run: discover, checkpoint, audit accounts, write outputs, exit code
├── audit.py            # one account: collect, evaluate, score; the unit the runner parallelises
├── accounts.py         # mode detection, ListAccounts, AssumeRole, session factory
├── runner.py           # bounded thread pool over accounts; one failure never stops the run
├── config.py           # the only module that reads configuration; frozen dataclass
├── models.py           # Credential, ActionResult, Principal, Finding, Account, AccountResult, RunSummary
├── collectors/
│   ├── credential_report.py   # generate and poll the report; root keys and MFA
│   ├── iam_users.py           # users, access keys, last use, attached and group policies
│   ├── api_keys.py            # long-term Amazon Bedrock and Claude Platform API keys
│   └── policy_resources.py    # Amazon Bedrock resources named by a user's Allow statements
├── evaluator.py        # SimulatePrincipalPolicy wrapper and the three-pass logic
├── scoring/
│   ├── tiers.py               # tier assignment, pure
│   ├── ordering.py            # sort key and visibility, pure
│   └── recommendations.py     # rule to recommended-action text, pure
├── summary.py          # run summary computed from findings
├── serialization.py    # lossless dataclass to JSON and back, used by checkpoints
├── checkpoint.py       # per-account checkpoints, scoring fingerprint, --resume
├── log.py              # JSON-lines logging with redaction
├── output/
│   ├── rows.py         # shared row building, masking, control-character and formula safety
│   ├── terminal.py     # text report, optional ANSI colour
│   ├── csv_writer.py
│   ├── json_writer.py
│   ├── remediation.py  # suggested policies, built as data so they are always valid JSON
│   └── files.py        # owner-only directories and atomic owner-only file writes
└── data/bedrock_regions.json   # Regions with Amazon Bedrock, sample models and inference profiles

infra/
├── audit-role.yaml     # CloudFormation: least-privilege read-only role (StackSet-ready)
└── caller-policy.json  # IAM policy for the identity that runs the tool
config/audit.example.toml       # every tunable, with its default and a comment
tests/                          # unit, collectors, evaluator, e2e, static
```

Dependencies: `boto3` only at runtime. TOML is read with the standard library `tomllib`. Test and
lint tooling (`pytest`, `moto`, `ruff`, `cfn-lint`, `pyyaml`) are development extras.

## 3. Modules

### 3.1 `config.py`

Single source of configuration. Precedence: flag, then TOML file, then default. Every value is
validated; a `ConfigError` becomes exit code 2.

| Setting | Default | Notes |
|---|---|---|
| `mode` | `auto` | `auto` tries Mode A and falls back to Mode B; `org` and `single` force |
| `role_name` | `BedrockPermissionsAuditRole` | Role assumed in each member account; the read-only role from `infra/audit-role.yaml`. An administrator role is never the default |
| `external_id` | none | Optional, for the dedicated audit role |
| `dormant_days` | 90 | `N` in requirements section 6 |
| `invoke_actions` / `escalation_actions` / `canary_actions` | see requirements section 5 | |
| `admin_policy_arns` | `AdministratorAccess`, `PowerUserAccess`, `AmazonBedrockFullAccess` | Attached directly or via a group |
| `bedrock_regions` | bundled list | Override to the Regions the customer uses; also drives the Region policy |
| `representative_models` | bundled list | Sample models used to detect scoped grants |
| `approved_models` | empty | Drives the model-allowlist policy only |
| `scp_exception_principals` | empty | Rendered into the user-deny SCP |
| `parallel_accounts` | 8 | Thread pool size, 1 to 64 |
| `output_dir` | `./bedrock-audit-<UTC timestamp>/` | |
| `show_all`, `unmask`, `resume`, `no_color`, `log_level` | off, off, off, off, `INFO` | |

### 3.2 `accounts.py`

* `discover` calls `sts:GetCallerIdentity`, then (unless mode is `single`) `organizations:ListAccounts`,
  keeping `ACTIVE` accounts. The account matching the caller identity is marked `is_caller` and is used
  with the existing session; every other account is assumed.
* `AccessDenied` or "organization not in use" on `ListAccounts` in `auto` mode returns Mode B with a
  printed notice; in `org` mode it raises `DiscoveryError`.
* `SessionFactory.for_account` assumes `arn:<partition>:iam::<id>:role/<role_name>` with session name
  `bedrock-permissions-audit`, an optional `ExternalId`, and a one-hour duration. A failure raises
  `AssumeRoleError`; the runner records it as that account's failure and continues.
* Every client uses adaptive retries with ten attempts.

### 3.3 Collectors (data retrieval)

All collectors take a client and return plain dataclasses. They do not score.

**`credential_report.py`** generates the report and polls until ready (60 seconds, then
`CredentialReportTimeout`). It is the only source of the root account's access keys. IAM reuses a
report up to four hours old and the report omits users created since, so no IAM user data is taken
from it: MFA state is read per user with `ListMFADevices`. It also returns the report's
`GeneratedTime`; the account audit records it and warns when the report is more than one hour old,
because a root access key created since then would not appear. The one-hour threshold is a constant,
not a setting: it describes IAM's caching, not a customer choice.

**`iam_users.py`** pages through users. A user is a principal if it has an access key, a long-term API
key, or an API-key-user name. For each access key it calls `GetAccessKeyLastUsed`, which is exact,
rather than inferring last use from the report. It then collects directly attached policies and, once
per group, group policies. A user deleted mid-scan is skipped with a warning; any other error
propagates and fails the account.

**`api_keys.py`** lists Amazon Bedrock long-term keys account-wide (`ListServiceSpecificCredentials`
with `ServiceName=bedrock.amazonaws.com` and `AllUsers=True`, following the marker by hand because boto3
has no paginator for it), because such keys can belong to any IAM user. It lists Claude Platform keys
per `AeaApiKey-*` user. A key past its expiry date is inactive and also marked **expired**, so that an
inactive key (which can be re-enabled) is told apart from an expired one (which cannot). Last use is
recorded as unknown. An older boto3 without `AllUsers` produces a warning rather than a crash. If the
account-wide listing is denied (`AccessDenied`), the collector still raises; the account audit
catches it for this one call, skips the per-user listing (it needs the same permission), carries on
with everything else, and returns the account as `partial` with the reason. This is the only call
whose denial does not fail the account, so the decision lives in `audit.py`, not in the collector.

**`policy_resources.py`** finds which Amazon Bedrock resources a user's own policies name. A pure
function takes a policy document and the invoke actions and returns the Resource entries of Allow
statements whose Action covers an invoke action (`bedrock:Invoke*`, `bedrock:Converse*`, `bedrock:*`,
`*`, or the configured actions; `NotAction` is treated as possibly covering them; `Deny` and
`NotResource` are ignored) and that are Amazon Bedrock ARNs. A reader applies it to the user's inline
policies, attached managed policies and group policies (inline and managed), caching managed documents
per account. The documents are held in memory only and never stored or written to any output.
Principals carry their group names so the reader needs no extra listing.

### 3.4 `evaluator.py`

Wraps `iam:SimulatePrincipalPolicy`. Three passes. A principal that cannot reach Amazon Bedrock costs
about six calls, and one with a broad `*` grant costs one or two:

1. **All configured actions against `*`.** An allowed invoke action means a **broad** grant.
2. **IAM escalation actions against the principal's own ARN**, skipped if pass 1 already allowed them.
   `iam:CreateServiceSpecificCredential` is normally granted on a specific user, which `*` would miss.
3. **Only if pass 1 allowed no invoke action:** the invoke actions against a grid of sample ARNs:
   one model in every configured Region, several model providers in the home Region, inference-profile
   ARNs, and application-inference-profile and provisioned-model ARNs, plus the probes built from the
   resources the user's own policies name (below), in chunks of 25. If at least 80% of the probes are
   allowed the grant is **broad**; if some is allowed it is **scoped** and the allowed Regions are
   recorded; if none is allowed it is **none**, unless the user's policies name Amazon Bedrock
   resources and none of those probes was explicitly denied, in which case it is **unknown**.

   **Probes from the user's policies.** The simulator matches ARNs as strings, so a probe only has to
   match the policy's pattern. A resource ARN is split into its parts. A wildcard Region expands to the
   configured Regions that match it, and a wildcard account becomes the principal's account. Each `*`
   in the resource part becomes a fixed token and each `?` an `x`, so the probe matches its own
   pattern: an explicit model, and a pattern such as `foundation-model/ai21.*`, are both found without
   knowing the model. Probes are de-duplicated against the sample and capped at 120; if the cap
   truncates, a warning says so. These reads happen only in this pass, so principals with a broad grant
   cost nothing extra.

   With specific resource ARNs the simulator refuses to evaluate actions that need different
   authorization information in one call (for example `bedrock:InvokeModel` with `bedrock:Converse`).
   The evaluator therefore learns once per evaluator, by probing with one sample ARN, which actions
   can share a call, and batches by those groups. It does not hard-code the groups because AWS decides
   them. If a call is still rejected it retries the actions singly and reports the one it could not
   evaluate. Against `*` any mix of actions is accepted.

   The simulator's overall decision for a multi-resource call is the most restrictive across the
   resources, so the evaluator reads the per-resource results and never the overall decision.

Each result keeps the decision, the resource, the names of matching policies with line numbers, and
the simulator's `MissingContextValues`. The root user is modelled as allowed everywhere without calling
the simulator. If the simulator rejects an action name, the evaluator retries the actions singly,
reports the rejected one as a warning, and keeps the rest.

`safe_evaluate` converts a transient or per-principal failure (throttling that outlasted the retries)
into grant `unknown` with a warning. Permission and credential errors (`AccessDenied`, `ExpiredToken`
and similar) are re-raised, because a broken audit must not look like a clean one.

### 3.5 Scoring (precision)

Pure functions over dataclasses; no AWS, no I/O, tested exhaustively.

`tiers.assign` applies requirements section 6 in order. Details that matter:

* Rules 5 and 6 apply only to an active credential that can invoke. An admin-class policy that an
  explicit deny has made unable to reach Amazon Bedrock is not Critical.
* In rule 6, `no MFA` applies only to access keys. Dormancy applies only where last use is known.
* Rule 7 does not apply when the grant is `none`: a console-created API key user whose policy was
  detached is not High.
* Every result carries plain-language reasons.
* The canary rule requires **every** configured canary action to be allowed on `*`, and an empty list
  never claims `bedrock:*`. The defaults are six unrelated management actions, because any one of them is
  granted by narrower managed policies such as `AmazonBedrockLimitedAccess`, which lists explicit actions.
* An inactive IAM access key (not root), or an inactive Amazon Bedrock or Claude Platform API key, is
  scored by running these same rules on a copy of the finding with the credential marked active. If
  that gives Critical or High, the key is Low, with the reasons that it works again if re-enabled
  (naming `iam:UpdateAccessKey` or `iam:UpdateServiceSpecificCredential`), what it would rate, and the
  inner reasons; the finding records `if_reactivated_tier`. Otherwise it is Info. Reusing the rules
  means the would-be tier cannot drift from the real one. It uses only data already collected. Expired
  credentials and root keys are not re-evaluated.

`ordering.sort_key` is `(tier, reactivation rank, not root, not dormant, -age, -regions, account,
name)`. The reactivation rank is 0 for an inactive key that would rate Critical if re-enabled, 1 for
High, and 2 for everything else, so only the Low tier is affected.
`ordering.is_visible` hides Info rows unless `--all`, except `unknown` rows.

`recommendations.for_finding` picks one text by rule: root key; orphaned user; unknown evaluation;
inactive key (delete it, saying it would restore Amazon Bedrock access, with admin-class permissions
named when they apply; delete it as having no reason to exist when the access is lesser; no action
when it has no Amazon Bedrock access); API key; dormant access key (delete); escalation action (remove, then rotate and
move to a role); admin or canary (replace with a scoped policy); no MFA or old (move to a role);
scoped and fresh (no urgent action); broad and fresh (narrow and prefer a role). Texts use masked key
IDs only.

### 3.6 Output (precision)

* `rows.py` builds the flat rows, masks key IDs, strips control characters from everything printed, and
  neutralises spreadsheet formulas (a cell beginning `=`, `+`, `-`, `@`, tab or carriage return is
  prefixed with `'`), because IAM names may legally begin with those characters. Free text is passed
  through the same redaction as logs unless `--unmask` is set.
* `terminal.py` prints a fixed-width table sorted by `sort_key`, one wrapped recommendation and every
  reason under each row (those after an "If re-enabled it would rate ..." line are indented under it),
  then the summary, with hidden Info findings counted by cause (`ordering.hidden_reason`), and the
  limitations. Colour only on a terminal, without
  `NO_COLOR`, and without `--no-color`.
* The terminal report also prints a per-account table and the partial accounts with their reasons,
  computed in `summary.py` (Critical count, then High, then account ID).
* `csv_writer.py` and `json_writer.py` write the same findings. JSON adds per-action results, matched
  policy names, the run summary (including `run.accounts`, `run.partial_accounts`), the limitations,
  and `"schema": 1`. The limitations are `SCP_NOTICE` (SCP and RCP), `ASSUME_ROLE_NOTICE`,
  `CONDITION_NOTICE` and `SCOPE_NOTICE`, appended in `summary.py` on every run.
* `remediation.py` builds three documents as Python data, so they are always valid JSON, and writes a
  `README.txt`. See requirements section 7. The user-deny SCP uses `aws:PrincipalType` in
  `["User", "Account"]` and `ArnNotLike` on `aws:PrincipalArn` for exceptions. The model allowlist uses
  `NotResource` with foundation-model ARNs and inference-profile ARNs that end in the model ID, and
  applies to the model-invocation actions only (bearer-token actions have no model resource). The
  Region policy uses `aws:RequestedRegion`. The API-key policy also denies
  `iam:CreateServiceSpecificCredential` where `iam:ServiceSpecificCredentialServiceName` is
  `bedrock.amazonaws.com`.
* `files.py` creates directories `0700` and writes files `0600` through a temporary file and
  `os.replace`, so a crash never leaves a partial or world-readable file.

All counts in the summary are computed from the findings list in `summary.py`.

### 3.7 `checkpoint.py`

After each account succeeds, its result is written to `<output_dir>/.checkpoints/<account_id>.json`
(owner-only, atomic) together with a fingerprint of every setting that affects scoring (everything
except output, presentation, run mechanics, role, and the two policy-rendering lists) and a format
version that changes whenever the scoring rules do. On `--resume`:

* accounts with a valid checkpoint are loaded and skipped; only `ok` accounts are checkpointed;
* a checkpoint with a different fingerprint, version, or unreadable content is ignored and the account
  is audited again;
* failed and partial accounts are never checkpointed, so they are always retried and a permission
  fixed between runs is picked up;
* without `--resume`, a directory that already holds checkpoints is refused.

Final outputs are regenerated from all results, so a resumed run produces what an uninterrupted run
would.

## 4. Unit classification

Both kinds are pure code; neither runs a model.

| Unit | Classification | Input | Output |
|---|---|---|---|
| `accounts.discover`, `SessionFactory` | Data retrieval | credentials, config | accounts, sessions |
| `collectors.credential_report` | Data retrieval | IAM client | report rows keyed by user |
| `collectors.iam_users` | Data retrieval | client, report, API keys | `list[Principal]` |
| `collectors.api_keys` | Data retrieval | client | credentials keyed by user |
| `evaluator` | Data retrieval | client, principal, config | `Evaluation` |
| `scoring.tiers`, `ordering`, `recommendations` | Precision | `Finding`, config | tier, order, text |
| `summary`, `output.*`, `checkpoint`, `serialization` | Precision | findings, results | stdout, files |

## 5. Data model (abridged)

```python
@dataclass(frozen=True)
class Credential:
    kind: Literal["access_key", "root_access_key", "bedrock_api_key", "claude_api_key"]
    key_id: str                  # full; output masks it unless --unmask
    active: bool
    created, last_used, expires: datetime | None
    last_used_region: str | None
    age_days: int | None
    unused_days: int | None
    last_used_known: bool        # False for API keys: IAM does not report their last use

@dataclass(frozen=True)
class ActionResult:
    action: str
    decision: Literal["allowed", "explicitDeny", "implicitDeny"]
    resource: str                # "*" or the ARN tested
    matched_statements: tuple[str, ...]   # policy names, never contents
    missing_context: tuple[str, ...]

@dataclass(frozen=True)
class AccountResult:
    account: Account
    status: Literal["ok", "partial", "failed"]     # partial: audited without Amazon Bedrock API keys
    reason: str | None                              # set for partial and failed
    findings: tuple[Finding, ...]
    principals_evaluated: int
    warnings: tuple[str, ...]
    credential_report_generated_at: datetime | None

@dataclass(frozen=True)
class AccountBreakout:           # one row of the per-account table
    account_id: str
    name: str | None
    status: Literal["ok", "partial"]
    principals_evaluated: int
    tier_counts: dict[str, int]   # visible findings only
    credential_report_generated_at: datetime | None

@dataclass(frozen=True)
class Finding:                   # one per credential; an orphaned user has credential=None
    account_id, account_name, principal_arn, principal_name: str
    credential: Credential | None
    mfa_active, is_root, is_phantom, orphaned: bool
    admin_policies: tuple[str, ...]
    results: tuple[ActionResult, ...]
    grant: Literal["none", "scoped", "broad", "unknown"]
    regions_allowed: tuple[str, ...]
    tier: Tier
    if_reactivated_tier: Tier | None   # CRITICAL or HIGH for an inactive key reported as Low
    tier_reasons: tuple[str, ...]
    recommended_action: str
    warnings: tuple[str, ...]
```

## 6. IAM permissions

### 6.1 Member-account audit role (`infra/audit-role.yaml`)

A role named by a parameter (default `BedrockPermissionsAuditRole`), assumable only by the one IAM role or
user named in the required `TrustedPrincipalArn` parameter (there is no default, and the template never
trusts an account root), with an optional `ExternalId` condition, a one-hour
session limit, and tags. It is deployed to member accounts, for example as a service-managed StackSet.
Read-only, `Resource: "*"` (these actions do not support resource scoping):

```
iam:GenerateCredentialReport, iam:GetCredentialReport, iam:ListUsers, iam:ListAccessKeys,
iam:GetAccessKeyLastUsed, iam:ListServiceSpecificCredentials, iam:GetAccountSummary,
iam:ListAttachedUserPolicies, iam:ListGroupsForUser, iam:ListAttachedGroupPolicies,
iam:ListMFADevices, iam:SimulatePrincipalPolicy, iam:GetUser, iam:GetUserPolicy, iam:ListUserPolicies,
iam:GetGroupPolicy, iam:ListGroupPolicies, iam:GetPolicy, iam:GetPolicyVersion
```

The last seven are the reads the policy simulator performs for the caller.

### 6.2 Caller policy (`infra/caller-policy.json`)

The same IAM reads for the caller's own account, plus `organizations:ListAccounts`,
`organizations:DescribeOrganization`, `sts:GetCallerIdentity`, and `sts:AssumeRole` scoped to the
dedicated read-only role (`BedrockPermissionsAuditRole`) across accounts. It names no administrator
role. A customer who uses a differently named role adds it to the policy.

The policy reads in section 3.3 (`GetUserPolicy`, `ListUserPolicies`, `GetGroupPolicy`,
`ListGroupPolicies`, `GetPolicy`, `GetPolicyVersion`) are the simulator-support reads already listed
above, so they need no further permission.

Neither document contains a mutating action. The static test enforces this on both documents, and
also checks that the policies grant at least what the code calls.

## 7. Error handling and limits

| Condition | Behaviour |
|---|---|
| `AssumeRole` denied or role missing | Account marked failed with reason; run continues |
| Credential report not ready in 60 seconds | Account failed, `CredentialReportTimeout` |
| Missing IAM permission or expired credentials during an account | Account failed loudly (never silent `unknown` rows) |
| `iam:ListServiceSpecificCredentials` denied on the account-wide listing | Account marked `partial` with the reason; everything else still reported; retried on `--resume` |
| Credential report older than one hour | Warning on that account; the generation time is shown |
| Throttling that outlasts adaptive retry on one principal | That principal is `unknown`, shown with a warning |
| Simulator rejects one action name | Action reported as a warning; the rest evaluated |
| User deleted mid-scan | Skipped with a warning |
| Older boto3 without `AllUsers` | Warning; only API-key users are checked |
| Caller credentials expire mid-run | Current accounts fail; checkpoints keep finished ones; rerun with `--resume` |
| Ctrl-C | Message explains `--resume`; exit 130 |
| Zero findings | Valid empty CSV and JSON and a summary |

Exit codes: `0`, `2`, `3` as in requirements section 8.

## 8. Performance

Per account: one credential report, one `ListUsers` page per 100 users, then per user about one
`ListAccessKeys`, one `GetAccessKeyLastUsed` per key, one `ListMFADevices`, one attached-policies call,
one group listing, and one call per distinct group; one account-wide API-key listing; and about six simulator calls
per principal that cannot reach Amazon Bedrock (the first in an account pays about six more to learn
the action groups), plus about two to five policy reads for such a principal and one `GetPolicy` and one
`GetPolicyVersion` per distinct managed policy per account. For 100 users that is roughly 1,000 calls, bounded by IAM's per-account rate
limits. Each account has its own IAM limits, so cross-account parallelism does not compound
throttling.

These figures are estimates from call counts, not measurements of a large organization. The 30-minute
target for 500 accounts of 100 users is plausible at 32 accounts in parallel (about 16 rounds of one to
two minutes) and not at the default 8; a timing run on a large organization is still outstanding.
The README recommends 32 for organizations of several hundred accounts, and says it is an estimate.

## 9. Testing

* `pytest`. `moto` serves IAM, STS and Organizations, including cross-account role assumption.
  `SimulatePrincipalPolicy` is not modelled faithfully by moto, so the evaluator is tested against a
  fake that applies IAM's evaluation rules (explicit deny wins, boundaries intersect, glob resources),
  plus botocore `Stubber` tests that pin the real response shape.
* `tests/e2e/` has a one-line fixture language for scenarios E3 to E15, a per-account pipeline test on
  a moto account, and whole-run tests (E1, E2, E13, exit codes, privacy of output).
* `tests/static/test_readonly.py` (E16) is a build gate: every AWS call in `src/` is on an allowlist and
  is a read; no `getattr`, `eval`, `exec`, shell-out, network library or AI SDK; every action in the
  shipped IAM documents is on a read-only allowlist and none has a write verb; the assume-role grant is
  scoped to named roles; the policies cover the code's calls.
* `cfn-lint` and `checkov` pass on `infra/audit-role.yaml`.
* No test contacts AWS. Fakes are used only where the real service cannot be reproduced offline; the
  accuracy of the simulator-dependent results is checked against a real non-production account.

## 10. Security and release considerations

* The tool holds read-only credentials and writes findings to local disk. Findings contain account IDs,
  user names, policy names and masked key IDs; the README advises treating the output as confidential
  and deleting it after use.
* No secrets are handled; no configuration value is a secret.
* Published Python files carry the MIT-0 header.
* `SECURITY.md` holds the threat model, data classification, and known limitations.

### Release surface

Root-level entries beyond the template's `src/`, `infra/`, `tests/`:

| Entry | Classification | Reason |
|---|---|---|
| `config/` | public | `audit.example.toml` is the documented way to configure the tool |
| `pyproject.toml` | public | Required for `pip install`; defines the `bedrock-audit` entry point |
| `SECURITY.md` | public | Threat model and limitations for customers |
| `.gitleaks.toml` | public | Allowlists the documented placeholder credentials the tests use, so secret scanners do not report them; the default rules stay on |
| `.kiro/specs/bedrock-permissions-audit/` | public | The master spec ships with the sample |
| `MUTATING_ACTIONS.md` | not created | No mutating action exists, so the opt-in write document is not needed |

## 11. Hard boundaries

1. No AWS call outside the allowlist in section 6; test E16 is a build gate.
2. No LLM, no HTTP beyond the AWS SDK, no telemetry.
3. Findings stay on local disk, owner-only.
4. Remediation documents are written, never applied. The tool never calls `organizations:CreatePolicy`,
   `iam:AttachUserPolicy`, or any similar action.
5. The SCP/RCP and `AssumeRole` limitation notices are printed on every run and included in
   `findings.json`.

## 12. Out of scope (design)

SCP and RCP evaluation (would need `organizations:ListPoliciesForTarget` and policy parsing from the
management account), one-hop `AssumeRole` reachability, a cross-account identity view, CloudTrail
correlation, an HTML report, and remediation execution. Each is a candidate for a
later change; none changes the architecture above.
