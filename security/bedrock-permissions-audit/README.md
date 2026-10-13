# Amazon Bedrock Permissions Audit

A read-only command-line tool that finds the long-lived AWS credentials in your account, or in
every account of your AWS Organization, that can invoke Amazon Bedrock models, and assigns each a
risk tier with a recommended action.

## Related AWS capabilities

This tool is a point-in-time review of IAM configuration. It does not monitor usage or enforce
anything. These AWS capabilities cover other parts of Amazon Bedrock credential security:

| Capability | What it does |
|---|---|
| [GuardDuty AI Protection](https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html) | Detects anomalous model invocation (`Impact:IAMUser/CostHarvesting`, `Impact:IAMUser/AnomalousModelInvocation`) |
| IAM Access Analyzer (unused access) | Reports unused access keys, roles and permissions |
| `AWSCompromisedKeyQuarantineV3` | AWS managed policy that AWS attaches to access keys it detects as publicly exposed |
| [Amazon Bedrock SCP examples](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_bedrock.html) | Example Service Control Policies that restrict Amazon Bedrock |

## What it does

1. Lists every IAM user that has an access key or a long-term Amazon Bedrock API key, plus the root
   account's access keys.
2. Asks the IAM policy simulator whether each one can invoke Amazon Bedrock models, enable more
   models, or create new API keys, taking inline policies, managed policies, group policies and
   permissions boundaries into account.
3. Ranks the result by risk, with dormant credentials ranked first within a tier.
4. Writes a terminal report, `findings.csv`, `findings.json`, and suggested guard-rail policies.

It is **read-only**. It never changes, deletes or creates anything in any account, never invokes a
model, never calls anything except AWS APIs, and never sends data anywhere. A test in this
repository (`tests/static/test_readonly.py`) fails the build if any code or shipped IAM policy
could write.

## Quick start

Requires Python 3.12 or later and AWS credentials (see [Permissions](#permissions)).

```bash
git clone <this repository>
cd bedrock-permissions-audit
python3 -m venv .venv && source .venv/bin/activate
pip install .

# Audit only the account your credentials belong to
bedrock-audit --single-account

# Audit every account in the organization (run from the management or a delegated administrator
# account, with the audit role deployed to the member accounts; see "Auditing an organization")
bedrock-audit
```

With no flags the tool tries the whole organization and falls back to the current account if it
is not allowed to list organization accounts, and says so. Without the audit role in the member
accounts, those accounts are reported as failed and only your own account is audited. Results go to
`./bedrock-audit-<UTC timestamp>/`.

### Auditing an organization

From the management account, the tool assumes a role in each member account. By default it
assumes `BedrockPermissionsAuditRole`, the read-only role that
[`infra/audit-role.yaml`](infra/audit-role.yaml) creates. Deploy that template to your member
accounts first (below). The management account itself is audited with your own credentials, so it
needs no role. If the role is missing in an account, that account is reported as failed with a hint,
and the other accounts are still audited.

> **Administrator roles.** The tool calls only read APIs, but a role such as
> `OrganizationAccountAccessRole` has administrator access, so the credential the tool holds would
> be able to change anything. It is not the default and is not in the shipped caller policy. For a
> short trial you can pass it with `--role-name OrganizationAccountAccessRole`, knowing that.

Deploy the role to all member accounts with a service-managed StackSet. This needs trusted access
for CloudFormation StackSets to be enabled in AWS Organizations.

```bash
aws cloudformation create-stack-set \
  --stack-set-name bedrock-permissions-audit-role \
  --template-body file://infra/audit-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
      ParameterKey=TrustedPrincipalArn,ParameterValue=arn:aws:iam::123456789012:role/SecurityAuditor

aws cloudformation create-stack-instances \
  --stack-set-name bedrock-permissions-audit-role \
  --deployment-targets OrganizationalUnitIds=r-examplerootid \
  --regions us-east-1

bedrock-audit
```

Replace the example account ID, principal and root ID with yours. `TrustedPrincipalArn` is required:
it is the one IAM role or user, in the account that runs the tool, that can assume the audit role. The
template never trusts a whole account. `ExternalId` is optional; when you set it, pass the same value
with `--external-id`.

## Permissions

The identity that runs the tool needs only the read-only actions in
[`infra/caller-policy.json`](infra/caller-policy.json): IAM list and get calls, the IAM policy
simulator, `organizations:ListAccounts`, and `sts:AssumeRole` on the audit role. Attach that
policy to a dedicated user or role. In a member account, the audit role grants the same IAM reads.

IAM API calls, including the policy simulator, have no charge.

## Reading the results

Example output (account IDs and keys are placeholders):

```
TIER      ACCOUNT       PRINCIPAL       CREDENTIAL       KEY                AGE    LAST USED  MFA  GRANT
--------------------------------------------------------------------------------------------------------
Critical  111111111111  <root_account>  root access key  root-access-key-1  2191d  never      no   broad
          -> Delete the root access key. Use IAM Identity Center or IAM roles for day-to-day work and keep root
             for account-level tasks only.
             why: The root account has an active access key.
Critical  111111111111  data-loader     access key       ...MPLE            700d   400d ago   no   broad
          -> Delete access key ...MPLE (unused for 400 days). Recreate it only if a workload breaks.
             why: Can invoke Amazon Bedrock models.
             why: Holds an admin-class policy: AdministratorAccess.
             why: Effectively holds bedrock:* (full control of Amazon Bedrock).
High      111111111111  ci-bot          access key       ...MPLE            400d   never      no   broad
          -> Delete access key ...MPLE (never used). Recreate it only if a workload breaks.
             why: Can invoke Amazon Bedrock models.
             why: The key has never been used, so nobody would notice misuse.
             why: The key is 400 days old (threshold 90).
Medium    111111111111  reporting       access key       ...DEFG            20d    1d ago     yes  broad
          -> Limit reporting to the specific models and Regions it needs, and prefer an IAM role over a long-
             lived key.
             why: Can invoke any model in any Region; the key is recent and in use.

Summary
  Mode: organization
  Accounts scanned: 1   partial: 0   failed: 0   principals evaluated: 4
  Findings: Critical 2  High 1  Medium 1  Low 0  Info 0
  Accounts:
    ACCOUNT       NAME       STATUS  PRINCIPALS  CRITICAL  HIGH  MEDIUM  LOW  INFO  REPORT GENERATED
    111111111111  workloads  ok               4         2     1       1    0     0  2026-06-01 08:30 UTC
```

The **Accounts** table has one row per audited account, the one with the most Critical findings
first, so in an organization you can see where to start. It also shows when IAM generated the
credential report that supplies the root account's access keys. A warning is added for an account
whose report is more than an hour old.

**Partial accounts.** If the audit role cannot call `iam:ListServiceSpecificCredentials`, the account
is not failed and is not silently reported without its Amazon Bedrock API keys. It is audited for
everything else and marked `partial`, with the reason, in the summary and in `findings.json`. Any
`BedrockAPIKey-*` user in it shows as orphaned, because its keys cannot be seen. Add the permission
(it is in `infra/audit-role.yaml`) and run again with `--resume`: a partial account is audited again.

A dormant key that can reach Amazon Bedrock (`ci-bot` above) is the pattern behind most of the
incidents this tool was written for.

| Tier | Meaning |
|---|---|
| **Critical** | The root account has an active access key; or the principal can invoke Amazon Bedrock **and** holds an admin-class policy, effectively has `bedrock:*`, can enable more models (`aws-marketplace:Subscribe`, `bedrock:CreateMarketplaceModelEndpoint`) or can create new API keys (`iam:CreateServiceSpecificCredential`) |
| **High** | Can invoke Amazon Bedrock and the key is dormant (never used, or unused for the threshold), old, or (for access keys) the user has no MFA; or an Amazon Bedrock API key on a console-created API key user |
| **Medium** | Can invoke Amazon Bedrock on any model and Region, but the key is recent and in use; or an Amazon Bedrock API key user with no active credential left (orphaned) |
| **Low** | Can invoke only specific models or Regions, and the key is recent and in use; or an inactive access key or Amazon Bedrock API key that would be Critical or High if re-enabled |
| **Info** | Cannot invoke Amazon Bedrock, or the credential is inactive (and would not be Critical or High if re-enabled), or expired. Hidden unless you pass `--all`, except principals that could not be evaluated, which are always shown |

Within a tier the order is: root first, dormant before active, older before newer, then wider
before narrower.
In Low, inactive keys that would be Critical if re-enabled come first, then those that would be High.

**Inactive keys are not safe.** Deactivating an access key does not invalidate its secret: anyone who
can call `iam:UpdateAccessKey` on the user can switch it back on, and it works again with the same
permissions (an Amazon Bedrock API key is switched back on with `iam:UpdateServiceSpecificCredential`).
Re-enabling is quieter than creating a key and works even when the user already has two.
So an inactive key that would rate Critical or High if it were active is reported as Low, with the
reason and the tier it would get, which makes it visible without `--all`. The remedy is to delete it.
Expired API keys cannot be re-enabled and stay Info.
`findings.json` and `findings.csv` carry that tier in `if_reactivated_tier`.

The `GRANT` column is `broad` (any model, any Region), `scoped` (specific models or Regions),
`none`, or `unknown` (the simulator call failed; review that principal by hand).

Each row has one recommended action. The tool only recommends: it never applies anything.

The terminal prints every reason under a row. For an inactive key, the reasons after "If re-enabled it
would rate Critical:" are the reasons for that rating, and are indented under it. The summary counts
the Info findings left out by cause, for example "3 Info findings hidden (1 cannot invoke Amazon
Bedrock, 2 expired or inactive credentials)". `findings.json` has the same counts in
`run.hidden_info_by_reason`.

### Using the results

The preferred outcome for a finding is to replace the long-lived credential with a short-lived one:
IAM Identity Center for people, IAM roles for workloads, and OIDC federation or IAM Roles Anywhere for
systems outside AWS. Where a long-lived key has to stay for now, these controls reduce what it can do
and make its use visible:

* Scope its permissions to the Amazon Bedrock actions and models it needs. The policies in
  `remediation/` are a starting point.
* Add IAM condition keys that limit where it can be used from, such as source IP or VPC endpoint.
* Set AWS Budgets and Cost Anomaly Detection alerts on Amazon Bedrock spend.
* Keep AWS CloudTrail on, and turn on Amazon Bedrock model invocation logging where you need request
  detail.
* Enable GuardDuty AI Protection.

Run the tool again after a change to confirm the tier has dropped.

### Output files

| File | Contents |
|---|---|
| `findings.csv` | One row per credential, for a spreadsheet. Values that could be read as spreadsheet formulas are neutralised |
| `findings.json` | The same findings with the per-action simulator results and the names of the policies that grant access, plus the run summary and the limitations below |
| `remediation/` | Suggested policies and a `README.txt`. **Review before applying.** See below |
| `.checkpoints/` | Per-account results, used by `--resume` |

Access key IDs are masked (`...MPLE`) everywhere unless you pass `--unmask`.

### Suggested policies

`remediation/` contains policies you can adopt. Each statement ID starts with `ReviewBeforeApplying`.

* `scp-deny-bedrock-to-iam-users.json`: denies Amazon Bedrock invocation to IAM users and to
  the account root user. Roles and IAM Identity Center users are unaffected. **This breaks any
  workload still running on IAM user keys**, so list those in `scp_exception_principals` first.
* `scp-restrict-bedrock-regions-models.json`: denies Amazon Bedrock outside the Regions in
  `bedrock_regions` and for models not in `approved_models`. Written only when you set one of them.
* `policy-deny-bedrock-api-keys.json`: an identity policy that denies using, and creating,
  Amazon Bedrock API keys.

Test every service control policy on a sandbox organizational unit first.

## Limitations

Read these before relying on a result.

* **Service control policies and resource control policies are not evaluated.** The IAM policy
  simulator ignores them, so a principal shown as able to invoke Amazon Bedrock may be blocked at
  the organization level. The tool prints this on every run.
* **Only long-lived credentials are audited**: IAM user access keys, root access keys, and
  long-term Amazon Bedrock and Claude Platform on AWS API keys. Roles are out of scope.
* **API key last use is unknown.** IAM does not report when a long-term API key was last used, so
  those keys show `unknown` and are never counted as dormant.
* **The root account's access keys come from the credential report, which can be up to four hours
  old.** IAM reuses a report generated within the last four hours. Everything about IAM users,
  including MFA, is read live and is not affected.
* **"Cannot invoke" is not a guarantee.** A statement that allows access only under a condition the
  simulator has no value for (a source IP, an MFA session, some tags) is reported as not allowing
  access, and such principals are hidden unless you pass `--all`. They carry `missing_context` in
  `findings.json`. If a user has conditioned Amazon Bedrock permissions, treat an Info result as
  unverified. A policy that restricts only the Region is treated as allowed, so it shows as `broad`.
* **The tool reads your policies to find models by name.** When a user has no broad grant, the
  tool reads that user's inline, attached and group policies in memory, only to extract the Amazon
  Bedrock resource names they allow, and tests those too. It never stores or writes a policy
  document. If a policy names Amazon Bedrock resources but the simulator denies every one without an
  explicit deny (a condition or a permissions boundary may apply), the result is `unknown` and the
  principal is shown for you to review. A policy with `Resource: "*"` plus a condition is not
  caught this way.
* **Who can re-enable an inactive key is not evaluated.** Inactive keys that would be Critical or
  High are reported as Low so they are visible by default; delete them. This applies to IAM access
  keys and to Amazon Bedrock and Claude Platform API keys that are inactive but not expired.
* **`sts:AssumeRole` is not followed.** A key is judged on its own identity-based permissions. A key
  whose policy grants only `sts:AssumeRole`, but which can assume a role that can invoke Amazon
  Bedrock, is reported as unable to invoke. The tool prints this on every run.
* **Conditions can make the tool over-report.** The simulator has no request context, so a grant
  limited by source IP, VPC or tags may be shown as allowed. `missing_context` in `findings.json`
  lists the condition keys it had no value for.
* **"Last used" is not Amazon Bedrock use.** IAM reports the key's last call to any AWS service.
  It shows whether the key is dormant, not whether it was used for Amazon Bedrock.
* **AWS's own exposure signal is not read.** A user with `AWSCompromisedKeyQuarantineV2` or `V3`
  attached has been flagged by AWS as exposed, but the tool does not specially mark it.
* **Commercial AWS partition only.** AWS GovCloud (US) and China Regions are not covered.
* **A point-in-time snapshot.** It does not look at CloudTrail, so it does not show whether a key
  has been used to invoke models. GuardDuty AI Protection detects that.

## Configuration

Every setting can go in a TOML file (`--config audit.toml`, see
[`config/audit.example.toml`](config/audit.example.toml)); most also have a flag. Flags override
the file, which overrides the defaults. `bedrock-audit --help` lists the flags.

| Setting | Flag | Default | Purpose |
|---|---|---|---|
| `mode` | `--mode`, `--single-account` | `auto` | `auto`, `org` or `single` |
| `role_name` | `--role-name` | `BedrockPermissionsAuditRole` | Role assumed in each member account |
| `external_id` | `--external-id` | none | `ExternalId` for the audit role |
| `dormant_days` | `--dormant-days` | `90` | Unused or older than this many days counts as dormant or old |
| `parallel_accounts` | `--parallel-accounts` | `8` | Accounts audited at once. Each account has its own IAM limits, so raising this does not compound throttling. 32 is a reasonable starting point for several hundred accounts (an estimate, not a measured figure) |
| `output_dir` | `--output-dir` | `./bedrock-audit-<timestamp>/` | Where results go |
| `bedrock_regions` | `--bedrock-regions` | all Regions with Amazon Bedrock | Regions you use; also drives the Region policy |
| `approved_models` | `--approved-models` | none | Drives the model allowlist policy |
| `show_all` | `--all` | off | Also show Info findings |
| `unmask` | `--unmask` | off | Full key IDs in CSV and JSON |
| `resume` | `--resume` | off | Continue an interrupted run in `--output-dir` |
| `no_color` | `--no-color` | off | No terminal colour |
| `log_level` | `--log-level` | `INFO` | JSON log lines on stderr |
| `invoke_actions` | file only | six invoke and bearer-token actions | Any allowed means "can invoke" |
| `escalation_actions` | file only | Marketplace subscribe, Marketplace endpoint, API key creation | Allowed on top of invoke means Critical |
| `canary_actions` | file only | six unrelated management actions (`DeleteCustomModel`, `PutModelInvocationLoggingConfiguration`, `DeleteGuardrail`, `CreateProvisionedModelThroughput`, `DeleteAgent`, `DeleteKnowledgeBase`) | **All** allowed on `*` means effectively `bedrock:*`. Any one alone is granted by narrower managed policies such as `AmazonBedrockLimitedAccess`, so it proves nothing. An empty list never claims `bedrock:*` |
| `admin_policy_arns` | file only | `AdministratorAccess`, `PowerUserAccess`, `AmazonBedrockFullAccess` | Admin-class policies |
| `representative_models` | file only | bundled list | Models used to detect a grant scoped to specific models |
| `scp_exception_principals` | file only | none | ARN patterns exempt from the user-deny SCP |

If a run is interrupted (for example your credentials expire), rerun the same command with
`--resume --output-dir <the same directory>`. Finished accounts are not queried again. Settings
that change scoring invalidate the saved results of earlier accounts.

Exit codes: `0` success, including partial account failures, which are listed in the summary;
`2` configuration or credential error before any account was audited; `3` no account could be
audited.

## Handling the output

The output names accounts, users and (masked) keys. Treat the directory as confidential, keep it
out of version control (the repository's `.gitignore` excludes `bedrock-audit-*/`), and delete it
when you have finished. The tool creates it readable by the owner only.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                      # no AWS credentials needed
ruff check src tests
```

The specification is in [`.kiro/specs/bedrock-permissions-audit/`](.kiro/specs/bedrock-permissions-audit/).

## License

This sample is licensed under the MIT-0 License. See the `LICENSE` file at the root of the
repository.
