# Security

## Reporting a vulnerability

If you find a security issue in this sample, report it through the AWS vulnerability reporting
process at <https://aws.amazon.com/security/vulnerability-reporting/>. Please do not open a public
issue.

## What this tool is, from a security point of view

`bedrock-audit` is a deterministic command-line program. It holds read-only AWS credentials while
it runs and writes its findings to local disk. It contains no AI model, makes no network calls
other than to AWS service endpoints through the AWS SDK, and has no telemetry.

## STRIDE risk summary

A STRIDE model of the tool was generated and checked against the source. Severity is the inherent severity before
mitigations. "Residual" is the state after the controls that exist today.

| STRIDE Category | HIGH | MEDIUM | LOW | Total |
|---|---|---|---|---|
| Spoofing | 0 | 2 | 0 | 2 |
| Tampering | 0 | 5 | 1 | 6 |
| Repudiation | 0 | 0 | 1 | 1 |
| Information Disclosure | 0 | 2 | 1 | 3 |
| Denial of Service | 0 | 0 | 2 | 2 |
| Elevation of Privilege | 0 | 1 | 0 | 1 |
| **Total** | **0** | **10** | **5** | **15** |

Residual state: 6 mitigated, 9 open, none rated HIGH after mitigation.

### Detailed findings

#### Spoofing

* **[MEDIUM] Another principal assumes the audit role.** `infra/audit-role.yaml`. The role trusts one
  named principal (`TrustedPrincipalArn`, never an account root) with an optional `ExternalId`.
  Residual: mitigated.
* **[MEDIUM] Stolen long-term operator keys are used to run the audit.** `accounts.py`. Use SSO or
  role credentials; the tool never reads secret key material. Residual: open, low. Temporary
  credentials are advised, not enforced.

#### Tampering

* **[MEDIUM] A checkpoint is edited so a risky credential is reported as Info or absent.**
  `checkpoint.py`. Owner-only files and a version and fingerprint check, which detect setting drift
  and not tampering. Recommended: authenticate checkpoints, or state that `--resume` trusts the output
  directory. Residual: open, low.
* **[MEDIUM] The config file is altered** (large `dormant_days`, an attacker in
  `scp_exception_principals`). `config.py`. Types and ranges are validated; exception principals are
  not format-checked. Residual: open, low.
* **[MEDIUM] A compromised or typosquatted dependency runs with the operator's credentials.**
  `pyproject.toml`. The build test forbids network use, shell-out and dynamic dispatch in the tool's
  own code, not in dependencies. `boto3` has a lower bound only. Recommended: constrain and hash-pin
  dependencies. The dedicated read-only role limits what a stolen session can do. Residual: open,
  medium.
* **[LOW] A symlink planted at the predictable `.tmp` path redirects a write.** `output/files.py`.
  The output directory is `0700`. Recommended: `O_EXCL | O_NOFOLLOW` with a random suffix. Residual:
  open, low.
* **[MEDIUM] A hostile IAM user name runs as a spreadsheet formula or injects terminal escapes.**
  `output/rows.py`. Neutralised. Residual: mitigated.
* **[MEDIUM] Generated policies are applied unreviewed and break workloads.**
  `output/remediation.py`. Files only, marked `ReviewBeforeApplying`, never applied by the tool.
  Residual: mitigated.

#### Repudiation

* **[LOW] Nothing proves who ran an audit or that findings were not edited afterwards.**
  `output/json_writer.py` records the tool version and the run start and end times, not the caller. CloudTrail records the `AssumeRole` calls.
  Recommended: record caller ARN, start time and config fingerprint. Residual: open, low.

#### Information disclosure

* **[MEDIUM] Findings, checkpoints or remediation files are read by someone else or committed.**
  `output/files.py`. Owner-only, key IDs masked, no secrets written, `bedrock-audit-*/` ignored by git.
  The tool does not encrypt at rest; keep the output on an encrypted volume outside any repository and
  delete it after use. Residual: open, medium.
* **[LOW] Full key IDs or policy text appear in logs or errors.** `log.py`. Pattern-based redaction;
  `--unmask` disables redaction of free text. Residual: open, low.
* **[MEDIUM] Caller or assumed-role credentials are read from the environment or memory.**
  `accounts.py`. Assumed-role credentials last one hour and are never written to disk. Residual:
  open, low.

#### Denial of service

* **[LOW] High concurrency exhausts IAM API quota in an account.** `runner.py`. Bounded pool (1 to
  64) and adaptive retries. Residual: mitigated.
* **[LOW] A very large account inflates audit time or times out the credential report.**
  `evaluator.py`, `collectors/credential_report.py`. Probe cap, 60-second timeout, failure isolated to
  that account. Residual: mitigated.

#### Elevation of privilege

* **[MEDIUM] An operator opts into an administrator role such as `OrganizationAccountAccessRole`.**
  `config.py`, `infra/caller-policy.json`. The dedicated read-only role is the default, the caller
  policy names no administrator role, and a build test enforces both. The README warns that an
  administrator role lets the held credential change anything. Residual: mitigated.

## Threat model

Verification: reviewed on 2026-10-13 against the source at commit `fe2f1e1`. Each mitigation below
names the file that implements it. No threat is rated High after mitigation.

| Threat | STRIDE | Mitigation | Residual risk |
|---|---|---|---|
| The tool changes something in a customer account | Tampering | Every AWS call is a read. `tests/static/test_readonly.py` scans the source against the AWS service models and fails the build on any write call, any dynamic dispatch (`getattr`, `eval`, `exec`), any shelling out, and any permission in the shipped IAM documents (`infra/audit-role.yaml`, `infra/caller-policy.json`) that is not on a read-only allowlist. The one call that is not a pure read, `iam:GenerateCredentialReport` (`collectors/credential_report.py`), asks IAM to refresh the credential report that IAM itself retains | Low |
| The audit role or caller policy is abused as a foothold | Elevation of privilege | Both are read-only. `infra/audit-role.yaml` requires `TrustedPrincipalArn` (an IAM role or user ARN, no default) and trusts only that principal; it never trusts an account root. `ExternalId` is optional and, when set, is required in the trust policy. The role can read IAM metadata but cannot read secret key material, which IAM never returns | Low |
| Findings leak | Information disclosure | Output is written owner-only (directory `0700`, files `0600`) with atomic writes (`output/files.py`). Access key IDs are masked unless `--unmask` is passed (`output/rows.py`). The tool uses no network library and sends nothing anywhere (checked by the same static test). Policy documents are read in memory to find the Amazon Bedrock resources a user's policies name (`collectors/policy_resources.py`), but they are never stored or copied into the output: only policy names and the resource names tested | Medium: the output is confidential data on the local disk |
| Hostile text in IAM names reaches the analyst | Tampering | IAM user names may legally begin with `=`, `+`, `-` or `@`. CSV cells are neutralised so a spreadsheet cannot execute them (`csv_safe` in `output/rows.py`), and control characters, including terminal escape sequences, are stripped from everything printed (`clean` in `output/rows.py`) | Low |
| Credentials or key IDs end up in logs | Information disclosure | Logging is structured JSON on stderr and redacts anything shaped like an access key ID or an Amazon Bedrock or Claude Platform API key (`log.py`), as a second line of defence. The tool never reads key secrets | Low |
| A broken audit looks like a clean one | Repudiation | A permission or credential error fails the account loudly (`evaluator.py`, `audit.py`). A principal that cannot be evaluated is reported as `unknown` and is never hidden (`scoring/ordering.py`). Failed accounts are listed in the summary and the exit code reflects total failure (`app.py`) | Medium: see the limitations below |
| A stale checkpoint is mistaken for fresh results | Tampering | Checkpoints record a fingerprint of every setting that affects scoring and a format version, and are ignored when either differs (`checkpoint.py`). Existing results are never overwritten without `--resume` | Low |
| Generated policies are applied without thought | Tampering | They are written only to files, every statement ID carries `ReviewBeforeApplying`, and a `README.txt` warns that the user-deny service control policy breaks workloads that still use IAM user keys (`output/remediation.py`) | Low |

## Known limitations that affect security conclusions

* The IAM policy simulator does not evaluate service control policies or resource control policies,
  so a result of "can invoke" may be blocked in practice.
* "Cannot invoke" is **not** a guarantee. If a policy allows access only under a condition the
  simulator has no value for (a source IP, an MFA session, some tags), the principal is reported as
  unable to invoke, and is hidden unless `--all` is given. Treat Info results from users with
  conditioned Amazon Bedrock permissions as unverified.
* A key is judged only on its own identity-based permissions; `sts:AssumeRole` is not followed. A key
  that can assume a role that can invoke Amazon Bedrock is reported as unable to invoke.
* A grant that depends on request context (source IP, VPC, tags) can simulate as allowed, so the tool
  may over-report. This is the safe direction for an exposure tool.
* Conditions the simulator has no value for can make an allowed action look denied. Such results
  are flagged in `findings.json` (`missing_context`).
* The root account's access keys come from the IAM credential report, which can be up to four hours
  old. User data, including MFA, is read live. The tool shows when each report was generated and warns
  when it is more than an hour old.
* If the audit role lacks `iam:ListServiceSpecificCredentials`, the account is marked partial and
  its Amazon Bedrock API keys are not evaluated. This is stated in the summary and in
  `findings.json`, not hidden.
* The tool never retrieves a secret access key or API key value. No API it calls returns one.
* Long-term API key last use is not available from IAM, so those keys are never labelled dormant.

## Data classification

| Data | Classification | Where it lives |
|---|---|---|
| Account IDs, user names, policy names, masked key IDs, key ages and last-use dates | Confidential | The output directory, on the machine that ran the tool |
| Key secrets, passwords | Never read | Not present |
| Policy documents (inline, managed, group) | Read in memory, only to extract the Amazon Bedrock resource names they allow | Never stored, logged or written to any output; only the resource names tested and the names of matching policies reach the output |

Delete the output directory when you have finished with it.

## Key management

The tool handles no keys of its own. It uses the standard AWS credential chain (environment,
profile, SSO or instance role) and prefers temporary credentials.
