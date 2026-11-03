# Operational tests (tasks.md 1.4, 1.6, 1.15, 1.28)

These need a deployed stack and AWS credentials, so they are not part of `pytest tests`.
Recorded results are from the lab deployment (account placeholder 123456789012, us-east-1).

## 1. Parameter rejection (task 1.4)

```bash
.venv/bin/pytest tests/iam -q          # writes infra/cdk.out.test/
.venv/bin/python tests/operational/check_parameter_rejection.py --profile <p> --region <r>
```

The test creates and deletes a throwaway stack per case: the real Parameters and Rules plus one free `AWS::CloudFormation::WaitConditionHandle`. The deployed checker is never modified.

**Result 2026-10-13: 9/9 pass, 0 probe stacks left.**

How CloudFormation enforces each check:

- **Parameter constraints** (required `ScheduleTimezone`, `AllowedPattern`) are rejected synchronously by the API. Nothing is created.
- **Template Rules** (the hand-off all-or-none rules) are enforced when the operation **executes**. The API accepts `CreateStack` or `CreateChangeSet`, then the stack operation fails with "Parameter validation failed: assertion error: …" and rolls back. A half-configured hand-off therefore fails the deploy, as required, but at execution time, not when you submit it.

## 2. A Region that cannot be evaluated (tasks 1.6, 1.15)

Procedure:

1. Attach a temporary inline Deny to the stack's **own** collect-region role for one Region (`ec2:*`, `directconnect:*` with `aws:RequestedRegion`). No customer resource is touched.
2. Wait 45 s for IAM propagation.
3. Start a full-scope run (`{}`).
4. Always remove the Deny afterwards, then confirm only the stack's own policy remains.

**Result 2026-10-13, after the fix below:**

| Observation | Value |
|---|---|
| Execution status | SUCCEEDED (the Catch kept the run alive) |
| Duration | 8 s |
| Failed Lambda attempts | 1 (access denied is not retried) |
| Report line | `Region eu-central-1 not evaluated: access denied; check IAM permissions, SCPs and whether the Region is enabled (CollectionAccessDenied)` |
| Findings in that Region | 5 stayed KNOWN, marked "not re-verified"; 0 wrongly RESOLVED |
| Lookback marker | Not advanced (the run was not complete) |

**Defect found and fixed.** The first run under the same fault took 158 s and made 6 attempts, and the reason read only `ClientError`. Every AWS error reached Step Functions as `ClientError`, and the retry list included it, so a permanent AccessDenied was retried 5 times.

The fix: collection errors are now classified in `src/drift_core/collectors/errors.py` as `CollectionThrottled`, `CollectionAccessDenied` or `CollectionApiError`. Only `CollectionThrottled` and Lambda sandbox timeouts are retried. The report shows a plain-language reason.

**Second defect found while redeploying the fix.** The Lambda asset hash did not cover `src/`, so the redeploy reused a stale bundle. Only the state machine changed. The asset hash is now a content hash of `src/` plus `requirements.txt` (`infra/lib/lambda-code.ts`), and `tests/iam/test_asset_hash.py` guards it.

## 3. Alarms (task 1.28)

Pause and resume the schedule with `scripts/set-schedule-state.sh DISABLED|ENABLED`. It writes back the full schedule definition with only `State` changed. A later `scripts/deploy.sh` also re-enables it.

- **Missed-run alarm.** The schedule was paused on 2026-10-13 at 16:24 UTC (last run 11:39 UTC). By 2026-10-14 15:32 UTC no e-mail had arrived. That exposed two defects, both fixed and deployed on 2026-10-14:
  1. **The alarm never evaluated to ALARM.** With the default sliding window, CloudWatch searches a wider evaluation range and kept reusing yesterday's real datapoint, so the alarm stayed OK. Fix: a wall clock window (`EvaluationWindow: WallClockWindow, UTC`), which reads exactly the last 26 completed clock hours. Guarded in `tests/iam/test_template.py`.
  2. **No alarm could notify anyone.** The stack's topic policy, which only denies non-TLS publishing, replaces the SNS default policy, so CloudWatch had no Allow. The alarm's one ALARM transition, at creation, failed with "CloudWatch Alarms is not authorized to perform: SNS:Publish." This affected all 9 alarms. Fix: an `AllowCloudWatchAlarmsToPublish` statement scoped by `aws:SourceAccount` and an `aws:SourceArn` for this account's alarms. Guarded in `test_cloudwatch_alarms_may_publish_to_topic`.
- **Notification path, verified 2026-10-14 18:05 UTC:** after the policy fix, `set-alarm-state ALARM` produced an action marked **Succeeded**, and the subscriber received the alarm e-mail. A retry about 1 minute after the deploy was needed while the topic policy propagated.
- **Automatic evaluation: not yet observed.** The wall-clock alarm stayed in ALARM after the forced transition, which is consistent with a correct evaluation, but it never transitioned to ALARM on its own before the schedule was re-enabled by the deploy. The next check: the 05:00 Berlin run on 2026-10-15 must return the alarm to OK. A full repeat (pause 26 hours, alarm fires on its own) remains open.
- **Region-not-evaluated alarm:** needs the same Region to fail on 3 consecutive daily runs.
