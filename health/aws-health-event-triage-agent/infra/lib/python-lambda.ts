// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * Shared helper for bundling this repo's Python Lambda handlers.
 *
 * All Python handlers (src/classifier, src/inventory, src/digest,
 * src/devops_agent, src/intake) live under one project-level `src/` package
 * and share one project-level `requirements.txt`. PythonFunction's `entry`
 * copies its entire target directory into the Lambda package and installs
 * `requirements.txt` found there (in a Lambda-compatible Docker container —
 * requires Docker at synth/deploy time), so `entry` must be the PROJECT
 * ROOT (not a handler-specific subdirectory) for `from src....` imports to
 * resolve at runtime. `index` then selects the specific handler file
 * relative to that root.
 *
 * This does mean every Lambda's deployment package contains the full
 * `requirements.txt` dependency set (including the classifier's
 * strands-agents/bedrock-agentcore, even for e.g. the lightweight digest
 * Lambda) — a deliberate simplicity-over-package-size trade-off appropriate
 * for a prototype; splitting into per-handler requirements files is a
 * documented, not-yet-needed optimization (see README.md's Phase 1b-deploy
 * section).
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as pythonLambda from '@aws-cdk/aws-lambda-python-alpha';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

/** Absolute path to the repository root (two levels up from infra/lib/). */
export const REPO_ROOT = path.join(__dirname, '..', '..');

/**
 * `PythonFunction`'s (aws-lambda-python-alpha 2.271.0-alpha.0) `assetExcludes`
 * bundling option is declared in its type definitions but never actually
 * consumed by its asset-staging copy step (confirmed by reading the compiled
 * bundling.js — it's only threaded into the in-container bundling *commands*,
 * never into what gets copied into the Docker build context). Using
 * `entry: REPO_ROOT` directly for more than one `PythonFunction` in the same
 * synth is therefore a real, reproducible bug, not a stale-state issue: the
 * first function's asset-staging copy writes `infra/cdk.out/asset.<hash>/`
 * *inside* the repo root; because nothing actually excludes `infra/cdk.out`,
 * the second function's staging copy sweeps that directory back in,
 * compounding once per additional `PythonFunction` until macOS's path-length
 * limit is hit (`ENAMETOOLONG`).
 *
 * Fixed by staging a minimal build directory *outside* the repo tree (under
 * the OS temp dir) containing `src/`, `requirements.txt`, and `config/` —
 * and pointing every `PythonFunction`'s `entry` at that instead of
 * `REPO_ROOT`. Since this directory can never contain `infra/` (or anything
 * else in the repo root), the self-referential recursion is structurally
 * impossible, not just excluded by a best-effort glob.
 *
 * `config/` MUST be staged alongside `src/`, not omitted: six modules
 * (`src/triage/disposition.py`, `src/triage/routing.py`,
 * `src/tools/get_event_type_guidance.py`, `src/cost/pricing.py`,
 * `src/cost/vcpu_map.py`, `src/devops_agent/registry.py`) each default their
 * config-file path to `Path(__file__).parents[2] / "config" / "<file>.json"`
 * — a sibling of `src/` in the deployed package, not inside it — and no CDK
 * stack overrides any of their `*_PATH` env vars. Confirmed missing by a
 * real deploy + real execution (not caught by `cdk synth` or by mocked unit
 * tests, which construct overrides directly or patch the path): a real
 * AWS_EKS_FARGATE_POD_EVICTIONS test event should have matched
 * `config/dispositions.json`'s DIGEST + fargate_posture override but instead
 * fell through to decide_disposition()'s hardcoded BREAKING_CHANGE->TICKET
 * class default, because `config/dispositions.json` did not exist anywhere
 * in the deployed Lambda package and `_load_overrides()` degraded to `{}`
 * on a silent `FileNotFoundError`. See architecture-decisions.md L2 and the
 * master spec's "Build validation note" for the broader pattern this fits.
 *
 * Computed once per synth process (module-level, memoized) since every
 * `PythonFunction` needs the identical staged content.
 */
let _stagedBuildRoot: string | undefined;

function getStagedBuildRoot(): string {
  if (_stagedBuildRoot) {
    return _stagedBuildRoot;
  }
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-triage-lambda-src-'));
  fs.cpSync(path.join(REPO_ROOT, 'src'), path.join(stageDir, 'src'), { recursive: true });
  fs.cpSync(path.join(REPO_ROOT, 'config'), path.join(stageDir, 'config'), { recursive: true });
  fs.copyFileSync(
    path.join(REPO_ROOT, 'requirements.txt'),
    path.join(stageDir, 'requirements.txt'),
  );
  _stagedBuildRoot = stageDir;
  return stageDir;
}

export interface TriagePythonFunctionProps {
  /** Path to the handler file, relative to the repository root, e.g. "src/digest/handler.py". */
  readonly indexFile: string;
  /** Name of the exported handler function. Default: "handler". */
  readonly handlerName?: string;
  readonly description: string;
  readonly timeout?: cdk.Duration;
  readonly memorySize?: number;
  readonly environment?: Record<string, string>;
  readonly kmsKey: kms.IKey;
  readonly deployEnvironment: string;
  readonly architecture?: lambda.Architecture;
  /**
   * The maximum concurrent executions to reserve for this function.
   *
   * @default undefined — no specific limit (the account's shared unreserved
   *   pool), matching this repo's behavior before this prop existed. Only
   *   set this for a function whose downstream dependency has its own
   *   throttling concern (see createTriagePythonFunction()'s docstring) —
   *   an unnecessary cap on a function with no such concern only produces
   *   `Lambda.TooManyRequestsException` under legitimate fan-out load with
   *   no corresponding safety benefit.
   */
  readonly reservedConcurrentExecutions?: number;
}

/**
 * Grants DynamoDB read/write IAM permissions to a grantee WITHOUT using
 * Table.grantReadWriteData()'s automatic KMS key-policy mutation.
 *
 * Table.grantReadWriteData() on a customer-managed-key-encrypted table
 * calls the key's grantOnKey(), which adds a statement to the KEY'S OWN
 * resource policy for the grantee. When the grantee lives in a different
 * stack than the key, this creates a <key's stack> -> <grantee's stack>
 * dependency — which becomes a cycle if the grantee's stack already
 * depends on the key's stack for anything else (e.g. the table/topic
 * ARNs themselves). This was hit during Build.
 *
 * This helper grants the equivalent IAM actions directly to the grantee's
 * role only (iam.Grant.addToPrincipal), never touching the key's resource
 * policy. It relies on the key's default `trustAccountIdentities: true`
 * policy (CDK's default since the KMS_DEFAULT_KEY_POLICIES feature flag),
 * which already allows any same-account IAM principal with the matching
 * kms:Decrypt/GenerateDataKey permission on their OWN policy to use the
 * key — exactly what this grants.
 */
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

const DYNAMODB_READ_ACTIONS = [
  'dynamodb:BatchGetItem',
  'dynamodb:GetRecords',
  'dynamodb:GetShardIterator',
  'dynamodb:Query',
  'dynamodb:GetItem',
  'dynamodb:Scan',
  'dynamodb:ConditionCheckItem',
  'dynamodb:DescribeTable',
];
const DYNAMODB_WRITE_ACTIONS = [
  'dynamodb:BatchWriteItem',
  'dynamodb:PutItem',
  'dynamodb:UpdateItem',
  'dynamodb:DeleteItem',
];
const KMS_ACTIONS = ['kms:Decrypt', 'kms:DescribeKey', 'kms:Encrypt', 'kms:GenerateDataKey*', 'kms:ReEncrypt*'];

export function grantTableReadWriteWithoutKeyPolicy(
  grantee: iam.IGrantable,
  table: dynamodb.ITable,
  kmsKeyArn: string,
): void {
  iam.Grant.addToPrincipal({
    grantee,
    actions: [...DYNAMODB_READ_ACTIONS, ...DYNAMODB_WRITE_ACTIONS],
    resourceArns: [table.tableArn, `${table.tableArn}/index/*`, `${table.tableArn}/stream/*`],
  });
  // Scoped to the specific key ARN — never a wildcard (security-policies.md).
  iam.Grant.addToPrincipal({
    grantee,
    actions: KMS_ACTIONS,
    resourceArns: [kmsKeyArn],
  });
}

/**
 * Grants `states:SendTaskSuccess/SendTaskFailure/SendTaskHeartbeat` to a
 * grantee for a specific state machine, WITHOUT using
 * `StateMachine.grantTaskResponse()`.
 *
 * `grantTaskResponse()` itself only builds a static ARN
 * (`CfnStateMachine.arnForStateMachine()`, not a live `Fn::GetAtt`/`Ref`) —
 * so it does not, by itself, create a live construct dependency. The cycle
 * comes from calling it on `identity` where `identity` is a Lambda function
 * that the state machine's OWN role policy separately needs
 * `lambda:InvokeFunction` on (auto-added by every `tasks.LambdaInvoke` state
 * using that function). Both edges then exist between the same two
 * resources' IAM policies in opposite directions within one stack —
 * confirmed as a real, deploy-blocking `Circular dependency between
 * resources` CloudFormation error during a real `cdk deploy` with
 * `enableDevOpsAgentGate=true` (not just the informational F3004
 * CloudFormation-Validate warning; that warning alone did not block
 * deploy). Building the identical policy via `iam.Grant.addToPrincipal`
 * with a manually-formatted ARN string (same format
 * `arnForStateMachine()` produces internally) grants the exact same
 * permission without CDK inferring any construct-level ordering dependency
 * from it, breaking the cycle. Only valid when the state machine's
 * `stateMachineName` is a fixed string set at synth time (true here:
 * `${projectName}-triage-workflow`), not an auto-generated physical name
 * only known after creation.
 */
export function grantTaskResponseByArn(
  grantee: iam.IGrantable & Construct,
  stateMachineName: string,
): void {
  const stack = cdk.Stack.of(grantee);
  iam.Grant.addToPrincipal({
    grantee,
    actions: ['states:SendTaskSuccess', 'states:SendTaskFailure', 'states:SendTaskHeartbeat'],
    resourceArns: [
      stack.formatArn({
        service: 'states',
        resource: 'stateMachine',
        arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
        resourceName: stateMachineName,
      }),
    ],
  });
}

export function grantTableReadWithoutKeyPolicy(
  grantee: iam.IGrantable,
  table: dynamodb.ITable,
  kmsKeyArn: string,
): void {
  iam.Grant.addToPrincipal({
    grantee,
    actions: [...DYNAMODB_READ_ACTIONS],
    resourceArns: [table.tableArn, `${table.tableArn}/index/*`, `${table.tableArn}/stream/*`],
  });
  iam.Grant.addToPrincipal({
    grantee,
    actions: ['kms:Decrypt', 'kms:DescribeKey'],
    resourceArns: [kmsKeyArn],
  });
}

/**
 * Builds a PythonFunction bundled from the repository root, with a KMS-
 * encrypted log group matching this repo's existing retention convention
 * (production=90d, non-production=14d).
 *
 * `reservedConcurrentExecutions` (fix-lambda-reserved-concurrency,
 * 2026-09-29): this factory previously set every tunable EXCEPT this one on
 * every function it built — memory, timeout, architecture, tracing were all
 * props; concurrency was not, on any of the 8 functions this factory
 * builds. That gap was already documented, undelivered intent, not a new
 * requirement: the master `design.md` §3.3 has said "reserved concurrency
 * sized to the Bedrock quota" for the Classify Lambda specifically since
 * that section was written — nothing in Build ever wired it, the same
 * pattern as `fix-config-not-bundled-in-lambda.md` and
 * `fix-digest-disposition-not-persisted.md` before it (a documented
 * behavior silently never built, invisible because nothing crashed).
 *
 * Scoped to Classify only, not all 8 functions this factory builds: it is
 * the only one that calls `bedrock:InvokeModel` (see triage-workflow.ts's
 * `classifierFunction`), and it is the only one design.md names for this
 * treatment. The other 7 (Worker, Inventory, DevOpsAgent, Callback,
 * Intake, Settle, Digest) have no cited downstream throttling concern in
 * the master spec, and capping them uniformly with no such concern would
 * only risk `Lambda.TooManyRequestsException` under legitimate multi-
 * account fan-out (R2.1's "30-40 messages for one PUBLIC event within
 * seconds") with no corresponding safety benefit — scope creep the finding
 * never asked for.
 *
 * The actual number is a deploy-time context flag
 * (`lambdaReservedConcurrency`, wired in triage-workflow.ts/app.ts), not a
 * constant here — the Bedrock on-demand RPM quota this cap protects is
 * per-account and adjustable via Service Quotas, so a value baked into
 * source would be either wrong for a customer with a raised quota or
 * silently unsafe for one who hasn't requested an increase. See
 * QUICKSTART.md's context-flags table for the default and rationale.
 */
export function createTriagePythonFunction(
  scope: Construct,
  id: string,
  props: TriagePythonFunctionProps,
): pythonLambda.PythonFunction {
  const logGroup = new logs.LogGroup(scope, `${id}Logs`, {
    logGroupName: `/aws/lambda/health-triage-${id.toLowerCase()}`,
    retention: props.deployEnvironment === 'production'
      ? logs.RetentionDays.THREE_MONTHS
      : logs.RetentionDays.TWO_WEEKS,
    encryptionKey: props.kmsKey,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });

  return new pythonLambda.PythonFunction(scope, id, {
    // Staged copy of just src/ + requirements.txt, outside the repo tree —
    // see getStagedBuildRoot()'s docstring for why entry can no longer be
    // REPO_ROOT directly.
    entry: getStagedBuildRoot(),
    index: props.indexFile,
    handler: props.handlerName ?? 'handler',
    runtime: lambda.Runtime.PYTHON_3_13,
    architecture: props.architecture ?? lambda.Architecture.ARM_64,
    description: props.description,
    timeout: props.timeout ?? cdk.Duration.seconds(30),
    memorySize: props.memorySize ?? 512,
    environment: props.environment ?? {},
    logGroup,
    tracing: lambda.Tracing.ACTIVE,
    ...(props.reservedConcurrentExecutions !== undefined
      ? { reservedConcurrentExecutions: props.reservedConcurrentExecutions }
      : {}),
    bundling: {
      // __pycache__/.pyc may exist in the staged src/ copy if it was ever
      // run locally; exclude defensively even though assetExcludes only
      // reaches the in-container bundling commands, not the staging copy
      // (see getStagedBuildRoot()) — cheap and harmless either way.
      assetExcludes: ['__pycache__', '**/__pycache__/**', '**/*.pyc'],
    },
  });
}
