// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * TriageWorkflow — Step Functions Standard workflow.
 *
 * States (post Phase B — feat-devops-agent-enrichment):
 *   LoadEvent → Classify → ComputeUrgency → DecideDisposition
 *     → [Choice: RequiresInventory]
 *         → InventoryBaseline → (enrichment path via DevOps Agent gate, or
 *           the enrichmentViaDevOpsAgent=false rollback path
 *           InventoryBaseline → ProjectCost) for BREAKING_CHANGE,
 *           SECURITY_RELATED, COST_IMPLICATION
 *         → SkipInventoryAndCost (all other classes)
 *     → Notify → Audit
 *
 * Phase B retired the maintenance-class prechecks (RunPrechecks /
 * HasBoundPrecheck), the OLD per-service Inventory step, and the separate
 * readiness-investigation Parallel branch (IncidentAndReadinessGates).
 *
 * Every task has a Catch block → AuditOnError so no execution ends without
 * an audit record, even on failure.
 *
 * Execution name convention: sha256(eventArn + lastUpdatedTime)[:64]
 * (set by the Intake Lambda before calling StartExecution).
 *
 * This stack BUILDS its own Python Lambda functions (via PythonFunction,
 * see infra/lib/python-lambda.ts) rather than receiving them as props —
 * workerFunction (LoadEvent, ComputeUrgency, DecideDisposition, Notify,
 * Audit), classifierFunction (Classify — Strands on Lambda, heavier deps),
 * inventoryFunction (InventoryBaseline, ProjectCost, MergeEnrichment —
 * separated because it needs pricing:GetProducts for ProjectCost, which the
 * classifier/notify path does not), and optionally devOpsAgentFunction
 * (Phase 1b's incident gate). Building them in this same stack — rather
 * than in a separate stack passed in via props — is deliberate: it avoids
 * the cross-stack grantStartExecution()/grantTaskResponse() dependency
 * cycle a synthetic test harness hit during Phase 1b's verification when
 * functions and the state machine that grants them execution rights lived
 * in different stacks.
 *
 * Phase 5: Notify resolves the owning team (src/triage/routing.py) and
 * dispatches to SnsSink (always) plus JiraSink/SlackSink/TeamsSink when the
 * resolved team's RoutingTable entry configures them. Sink credentials are
 * read from the jiraSecret/slackSecret/teamsSecret Secrets Manager ARNs.
 *
 * The scheduled Digest Lambda (src/digest/handler.py) runs independently of
 * this workflow (see infra/lib/digest-stack.ts), triggered by an
 * EventBridge Scheduler rule — it queries ConsolidatedEvents directly
 * rather than being invoked per-execution.
 */

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import {
  createTriagePythonFunction,
  grantTableReadWithoutKeyPolicy,
  grantTableReadWriteWithoutKeyPolicy,
  grantTaskResponseByArn,
} from './python-lambda';

export interface TriageWorkflowProps extends cdk.StackProps {
  readonly projectName: string;
  /**
   * The CoreStack KMS key. Only its ARN is used (via Key.fromKeyArn inside
   * the constructor) — never the live construct. This is deliberate: the
   * live kms.Key construct's grant helpers (used by
   * dynamodb.Table.grantReadWriteData for encrypted tables) mutate the
   * KEY'S OWN resource policy for cross-account/cross-stack principals,
   * which would create a CoreStack -> TriageWorkflowStack dependency
   * (needing this stack's Lambda role ARNs) on top of this stack's
   * existing CoreStack -> TriageWorkflowStack dependency (needing the
   * key/table ARNs) — a real cycle hit during Build. Importing
   * by ARN gives an IKey with no mutable resource policy, so those grant
   * calls become safe no-ops; the key's default `trustAccountIdentities:
   * true` policy already allows same-account IAM principals via their own
   * role policy (which Table.grantReadWriteData still correctly writes).
   */
  readonly kmsKey: kms.Key;
  readonly deployEnvironment?: string;

  /**
   * The Amazon Bedrock Guardrail's ID/ARN (from GuardrailStack). Wired
   * onto ClassifierFunction's environment as GUARDRAIL_ID so
   * `src/classifier/service.py`'s `if config.GUARDRAIL_ID:` branch
   * actually fires — before this prop existed, GuardrailStack
   * provisioned a real guardrail that no Lambda ever received the ID
   * for, so every classification call ran without it despite
   * README.md/SECURITY.md claiming otherwise (confirmed: no env var, no
   * IAM grant, anywhere in this stack or app.ts). Required (not
   * optional) — a deployment without a guardrail configured is a
   * deployment that doesn't match its own security documentation.
   *
   * guardrailVersion is deliberately NOT a prop here (unlike
   * guardrailId/guardrailArn) — see the `guardrailVersion` local const
   * built inside this constructor for why: GuardrailStack's
   * CfnGuardrailVersion is a real resource CloudFormation replaces
   * (delete+create) whenever the guardrail's policy content changes
   * (see that resource's own docstring in guardrail-stack.ts). Taking
   * its `attrVersion` as a literal cross-stack prop the way
   * guardrailId/guardrailArn do wires a CDK cross-stack
   * `Fn::GetAtt`/`Fn::ImportValue` — confirmed via a real `cdk deploy`
   * that CloudFormation then permanently refuses to let GuardrailStack
   * replace, failing every attempt to roll out a new guardrail version
   * with "Cannot update export ... as it is in use by
   * HealthTriageWorkflowStack". Resolving it via an SSM dynamic
   * reference instead (against GuardrailStack's own
   * `GuardrailVersionParam`, same mechanism guardrailId's
   * GuardrailIdParam already publishes, just consumed differently
   * here) re-reads the current value at THIS stack's own deploy time
   * with no Export/Import edge between the two stacks, so
   * GuardrailStack can freely replace its CfnGuardrailVersion on any
   * future policy change without this stack blocking it.
   */
  readonly guardrailId: string;
  readonly guardrailArn: string;
  /**
   * The cross-Region guardrail-profile ARNs
   * (GuardrailStack.guardrailProfileDestinationRegionArns) the
   * classifier's `bedrock:ApplyGuardrail` grant must also cover — the
   * guardrail's topic policy now runs on the STANDARD tier, which
   * requires cross-Region inference; a caller invoking it needs
   * ApplyGuardrail on the guardrail itself PLUS every destination-Region
   * profile ARN, not just the source Region's (confirmed against the AWS
   * Bedrock user guide's cross-Region-inference permissions page).
   * Required, matching guardrailId/guardrailArn above — omitting it
   * would leave the classifier's real Bedrock calls failing on an
   * AccessDenied the moment inference actually routes cross-Region.
   */
  readonly guardrailProfileDestinationRegionArns: string[];

  // ---- Tables the Lambda functions built by this stack need (from CoreStack) ----
  readonly consolidatedEventsTable: dynamodb.ITable;
  readonly idempotencyTable: dynamodb.ITable;
  readonly accountContextCacheTable: dynamodb.ITable;
  readonly ticketMapTable: dynamodb.ITable;
  readonly auditLogTable: dynamodb.ITable;

  /**
   * Phase 5: Secrets Manager secrets for the sink credentials the NOTIFY
   * step's worker function reads (JiraSink, SlackSink, TeamsSink).
   */
  readonly jiraSecret?: secretsmanager.ISecret;
  readonly slackSecret?: secretsmanager.ISecret;
  readonly teamsSecret?: secretsmanager.ISecret;

  /**
   * Phase 5: the classification-result SNS topic (CoreStack.classificationTopic),
   * for SnsSink (the always-on core sink, R11.1). A real deploy + test event
   * confirmed this was never wired at all — SNS_TOPIC_ARN was never set on
   * workerFunction's environment, and no IAM grant existed, so every real
   * execution's SnsSink dispatch skipped with "SNS_TOPIC_ARN not configured"
   * (see fix-config-not-bundled-in-lambda.md's follow-up evidence). Imported
   * by ARN via `sns.Topic.fromTopicArn` (an ITopic with no mutable resource
   * policy), and granted via `iam.Grant.addToPrincipal` + explicit
   * `kms:Decrypt`/`kms:GenerateDataKey*` (matching the jiraSecret/slackSecret/
   * teamsSecret pattern above) rather than `Topic.grantPublish()` — reading
   * the installed aws-cdk-lib's sns-grants.generated.js confirmed
   * `grantPublish()` passes `keyActions: ["kms:Decrypt", "kms:GenerateDataKey*"]`
   * to the topic's `masterKey.grant()`, which DOES mutate the key's own
   * cross-stack resource policy for a live kms.Key construct (the same
   * cross-stack-grant cycle risk documented on the kmsKey prop above,
   * despite digest-stack.ts's now-corrected comment claiming SNS grants are
   * exempt from it).
   */
  readonly classificationTopicArn?: string;

  // ---- Phase 1b: DevOps Agent incident gate (from DevOpsAgentStack) ----
  /**
   * Enable the DevOps Agent incident-gate states. When false/omitted, the
   * DevOps Agent Lambda is not built and the workflow behaves exactly as
   * Phase 5 shipped it — impact/investigationLink pass through as null
   * (R8's default, R12.1 "module disabled").
   */
  readonly enableDevOpsAgentGate?: boolean;
  readonly taskTokenTable?: dynamodb.ITable;
  readonly agentSpaceCountersTable?: dynamodb.ITable;
  readonly activeInvestigationsTable?: dynamodb.ITable;
  readonly agentSpaceRegistryPath?: string;
  /**
   * Build-validation only: grants devOpsAgentFunction read access to these
   * specific webhook secret ARN(s). See the comment above this prop's
   * usage for why this stack does not add a blanket grant by default — a
   * real deployment wires this per registry entry, scoped to just the
   * ARNs its own registry actually references, never a wildcard.
   *
   * Widened from a single string to string[] for task 14 / -1c's live
   * multi-space validation (working spec feat-devops-agent-enrichment) —
   * that test's registry has TWO real registry entries (one per Agent
   * Space), each needing its own webhook secret grant, not one. Kept as a
   * temporary widening for this validation session, not a permanent
   * multi-space design: a real customer deployment would grant these
   * per-registry-entry itself (see README.md's Phase 1b-deploy section),
   * the same way this stack's own docstring for the singular case already
   * says.
   */
  readonly devOpsAgentWebhookSecretArnForValidation?: string | string[];

  // ---- Phase 5b: DevOps Agent readiness gate (from DevOpsAgentStack) ----
  /** Per-(eventArn, accountId) readiness-assessment tracking table (R12.3). */
  readonly readinessAssessmentsTable?: dynamodb.ITable;

  /**
   * Phase A (working spec feat-devops-agent-enrichment, req §7 / design
   * §3.0/§3.8, task 11/12): enable enrichment via a DevOps Agent
   * investigation for deadline-class events (BREAKING_CHANGE,
   * SECURITY_RELATED, COST_IMPLICATION), replacing the plug-in-based
   * Inventory/ProjectCost chain for those classes with a new
   * Map-over-distinct-spaces enrichment path. Default true (the reference
   * deploy's intended architecture — design §7's migration note: Stage 1
   * IS the intended design, not an opt-in). When false, deadline-class
   * events keep routing through the existing Inventory/ProjectCost chain
   * unchanged — this is the rollback/migration lever design §7 describes,
   * NOT a restoration of the deleted plug-ins (nothing is deleted during
   * Phase A; this flag only decides which of the two ALREADY-BUILT paths
   * the workflow routes deadline-class events through). Requires
   * enableDevOpsAgentGate=true and devOpsAgentFunction to exist — if
   * enableDevOpsAgentGate is false, this flag has no effect regardless of
   * its own value (there is no DevOps Agent Lambda to route to).
   */
  readonly enrichmentViaDevOpsAgent?: boolean;
  /**
   * Phase A (req E7 / design §3.6, task 11): the S3 event-snapshot
   * bucket's name. Not read directly by this stack's own Lambdas — the
   * snapshot key travels on the consolidated event record itself
   * (src/intake/service.py stamps event.snapshotKey; LoadEvent reads it
   * back). Accepted here only so a future caller that needs the bucket
   * name for a grant/reference has a natural place to pass it; unused by
   * the workflow graph itself today.
   */
  readonly eventSnapshotBucketName?: string;

  /**
   * fix-lambda-reserved-concurrency (2026-09-29): caps ClassifierFunction's
   * concurrent executions so a large multi-account event fan-out (R2.1:
   * "30-40 messages for one PUBLIC event within seconds", each becoming
   * its own Classify invocation) cannot exceed the deployment's Amazon
   * Bedrock on-demand requests-per-minute quota. Restores design.md §3.3's
   * documented-but-never-wired "reserved concurrency sized to the Bedrock
   * quota" — see python-lambda.ts's createTriagePythonFunction() docstring
   * for why this is scoped to Classify only, and why the number is a
   * deploy-time knob rather than a constant.
   *
   * @default 5 — conservative: Bedrock's default on-demand RPM quota for
   *   Claude models is commonly in the low single/double digits per
   *   account until a Service Quotas increase is requested (varies by
   *   model/account/Region — this default does not assume any specific
   *   quota value, it only avoids letting an unbounded fan-out exceed
   *   *whatever* the deployment's real quota is by more than a small,
   *   safe margin). Raise via the `lambdaReservedConcurrency` CDK context
   *   flag once a real quota increase is confirmed (see QUICKSTART.md).
   */
  readonly classifierReservedConcurrency?: number;
}

export class TriageWorkflowStack extends cdk.Stack {
  public readonly stateMachine: sfn.StateMachine;
  /**
   * The literal state machine name string (NOT `stateMachine.stateMachineName`,
   * which returns a live attribute token) — exposed so app.ts's
   * CallbackFunction grant can use `grantTaskResponseByArn` too, avoiding
   * the same live-dependency cycle this field's docstring in
   * python-lambda.ts explains.
   */
  public readonly stateMachineName: string;
  /** Built by this stack — exposed so app.ts can wire the intake Lambda's StartExecution grant and callers needing direct references. */
  public readonly workerFunction: lambda.IFunction;
  public readonly inventoryFunction: lambda.IFunction;
  public readonly devOpsAgentFunction?: lambda.IFunction;

  constructor(scope: Construct, id: string, props: TriageWorkflowProps) {
    super(scope, id, props);

    const {
      projectName,
      classificationTopicArn,
      jiraSecret,
      slackSecret,
      teamsSecret,
    } = props;
    const deployEnvironment = props.deployEnvironment ?? 'prototype';
    // Imported by ARN — see the kmsKey prop doc above for why this avoids
    // a CoreStack <-> TriageWorkflowStack dependency cycle.
    const kmsKey = kms.Key.fromKeyArn(this, 'ImportedKmsKey', props.kmsKey.keyArn);
    const enableDevOpsAgentGate = props.enableDevOpsAgentGate ?? false;
    // fix-guardrail-topic-false-positives (real deploy defect #2): read
    // GuardrailStack's published guardrail version via an SSM dynamic
    // reference against `/${projectName}/guardrail-version`
    // (GuardrailStack's own GuardrailVersionParam — same parameter name
    // that stack builds from its own `projectName` prop) rather than
    // accepting `guardrailStack.guardrailVersion` as a literal TS-level
    // cross-stack prop. `valueForStringParameter` (confirmed by reading
    // the installed aws-cdk-lib's aws-ssm/lib/parameter.js source) emits
    // a CloudFormation `AWS::SSM::Parameter::Value<String>` parameter
    // resolved at THIS stack's own deploy time, not a
    // `Fn::GetAtt`/`Fn::ImportValue` edge — so GuardrailStack's
    // CfnGuardrailVersion (which CloudFormation replaces on every real
    // policy change, see its docstring) is never "in use by" this stack
    // the way the literal cross-stack prop made it, and can be replaced
    // freely on future GuardrailStack deploys. This does NOT change
    // QUICKSTART.md's deploy instructions: this stack still imports
    // guardrailId/guardrailArn from GuardrailStack's mutable CfnGuardrail
    // (only the version-specific export was removed), so CDK's
    // dependency graph still orders GuardrailStack's deploy to complete
    // before this stack's within a single `cdk deploy --all` — confirmed
    // via the synthesized cloud assembly manifest
    // (HealthTriageWorkflowStack.dependencies still lists
    // HealthTriageGuardrailStack). Lambda env vars are static at deploy
    // time, so this stack's own deploy step (same `cdk deploy --all` run,
    // just later in the same dependency-ordered sequence) is what reads
    // the parameter's THEN-current value — already the new version, since
    // GuardrailStack's replacement finished first.
    const guardrailVersion = ssm.StringParameter.valueForStringParameter(
      this,
      `/${projectName}/guardrail-version`,
    );

    // -----------------------------------------------------------------------
    // Lambda functions (Python, bundled via PythonFunction — see
    // infra/lib/python-lambda.ts). Built HERE, in the same stack as the
    // state machine that grants them execution rights, so
    // grantStartExecution() and the DevOps Agent Lambda's
    // states:SendTaskFailure grant never create a cross-stack dependency
    // cycle (a synthetic test harness hit exactly this cycle during Phase
    // 1b's verification when functions and the state machine lived in
    // different stacks).
    // -----------------------------------------------------------------------
    const commonEnv: Record<string, string> = {
      // AWS_REGION is a reserved Lambda runtime env var — injected
      // automatically, must not be set manually (CDK synth rejects it).
      LOG_LEVEL: 'INFO',
      CONSOLIDATED_TABLE_NAME: props.consolidatedEventsTable.tableName,
      IDEMPOTENCY_TABLE_NAME: props.idempotencyTable.tableName,
      ACCOUNT_CACHE_TABLE_NAME: props.accountContextCacheTable.tableName,
      TICKET_MAP_TABLE_NAME: props.ticketMapTable.tableName,
      AUDIT_LOG_TABLE_NAME: props.auditLogTable.tableName,
      KMS_KEY_ARN: kmsKey.keyArn,
      ...(classificationTopicArn ? { SNS_TOPIC_ARN: classificationTopicArn } : {}),
      ...(jiraSecret ? { JIRA_SECRET_ARN: jiraSecret.secretArn } : {}),
      ...(slackSecret ? { SLACK_SECRET_ARN: slackSecret.secretArn } : {}),
      ...(teamsSecret ? { TEAMS_SECRET_ARN: teamsSecret.secretArn } : {}),
    };

    const workerFunction = createTriagePythonFunction(this, 'WorkerFunction', {
      indexFile: 'src/classifier/worker_handler.py',
      description: 'AWS Health Event Triage Agent — LOAD_EVENT, COMPUTE_URGENCY, DECIDE_DISPOSITION, NOTIFY, AUDIT steps',
      timeout: cdk.Duration.minutes(2),
      memorySize: 512,
      environment: commonEnv,
      kmsKey,
      deployEnvironment,
    });
    this.workerFunction = workerFunction;

    // Classifier: heavier deps (strands-agents, bedrock-agentcore), longer
    // timeout/memory per design.md's "2 GB, 10-min timeout" spec.
    const classifierFunction = createTriagePythonFunction(this, 'ClassifierFunction', {
      indexFile: 'src/classifier/handler.py',
      description: 'AWS Health Event Triage Agent — CLASSIFY step (Strands on Lambda)',
      timeout: cdk.Duration.minutes(10),
      memorySize: 2048,
      environment: {
        ...commonEnv,
        BEDROCK_MODEL_ID: 'eu.anthropic.claude-sonnet-5',
        BEDROCK_REGION: cdk.Stack.of(this).region,
        // fix-guardrail-not-wired (PCSR blocker 3): GuardrailStack
        // provisions a real Guardrail, but nothing previously forwarded
        // its ID/version onto this function — src/classifier/service.py's
        // `if config.GUARDRAIL_ID:` branch always evaluated false, so
        // every Bedrock call ran without the guardrail despite
        // README.md/SECURITY.md documenting it as always-on. Required
        // props (see TriageWorkflowProps), not optional — a deployment
        // with no guardrail configured is a deployment that contradicts
        // its own security documentation.
        GUARDRAIL_ID: props.guardrailId,
        // Resolved above via SSM dynamic reference, not props.guardrailVersion
        // — see that local const's doc comment and the guardrailId/
        // guardrailArn prop doc above for why.
        GUARDRAIL_VERSION: guardrailVersion,
      },
      // BEDROCK_REGION is not a reserved name (only AWS_REGION is), so it stays.
      kmsKey,
      deployEnvironment,
      // fix-lambda-reserved-concurrency: bounds concurrent Bedrock calls
      // under multi-account fan-out — see the prop's doc on
      // TriageWorkflowProps above and createTriagePythonFunction()'s
      // docstring in python-lambda.ts for why only this function is capped.
      reservedConcurrentExecutions: props.classifierReservedConcurrency ?? 5,
    });
    grantTableReadWriteWithoutKeyPolicy(classifierFunction, props.consolidatedEventsTable, props.kmsKey.keyArn);
    classifierFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
      resources: ['*'],
    }));
    // Scoped to the specific guardrail ARN plus the cross-Region
    // guardrail-profile ARNs its STANDARD-tier topic policy requires —
    // never a wildcard (security-policies.md). The profile ARNs are the
    // permission fix-guardrail-topic-false-positives added: cross-Region
    // inference needs ApplyGuardrail on every destination-Region profile
    // resource, not only the guardrail's own source-Region ARN.
    classifierFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['bedrock:ApplyGuardrail'],
      resources: [props.guardrailArn, ...props.guardrailProfileDestinationRegionArns],
    }));

    const inventoryFunction = createTriagePythonFunction(this, 'InventoryFunction', {
      indexFile: 'src/inventory/handler.py',
      description: 'AWS Health Event Triage Agent — INVENTORY_BASELINE, PROJECT_COST, MERGE_ENRICHMENT steps',
      timeout: cdk.Duration.minutes(3),
      memorySize: 512,
      environment: commonEnv,
      kmsKey,
      deployEnvironment,
    });
    this.inventoryFunction = inventoryFunction;

    let devOpsAgentFunction: lambda.IFunction | undefined;
    if (enableDevOpsAgentGate) {
      devOpsAgentFunction = createTriagePythonFunction(this, 'DevOpsAgentFunction', {
        indexFile: 'src/devops_agent/workflow_handler.py',
        description: 'AWS Health Event Triage Agent — RESOLVE_AGENT_SPACE, RESOLVE_AGENT_SPACES, DECIDE_INVESTIGATION, TRIGGER_INVESTIGATION, SUMMARIZE_OUTCOME steps',
        timeout: cdk.Duration.minutes(1),
        memorySize: 512,
        environment: {
          ...commonEnv,
          TASK_TOKEN_TABLE_NAME: props.taskTokenTable?.tableName ?? '',
          AGENT_SPACE_COUNTERS_TABLE_NAME: props.agentSpaceCountersTable?.tableName ?? '',
          ACTIVE_INVESTIGATIONS_TABLE_NAME: props.activeInvestigationsTable?.tableName ?? '',
          AGENT_SPACE_REGISTRY_PATH: props.agentSpaceRegistryPath ?? '',
          READINESS_ASSESSMENTS_TABLE_NAME: props.readinessAssessmentsTable?.tableName ?? '',
        },
        kmsKey,
        deployEnvironment,
      });
      this.devOpsAgentFunction = devOpsAgentFunction;

      // These three tables live in DevOpsAgentStack, encrypted with the
      // same CoreStack key — the without-key-policy helper avoids a
      // DevOpsAgentStack -> TriageWorkflowStack cycle the same way it
      // avoids the CoreStack one above.
      if (props.taskTokenTable) {
        grantTableReadWriteWithoutKeyPolicy(devOpsAgentFunction, props.taskTokenTable, props.kmsKey.keyArn);
      }
      if (props.agentSpaceCountersTable) {
        grantTableReadWriteWithoutKeyPolicy(devOpsAgentFunction, props.agentSpaceCountersTable, props.kmsKey.keyArn);
      }
      if (props.activeInvestigationsTable) {
        grantTableReadWriteWithoutKeyPolicy(devOpsAgentFunction, props.activeInvestigationsTable, props.kmsKey.keyArn);
      }
      // Phase 5b: readiness gate — same devOpsAgentFunction handles
      // RESOLVE_READINESS_ELIGIBILITY/TRIGGER_READINESS, so it needs
      // read/write on the ReadinessAssessments table too.
      if (props.readinessAssessmentsTable) {
        grantTableReadWriteWithoutKeyPolicy(devOpsAgentFunction, props.readinessAssessmentsTable, props.kmsKey.keyArn);
      }
      // Webhook secret reads are scoped per-registry-entry ARN at the IAM
      // policy level once the registry's real secret ARNs are known
      // (design.md §10) — a wildcard grant here would defeat that scoping,
      // so this stack does not add a blanket secretsmanager:GetSecretValue
      // grant. Callers wiring a real AgentSpaceRegistry must grant read
      // access to devOpsAgentFunction for each registry entry's specific
      // webhookSecretArn (see README.md's Phase 1b-deploy section).
      // devOpsAgentWebhookSecretArnForValidation (app.ts) is exactly that:
      // a caller-supplied grant for the one real registry entry this
      // session's live validation wires — confirmed necessary by a real
      // deploy + test event that failed with AccessDeniedException on
      // GetSecretValue before this grant existed.
      if (props.devOpsAgentWebhookSecretArnForValidation) {
        const validationSecretArns = Array.isArray(props.devOpsAgentWebhookSecretArnForValidation)
          ? props.devOpsAgentWebhookSecretArnForValidation
          : [props.devOpsAgentWebhookSecretArnForValidation];
        iam.Grant.addToPrincipal({
          grantee: devOpsAgentFunction,
          actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
          resourceArns: validationSecretArns,
        });
      }
      //
      // states:SendTaskFailure/SendTaskSuccess grants are added after
      // `this.stateMachine` is created below (grantTaskResponse needs the
      // state machine to exist first).
    }

    // -----------------------------------------------------------------------
    // DynamoDB grants for the worker/inventory functions (agent-internal
    // resources, per iam-permission-boundary — these tables are the agent's
    // own, not customer resources).
    // -----------------------------------------------------------------------
    const keyArn = props.kmsKey.keyArn;
    grantTableReadWriteWithoutKeyPolicy(workerFunction, props.consolidatedEventsTable, keyArn);
    grantTableReadWriteWithoutKeyPolicy(workerFunction, props.ticketMapTable, keyArn);
    grantTableReadWriteWithoutKeyPolicy(workerFunction, props.auditLogTable, keyArn);
    grantTableReadWithoutKeyPolicy(inventoryFunction, props.consolidatedEventsTable, keyArn);
    grantTableReadWriteWithoutKeyPolicy(inventoryFunction, props.auditLogTable, keyArn);
    grantTableReadWriteWithoutKeyPolicy(classifierFunction, props.idempotencyTable, keyArn);
    grantTableReadWithoutKeyPolicy(classifierFunction, props.accountContextCacheTable, keyArn);

    // -----------------------------------------------------------------------
    // Execution log group
    // -----------------------------------------------------------------------
    const workflowLogGroup = new logs.LogGroup(this, 'WorkflowLogGroup', {
      logGroupName: `/aws/states/${projectName}-triage-workflow`,
      retention: logs.RetentionDays.THREE_MONTHS,
      encryptionKey: kmsKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // -----------------------------------------------------------------------
    // Terminal: Audit (always reached)
    // -----------------------------------------------------------------------
    const auditSuccess = new tasks.LambdaInvoke(this, 'Audit', {
      lambdaFunction: workerFunction,
      payload: sfn.TaskInput.fromObject({
        'step': 'AUDIT',
        'eventArn.$': '$.eventArn',
        'executionId.$': '$$.Execution.Name',
        'status': 'SUCCESS',
        'error': null,
      }),
      resultPath: sfn.JsonPath.DISCARD,
    });

    // Error path: enriches the state with error info then audits. Built as
    // a factory (not a single shared instance) because Step Functions
    // rejects reusing the same State construct across separate graphs —
    // a real «StateAlreadyInGraph» synth error surfaced when the shared
    // instance below was also referenced from inside a Parallel branch's
    // sub-graph (Phase 5b's readiness-gate build; every Parallel branch
    // needs its own dedicated EnrichError/AuditOnError chain).
    const buildAuditOnError = (idSuffix: string): sfn.IChainable =>
      new sfn.Pass(this, `EnrichError${idSuffix}`, {
        parameters: {
          'eventArn.$': '$.eventArn',
          'error.$': '$.Cause',
          'step.$': '$.step',
        },
      }).next(
        new tasks.LambdaInvoke(this, `AuditOnError${idSuffix}`, {
          lambdaFunction: workerFunction,
          payload: sfn.TaskInput.fromObject({
            'step': 'AUDIT',
            'eventArn.$': '$.eventArn',
            'executionId.$': '$$.Execution.Name',
            'status': 'ERROR',
            'error.$': '$.error',
            'failedStep.$': '$.step',
          }),
          resultPath: sfn.JsonPath.DISCARD,
        }),
      );
    // The main-graph instance, used by every Catch outside a Parallel branch.
    const auditOnError = buildAuditOnError('');

    // -----------------------------------------------------------------------
    // Notify — publishes NotificationPayload v1 to SNS
    // -----------------------------------------------------------------------
    const notifyState = new tasks.LambdaInvoke(this, 'Notify', {
      lambdaFunction: workerFunction,
      payload: sfn.TaskInput.fromObject({
        'step': 'NOTIFY',
        'eventArn.$': '$.eventArn',
        // 'event' MUST be forwarded to the actual NOTIFY Lambda invocation
        // payload, not just carried through PrepareNotifyInput's output --
        // this Task's own `payload` object is a SEPARATE projection of
        // fields and dropped 'event' independently of that Pass state. A
        // real deploy + test event (service: "EKS") confirmed this: even
        // after PrepareNotifyInput was fixed to carry 'event' in its own
        // output, a direct `aws lambda invoke` with the exact real
        // execution's Notify-state INPUT (captured from
        // get-execution-history) correctly resolved Platform-Kubernetes,
        // proving worker_handler.py and config/routing.example.json were
        // both already correct — but the real Step-Functions-driven
        // invocation still returned Platform-Operations, because THIS
        // payload object (what Step Functions actually sends the Lambda)
        // never included 'event' at all.
        'event.$': '$.event',
        'classification.$': '$.classification',
        'urgency.$': '$.urgency',
        'deadline.$': '$.deadline',
        'disposition.$': '$.disposition',
        'reason.$': '$.reason',
        'impactSummary.$': '$.impactSummary',
        'costProjection.$': '$.costProjection',
        'precheckResult.$': '$.precheckResult',
        'impact.$': '$.impact',
        'investigationLink.$': '$.investigationLink',
        // Phase 5b: readiness-gate fields (design.md §9's schema
        // extension) -- present alongside impact/investigationLink, null
        // when the readiness gate is disabled/not eligible/not built.
        // JsonPath.isPresent-style optional fields aren't needed here:
        // every path into this state (including the Phase 1b-only /
        // gate-disabled paths via preNotifyPass/investigationFailedPass/
        // SkipInvestigation) sets these to null explicitly so the field
        // is always structurally present on the payload.
        'readinessFeasibility.$': '$.readinessFeasibility',
        'readinessBlockers.$': '$.readinessBlockers',
        'readinessRisk.$': '$.readinessRisk',
        'readinessAssessmentLink.$': '$.readinessAssessmentLink',
      }),
      resultPath: '$.notifyResult',
    });
    notifyState.addCatch(auditOnError, {
      resultPath: '$.Cause',
      errors: ['States.ALL'],
    });
    notifyState.next(auditSuccess);

    // -----------------------------------------------------------------------
    // Phase 1b: DevOps Agent incident gate (R12 incident gate only).
    // Inserted between DecideDisposition and Notify (design.md §7). When
    // devOpsAgentFunction is not supplied, the whole block is skipped and
    // impact/investigationLink pass through as null (R8's default,
    // R12.1 "module disabled").
    // -----------------------------------------------------------------------
    // NOTE: sfn.Pass's `parameters` prop silently drops any key with a
    // literal `null` value during synth — confirmed by reading the
    // installed CDK's FieldUtils.renderObject (json-path.js): its
    // recurseObject() helper treats `value == null` as "omit this key"
    // for both null and undefined. A Pass mixing dynamic `.$` fields with
    // static nulls in one `parameters` object therefore loses the null
    // fields entirely. Fixed here by seeding the nulls first (via a
    // `result`-based Pass, which bypasses that renderer and preserves
    // nulls) and merging them onto state via a states.JsonMerge Pass, so
    // PrepareNotifyInput's own `.$` references pick them up like any
    // other upstream field.
    const seedNullReadinessFields = new sfn.Pass(this, 'SeedNullReadinessFields', {
      resultPath: '$.nullReadinessFields',
      result: sfn.Result.fromObject({
        readinessFeasibility: null,
        readinessBlockers: null,
        readinessRisk: null,
        readinessAssessmentLink: null,
      }),
    });
    const preNotifyPass = new sfn.Pass(this, 'PrepareNotifyInput', {
      parameters: {
        'eventArn.$': '$.eventArn',
        // 'event' MUST be carried through to NOTIFY: worker_handler.py's
        // notify() reads payload.get("service", "") to pass to
        // resolve_team()'s SERVICE routing rule, and payload.get(
        // "eventTypeCode"/"statusCode"/"affectedEntities") for the
        // NotificationPayload and should_close()/dispatcher's record dict.
        // A real deploy + test event (service: "EKS", matching
        // config/routing.example.json's SERVICE/EKS -> Platform-Kubernetes
        // rule) confirmed this Pass state previously dropped 'event'
        // entirely — resolve_team() always received service="" and fell
        // through to the DEFAULT rule regardless of the event's real
        // service, even after config/ was correctly bundled into the
        // Lambda asset (a distinct bug from the config-bundling one; this
        // Pass state simply never forwarded 'event' at all).
        'event.$': '$.event',
        'classification.$': '$.classification',
        'urgency.$': '$.urgency',
        'deadline.$': '$.deadline',
        'reason.$': '$.reason',
        'disposition.$': '$.disposition',
        'precheck.$': '$.precheck',
        'precheckResult.$': '$.precheckResult',
        'impactSummary.$': '$.impactSummary',
        'costProjection.$': '$.costProjection',
        // DevOps Agent module disabled entirely (enableDevOpsAgentGate:
        // false) -- impact/investigationLink are never set anywhere on
        // this path (only resolveAgentSpaceState's chain sets them), so
        // they must come from nullDefaults rather than a bare '$.impact'/
        // '$.investigationLink' reference — a real deploy + test event
        // confirmed the bare reference is a hard States.Runtime failure,
        // not just a silently-null value, when the source key was never
        // written at all (as opposed to written-then-dropped, this
        // states.ts file's other null-preservation fix's failure mode).
        'impact.$': '$.nullDefaults.impact',
        'investigationLink.$': '$.nullDefaults.investigationLink',
        // Both the incident-gate and readiness-gate fields stay null,
        // matching R12.1's "module disabled" default. Sourced from
        // seedNullReadinessFields (see the note above `preNotifyPass`).
        'readinessFeasibility.$': '$.nullReadinessFields.readinessFeasibility',
        'readinessBlockers.$': '$.nullReadinessFields.readinessBlockers',
        'readinessRisk.$': '$.nullReadinessFields.readinessRisk',
        'readinessAssessmentLink.$': '$.nullReadinessFields.readinessAssessmentLink',
      },
    });

    let postDispositionState: sfn.IChainable;
    // Phase A (task 11): the enrichment path's entry point
    // (ResolveAgentSpaces -> Map -> MergeEnrichment -> Notify), built
    // below only when devOpsAgentFunction exists. Stays undefined when
    // the DevOps Agent module is disabled entirely or when
    // enrichmentViaDevOpsAgent is false — RequiresInventory's routing
    // below falls back to the existing Inventory/ProjectCost chain in
    // either case.
    let enrichmentEntryState: sfn.IChainable | undefined;
    // Whether the enrichment path is genuinely the active path for THIS
    // deploy (devOpsAgentFunction exists AND enrichmentViaDevOpsAgent is
    // true) — set inside the devOpsAgentFunction branch below, always
    // false in the else branch (no devOpsAgentFunction means no
    // enrichment path can exist regardless of the flag's own value).
    // Declared this early because the OLD Inventory/ProjectCost chain
    // (constructed well below, but before RequiresInventory) needs this
    // decision available to conditionally wire its own final edge into
    // postDispositionState — see that chain's own comment for why.
    let enrichmentViaDevOpsAgentActive = false;

    if (devOpsAgentFunction) {
      // Set at the TOP of this block (not after the enrichment chain is
      // built, where an earlier draft placed it) because the enrichment
      // chain's own final edges — several hundred lines below — need
      // this value to decide whether they should exist at all, matching
      // the identical gating this file already applies to the OLD
      // Inventory/ProjectCost chain's own final edge (see its comment,
      // well below). props.enrichmentViaDevOpsAgent defaults true
      // (design §7 — Stage 1 IS the intended architecture).
      enrichmentViaDevOpsAgentActive = props.enrichmentViaDevOpsAgent ?? true;

      const summarizeOutcomeState = new tasks.LambdaInvoke(this, 'SummarizeOutcome', {
        lambdaFunction: devOpsAgentFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'SUMMARIZE_OUTCOME',
          'investigationDecision.$': '$.investigationDecision',
          'investigationOutcome.$': '$.investigationOutcome',
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          // NOTE: 'impact'/'investigationLink' deliberately not forwarded
          // here — summarize_outcome_step (workflow_handler.py) never
          // reads them as input on the "triggered" path (it always
          // returns a fresh dict from investigationOutcome), and its
          // "not triggered" fallback path is unreachable from this state
          // (only reached via PrepareTriggerInput, which only runs when
          // ShouldTriggerInvestigation already chose trigger:true). A
          // real deploy + test event confirmed a bare '$.impact'/
          // '$.investigationLink' reference here is a hard States.Runtime
          // failure once the incident gate is enabled, since neither key
          // exists in state at this point in the trigger-taken branch.
        }),
        resultSelector: {
          'impact.$': '$.Payload.impact',
          'investigationLink.$': '$.Payload.investigationLink',
        },
        resultPath: '$.outcomeResult',
      });
      summarizeOutcomeState.addCatch(buildAuditOnError('SummarizeOutcome'), {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });
      const mergeOutcomeState = new sfn.Pass(this, 'MergeOutcome', {
        parameters: {
          'eventArn.$': '$.eventArn',
          // 'event' forwarded (Phase B): MergeGatesResult now runs directly in
          // the main chain after this state, and Notify reads '$.event'.
          'event.$': '$.event',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.disposition',
          'precheck.$': '$.precheck',
          'precheckResult.$': '$.precheckResult',
          'impactSummary.$': '$.impactSummary',
          'costProjection.$': '$.costProjection',
          'impact.$': '$.outcomeResult.impact',
          'investigationLink.$': '$.outcomeResult.investigationLink',
          // Forwarded so MergeGatesResult (now directly downstream, Phase B)
          // can source its always-null readiness* fields from nullDefaults.
          'nullDefaults.$': '$.nullDefaults',
        },
      });
      summarizeOutcomeState.next(mergeOutcomeState);

      // .waitForTaskToken: this Lambda sends the webhook and returns
      // without completing the task; callback_handler.py (triggered by the
      // aws.aidevops EventBridge forward, StackSet C) later calls
      // SendTaskSuccess/SendTaskFailure with $.TaskToken. Heartbeat is not
      // used (no confirmed heartbeat signal exists in the DevOps Agent API,
      // design.md §7) — only the overall timeout bounds the wait.
      const triggerInvestigationState = new tasks.LambdaInvoke(this, 'TriggerInvestigation', {
        lambdaFunction: devOpsAgentFunction,
        integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
        payload: sfn.TaskInput.fromObject({
          'step': 'TRIGGER_INVESTIGATION',
          'TaskToken': sfn.JsonPath.taskToken,
          'event.$': '$.event',
          'agentSpaceEntry.$': '$.agentSpaceEntry',
        }),
        // Field names here MUST match summarize_investigation_outcome()'s
        // real return dict (src/devops_agent/outcome.py) — verified by
        // reading it directly, not inferred: {impact, summary, root_cause,
        // severity, findings, recommendations, investigation_status}, all
        // snake_case (Python convention), plus taskId/agentSpaceId added
        // by callback_handler.py's caller on top (those two ARE
        // camelCase — callback_handler.py sets them directly). A real
        // SendTaskSuccess with that exact real shape confirmed 'rootCause'/
        // 'investigationStatus' below were wrong — they don't exist in the
        // real output (it's 'root_cause'/'investigation_status'), so
        // $.rootCause/$.investigationStatus were always undefined
        // JSONPath references, a hard States.Runtime failure once a real
        // callback ever completed successfully (masked until this session
        // because the incident gate had never been deployed/exercised
        // live before).
        resultSelector: {
          'impact.$': '$.impact',
          'taskId.$': '$.taskId',
          'summary.$': '$.summary',
          'rootCause.$': '$.root_cause',
          'severity.$': '$.severity',
          'findings.$': '$.findings',
          'recommendations.$': '$.recommendations',
          'investigationStatus.$': '$.investigation_status',
        },
        resultPath: '$.investigationOutcome',
        taskTimeout: sfn.Timeout.duration(cdk.Duration.minutes(55)),
      });
      // Catch: investigation failed/cancelled/timed out. Route to Audit's
      // failure recording but still fall through to Notify with
      // impact=unverifiable rather than dropping the ticket (R12.7,
      // design.md §7's Catch → AUDIT → NOTIFY, impact: unverifiable).
      const investigationFailedPass = new sfn.Pass(this, 'MarkInvestigationUnverifiable', {
        parameters: {
          'eventArn.$': '$.eventArn',
          // 'event' forwarded (Phase B): MergeGatesResult now runs directly in
          // the main chain after this state, and Notify reads '$.event'.
          'event.$': '$.event',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.disposition',
          'precheck.$': '$.precheck',
          'precheckResult.$': '$.precheckResult',
          'impactSummary.$': '$.impactSummary',
          'costProjection.$': '$.costProjection',
          'impact': 'unverifiable',
          // 'investigationLink': null literal would be silently dropped by
          // sfn.Pass's parameters renderer (see SeedNullDefaults docstring
          // above) — sourced from nullDefaults instead, threaded through
          // this branch via MergeAgentSpaceEntry below.
          'investigationLink.$': '$.nullDefaults.investigationLink',
          // nullDefaults forwarded for MergeGatesResult's readiness* nulls.
          'nullDefaults.$': '$.nullDefaults',
        },
      });
      triggerInvestigationState.addCatch(investigationFailedPass, {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });
      triggerInvestigationState.next(summarizeOutcomeState);

      const decideInvestigationState = new tasks.LambdaInvoke(this, 'DecideInvestigation', {
        lambdaFunction: devOpsAgentFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'DECIDE_INVESTIGATION',
          'event.$': '$.event',
          'agentSpaceEntry.$': '$.agentSpaceEntry',
        }),
        resultSelector: {
          'investigationDecision.$': '$.Payload.investigationDecision',
        },
        resultPath: '$.decisionResult',
      });
      decideInvestigationState.addCatch(buildAuditOnError('DecideInvestigation'), {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });
      // Phase B (feat-devops-agent-enrichment, design §3.7/§3.8): the
      // incident gate is no longer wrapped in the IncidentAndReadinessGates
      // Parallel (its second, readiness branch was retired). DecideInvestigation
      // and its downstream trigger/skip sub-graph now run DIRECTLY in the main
      // chain, and every terminal of that sub-graph (MergeOutcome,
      // SkipInvestigation, MarkInvestigationUnverifiable) flows into
      // MergeGatesResult, which folds the four (now always-null) readiness*
      // fields back on for NotificationPayload v1 schema compatibility (E4.4).
      const skipInvestigationState = new sfn.Pass(this, 'SkipInvestigation', {
        parameters: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.disposition',
          'precheck.$': '$.precheck',
          'precheckResult.$': '$.precheckResult',
          'impactSummary.$': '$.impactSummary',
          'costProjection.$': '$.costProjection',
          // Not investigated: impact stays whatever R8 already set
          // (design.md §9 — additive, non-destructive when skipped).
          'impact.$': '$.impactSummary.impact_status',
          'investigationLink.$': '$.nullDefaults.investigationLink',
          // 'event' is forwarded so MergeGatesResult (which no longer sits
          // behind a Parallel that re-supplied it) still sees it downstream.
          // nullDefaults forwarded for MergeGatesResult's readiness* nulls.
          'nullDefaults.$': '$.nullDefaults',
        },
      });
      decideInvestigationState.next(
        new sfn.Choice(this, 'ShouldTriggerInvestigation')
          .when(
            sfn.Condition.booleanEquals('$.decisionResult.investigationDecision.trigger', true),
            new sfn.Pass(this, 'PrepareTriggerInput', {
              parameters: {
                'eventArn.$': '$.eventArn',
                'event.$': '$.event',
                'classification.$': '$.classification',
                'urgency.$': '$.urgency',
                'deadline.$': '$.deadline',
                'reason.$': '$.reason',
                'disposition.$': '$.disposition',
                'precheck.$': '$.precheck',
                'precheckResult.$': '$.precheckResult',
                'impactSummary.$': '$.impactSummary',
                'costProjection.$': '$.costProjection',
                'agentSpaceEntry.$': '$.agentSpaceEntry',
                'investigationDecision.$': '$.decisionResult.investigationDecision',
                'nullDefaults.$': '$.nullDefaults',
              },
            }).next(triggerInvestigationState),
          )
          .otherwise(skipInvestigationState),
      );

      const resolveAgentSpaceState = new tasks.LambdaInvoke(this, 'ResolveAgentSpace', {
        lambdaFunction: devOpsAgentFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'RESOLVE_AGENT_SPACE',
          'event.$': '$.event',
          'accountContexts.$': '$.accountContexts',
        }),
        resultSelector: {
          'agentSpaceEntry.$': '$.Payload.agentSpaceEntry',
        },
        resultPath: '$.resolveResult',
      });
      resolveAgentSpaceState.addCatch(auditOnError, { resultPath: '$.Cause', errors: ['States.ALL'] });

      // ---------------------------------------------------------------
      // Phase B (feat-devops-agent-enrichment, design §3.7/§3.8): the
      // IncidentAndReadinessGates Parallel and its second (readiness) branch
      // — ReadinessNoop, DecideReadiness (RESOLVE_READINESS_ELIGIBILITY),
      // ShouldTriggerReadiness/SkipReadiness, TriggerReadiness,
      // SummarizeReadiness, MergeReadinessSummary — were retired. A single
      // enrichment investigation now answers both impact and readiness
      // (E4.1), so only the incident gate remains here. A Parallel wrapping
      // exactly one branch is unnecessary, so DecideInvestigation and its
      // trigger/skip sub-graph run DIRECTLY in the main chain: every terminal
      // of that sub-graph (MergeOutcome, SkipInvestigation,
      // MarkInvestigationUnverifiable) flows into MergeGatesResult.
      //
      // MergeGatesResult reads impact/investigationLink at the top level
      // (where the sub-graph terminals write them — no '$[0]' Parallel-branch
      // indexing anymore) and folds the four readiness* fields back on as
      // null literals, sourced from nullDefaults so sfn.Pass's parameters
      // renderer does not silently drop them (the FieldUtils.renderObject bug
      // documented on SeedNullDefaults). E4.4 requires these four keys stay on
      // NotificationPayload v1 for schema compatibility even though nothing on
      // this path populates them now.
      // ---------------------------------------------------------------
      const mergeGatesResultState = new sfn.Pass(this, 'MergeGatesResult', {
        parameters: {
          'eventArn.$': '$.eventArn',
          // 'event' MUST be forwarded (a real deploy + incident-gate test
          // confirmed a missing '$.event' is a hard States.Runtime failure on
          // Notify, not a silent null) — the sub-graph terminals now forward
          // it directly since this Pass no longer sits behind a Parallel.
          'event.$': '$.event',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.disposition',
          'precheck.$': '$.precheck',
          'precheckResult.$': '$.precheckResult',
          'impactSummary.$': '$.impactSummary',
          'costProjection.$': '$.costProjection',
          // Top-level now (no Parallel resultSelector indexing) — the
          // sub-graph terminals write these directly.
          'impact.$': '$.impact',
          'investigationLink.$': '$.investigationLink',
          // E4.4: preserved on NotificationPayload v1, always null on this
          // incident-gate path now. Sourced from nullDefaults (null-preserving)
          // rather than a literal null, which parameters would drop.
          'readinessFeasibility.$': '$.nullDefaults.readinessFeasibility',
          'readinessBlockers.$': '$.nullDefaults.readinessBlockers',
          'readinessRisk.$': '$.nullDefaults.readinessRisk',
          'readinessAssessmentLink.$': '$.nullDefaults.readinessAssessmentLink',
        },
      });
      mergeGatesResultState.next(notifyState);

      // Wire every incident-gate sub-graph terminal into MergeGatesResult.
      mergeOutcomeState.next(mergeGatesResultState);
      skipInvestigationState.next(mergeGatesResultState);
      investigationFailedPass.next(mergeGatesResultState);

      resolveAgentSpaceState.next(
        new sfn.Pass(this, 'MergeAgentSpaceEntry', {
          parameters: {
            'eventArn.$': '$.eventArn',
            'event.$': '$.event',
            'accountContexts.$': '$.accountContexts',
            'classification.$': '$.classification',
            'urgency.$': '$.urgency',
            'deadline.$': '$.deadline',
            'reason.$': '$.reason',
            'disposition.$': '$.disposition',
            'precheck.$': '$.precheck',
            'precheckResult.$': '$.precheckResult',
            'impactSummary.$': '$.impactSummary',
            'costProjection.$': '$.costProjection',
            'agentSpaceEntry.$': '$.resolveResult.agentSpaceEntry',
            'nullDefaults.$': '$.nullDefaults',
          },
        }).next(decideInvestigationState),
      );

      postDispositionState = resolveAgentSpaceState;

      // -----------------------------------------------------------------
      // Phase A (working spec feat-devops-agent-enrichment, design §3.0,
      // §3.2, §3.8; task 11): the enrichment path for deadline-class
      // events (BREAKING_CHANGE, SECURITY_RELATED, COST_IMPLICATION).
      // Entered from RequiresInventory below instead of the deleted-later
      // Inventory/ProjectCost chain, when enrichmentViaDevOpsAgent is
      // true. Reuses this same devOpsAgentFunction and the identical
      // DECIDE_INVESTIGATION/TRIGGER_INVESTIGATION steps the incident
      // gate above already calls — kind="enrichment" is the only thing
      // that changes their behaviour (task 3/6, already committed).
      //
      // Design §3.0's dedupe/cap rule is explicitly PER SPACE ("gate.py
      // iterates the distinct spaces and dedupe.py's (agentSpaceId,
      // eventArn) key yields one investigation per space" — point 2 of
      // "How multi-space results reach one ticket"). decide_investigation()
      // itself (gate.py) only ever takes ONE registry_entry and checks
      // dedupe/cap against ONE agentSpaceId — it cannot be called once
      // for a combined multi-space decision. So DECIDE_INVESTIGATION runs
      // INSIDE the Map, once per branch/space, not once before it — only
      // RESOLVE_AGENT_SPACES (the registry lookup itself) runs once,
      // outside the Map, since resolving which spaces cover which
      // accounts is a single deterministic lookup shared by every branch.
      // -----------------------------------------------------------------
      const resolveAgentSpacesState = new tasks.LambdaInvoke(this, 'ResolveAgentSpaces', {
        lambdaFunction: devOpsAgentFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'RESOLVE_AGENT_SPACES',
          'event.$': '$.event',
          'accountContexts.$': '$.accountContexts',
        }),
        resultSelector: {
          'agentSpaceGroups.$': '$.Payload.agentSpaceGroups',
        },
        resultPath: '$.resolveSpacesResult',
      });
      // Gated on enrichmentViaDevOpsAgentActive — same
      // Catch-target-alone-binds-the-state mechanism documented in full
      // on the OLD Inventory/ProjectCost chain's own gated addCatch calls
      // (well below in file order). Without this gate,
      // ResolveAgentSpaces showed up as MISSING_TRANSITION_TARGET in the
      // enrichmentViaDevOpsAgentActive===false variant, confirmed via
      // a local ASL-reachability check script against a real synthesized
      // template.
      if (enrichmentViaDevOpsAgentActive) {
        resolveAgentSpacesState.addCatch(auditOnError, { resultPath: '$.Cause', errors: ['States.ALL'] });
      }

      // ---- Per-branch iterator body (design §3.0 point 2: the Catch
      // MUST live here, inside the iterator, never on the outer Map —
      // one bad space must never fail the good ones). ----
      //
      // Iterator entry: seeds a null-preserving source for the three
      // fields (analysisMarkdown/readiness/taskId) every "no real
      // investigation happened for this branch" Pass below needs to set
      // to null — a literal 'field': null in ANY of those Pass states'
      // own parameters would be silently dropped by sfn.Pass's renderer
      // (the exact FieldUtils.renderObject bug documented on
      // SeedNullDefaults, far above in this file). Scoped to just this
      // iterator (via `result`, which bypasses the broken renderer,
      // exactly like SeedNullDefaults itself) rather than reusing the
      // outer nullDefaults object, since these three fields have no
      // equivalent slot there and are only ever needed inside this Map's
      // iterator body. Runs first, before DecideInvestigationForSpace,
      // so every downstream Pass in this iterator (including
      // MarkSpaceUnverifiable, decided_investigation's own Catch target)
      // can rely on $.branchNullDefaults already being present.
      const seedEnrichmentBranchNullDefaults = new sfn.Pass(this, 'SeedEnrichmentBranchNullDefaults', {
        resultPath: '$.branchNullDefaults',
        result: sfn.Result.fromObject({
          analysisMarkdown: null,
          readiness: null,
          taskId: null,
        }),
      });

      const decideInvestigationForSpaceState = new tasks.LambdaInvoke(this, 'DecideInvestigationForSpace', {
        lambdaFunction: devOpsAgentFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'DECIDE_INVESTIGATION',
          'kind': 'enrichment',
          'event.$': '$.event',
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'impactSummary.$': '$.impactSummary',
        }),
        resultSelector: {
          'investigationDecision.$': '$.Payload.investigationDecision',
          'askReadiness.$': '$.Payload.askReadiness',
          'readinessAccounts.$': '$.Payload.readinessAccounts',
        },
        resultPath: '$.decisionResult',
      });
      // A decision-step failure for ONE space must not fail the whole Map
      // (a sibling space's decision/investigation must still complete) —
      // caught to the same MarkSpaceUnverifiable Pass a triggered
      // investigation's own failure uses below, not to auditOnError
      // (which would fail the entire execution, taking every other
      // branch's in-flight investigation down with it).
      const markSpaceUnverifiablePass = new sfn.Pass(this, 'MarkSpaceUnverifiable', {
        parameters: {
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'accounts.$': '$.accounts',
          'analysisMarkdown.$': '$.branchNullDefaults.analysisMarkdown',
          'impact': 'unverifiable',
          'readiness.$': '$.branchNullDefaults.readiness',
          'taskId.$': '$.branchNullDefaults.taskId',
        },
      });
      decideInvestigationForSpaceState.addCatch(markSpaceUnverifiablePass, {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });
      seedEnrichmentBranchNullDefaults.next(decideInvestigationForSpaceState);

      const triggerInvestigationForSpaceState = new tasks.LambdaInvoke(this, 'TriggerInvestigationForSpace', {
        lambdaFunction: devOpsAgentFunction,
        integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
        payload: sfn.TaskInput.fromObject({
          'step': 'TRIGGER_INVESTIGATION',
          'TaskToken': sfn.JsonPath.taskToken,
          'kind': 'enrichment',
          'event.$': '$.event',
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'impactLocus.$': '$.impactLocus',
          's3SnapshotKey.$': '$.event.snapshotKey',
        }),
        // The callback's real output shape (verified directly against
        // callback_handler.py's kind == "enrichment" branch — see this
        // stack's own TriggerInvestigation state above for why field
        // names are read from real code, not guessed):
        // {analysisMarkdown, impact, readiness: {feasibility, blockers,
        //  risk, rollback_available}, taskId, agentSpaceId}.
        resultSelector: {
          'analysisMarkdown.$': '$.analysisMarkdown',
          'impact.$': '$.impact',
          'readiness.$': '$.readiness',
          'taskId.$': '$.taskId',
        },
        // NOT DISCARD — an earlier draft discarded this state's own
        // successful result entirely, which would have made
        // 'analysisMarkdown'/'impact'/'readiness'/'taskId' undefined
        // JSONPath references for every SUCCESSFULLY-triggered branch (the
        // itemSelector input this state started from carries none of
        // those keys). resultPath here merges this selector's output
        // non-destructively onto the branch's existing
        // agentSpaceEntry/accounts, matching the shape
        // MergeEnrichmentForSpaceOutput below expects from every branch
        // (triggered or skipped/failed) uniformly.
        resultPath: '$.investigationResult',
        taskTimeout: sfn.Timeout.duration(cdk.Duration.minutes(55)),
      });
      const mergeTriggerResultForSpacePass = new sfn.Pass(this, 'MergeTriggerResultForSpace', {
        parameters: {
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'accounts.$': '$.accounts',
          'analysisMarkdown.$': '$.investigationResult.analysisMarkdown',
          'impact.$': '$.investigationResult.impact',
          'readiness.$': '$.investigationResult.readiness',
          'taskId.$': '$.investigationResult.taskId',
        },
      });
      triggerInvestigationForSpaceState.next(mergeTriggerResultForSpacePass);
      // Per-branch Catch — design §3.0 point 2. A malformed/timed-out
      // investigation for space B must leave space A's already-resolved
      // branch output untouched; this Catch is on the ITERATOR's own
      // task state, never on the outer resolveAgentSpacesMapState below.
      const markInvestigationUnverifiableForSpacePass = new sfn.Pass(this, 'MarkInvestigationUnverifiableForSpace', {
        parameters: {
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'accounts.$': '$.accounts',
          'analysisMarkdown.$': '$.branchNullDefaults.analysisMarkdown',
          'impact': 'unverifiable',
          'readiness.$': '$.branchNullDefaults.readiness',
          'taskId.$': '$.branchNullDefaults.taskId',
        },
      });
      triggerInvestigationForSpaceState.addCatch(markInvestigationUnverifiableForSpacePass, {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });

      const skipInvestigationForSpacePass = new sfn.Pass(this, 'SkipInvestigationForSpace', {
        parameters: {
          'agentSpaceEntry.$': '$.agentSpaceEntry',
          'accounts.$': '$.accounts',
          'analysisMarkdown.$': '$.branchNullDefaults.analysisMarkdown',
          // Not investigated (no_registry / not_eligible / duplicate /
          // cap_exceeded, gate.py's skip_kind): impact stays whatever the
          // entity-list baseline already set for these accounts — design
          // §3.1 step 3's "no Agent Space covers account <id>" case is
          // exactly this branch when agentSpaceEntry is None.
          'impact.$': '$.impactSummary.impact_status',
          'readiness.$': '$.branchNullDefaults.readiness',
          'taskId.$': '$.branchNullDefaults.taskId',
        },
      });

      decideInvestigationForSpaceState.next(
        new sfn.Choice(this, 'ShouldTriggerInvestigationForSpace')
          .when(
            sfn.Condition.booleanEquals('$.decisionResult.investigationDecision.trigger', true),
            triggerInvestigationForSpaceState,
          )
          .otherwise(skipInvestigationForSpacePass),
      );

      // itemSelector builds each iteration's input from the outer state
      // (carrying event/classification/impactLocus etc. — every field
      // the branch's own LambdaInvoke payloads above read via '$.xxx')
      // PLUS the current array element's own agentSpaceEntry/accounts
      // (Map's default per-item binding, '$$.Map.Item.Value'). Per-item
      // '.$' references here follow the identical FieldUtils.renderObject
      // null-dropping rule documented on SeedNullDefaults above — none of
      // these fields are ever a literal null, so that trap does not apply
      // to this itemSelector.
      // Construct ID 'EnrichmentInvestigations', NOT 'TriggerInvestigation'
      // — the incident gate's own TriggerInvestigation LambdaInvoke
      // (defined earlier in this same construct scope, `this`) already
      // owns that ID. A real `cdk synth -c enableDevOpsAgentGate=true`
      // confirmed the collision as a hard, deploy-blocking
      // "There is already a Construct with name 'TriggerInvestigation'"
      // error — CDK construct IDs are just strings; tsc --noEmit cannot
      // catch this, only a real synth does.
      const enrichmentMapState = new sfn.Map(this, 'EnrichmentInvestigations', {
        itemsPath: '$.resolveSpacesResult.agentSpaceGroups',
        itemSelector: {
          'agentSpaceEntry.$': '$$.Map.Item.Value.agentSpaceEntry',
          'accounts.$': '$$.Map.Item.Value.accounts',
          'event.$': '$.event',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'impactLocus.$': '$.impactLocus',
          'impactSummary.$': '$.impactSummary',
        },
        resultPath: '$.enrichmentBranchResults',
      });
      enrichmentMapState.itemProcessor(seedEnrichmentBranchNullDefaults);
      // NOTE: no .addCatch() on enrichmentMapState itself — design §3.0
      // point 2 is deliberate: every failure mode inside the iterator
      // (decision-step error, trigger-step error/timeout) already has
      // its OWN per-branch Catch above, so a bad branch degrades to
      // {impact: "unverifiable", ...} for just that space and the Map as
      // a whole always completes successfully once every branch — good
      // or degraded — has resolved. A Catch here would instead fail
      // every space's already-good results because one space errored.

      // ---- After the Map completes: fold every branch's markdown into
      // one inventory (design §3.0's "MergeEnrichment parses every
      // branch's output into one inventory keyed per account"). One
      // MERGE_ENRICHMENT call per branch result, using the SAME Lambda
      // step task 2 already built — that step's own per-callback parsing
      // is unchanged; this second, OUTER Map only fans it out over N
      // branch outputs instead of the single callback the non-multi-
      // space case has. Its resultPath ('$.mergedEnrichmentResults') is
      // a real array of every branch's folded result, so
      // MergeAllEnrichmentResults below can read it.
      // -----------------------------------------------------------------
      const mergeEnrichmentForSpaceState = new tasks.LambdaInvoke(this, 'MergeEnrichmentForSpace', {
        lambdaFunction: inventoryFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'MERGE_ENRICHMENT',
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'analysisMarkdown.$': '$.analysisMarkdown',
          'deadline.$': '$.deadline',
        }),
        // ResultSelector can only select from THIS TASK'S OWN RAW RESULT
        // ('$.Payload.xxx' for a synchronous LambdaInvoke) — never from the
        // state's input, confirmed against AWS's own ResultSelector docs
        // ("values are static or selected from the state's result").
        // 'accounts'/'impact' (this branch's own identifying fields, set
        // by the outer enrichment Map's itemSelector, never touched by
        // this Lambda) are therefore NOT put here — an earlier draft tried
        // '$.accounts'/'$.impact' directly in this resultSelector, which
        // would have been a hard States.Runtime failure (no such key
        // exists anywhere in the Lambda's raw response). resultPath
        // below merges this selector's output back onto the ORIGINAL
        // input non-destructively, so the next Pass state can still read
        // 'accounts'/'impact' from the (untouched) top level.
        resultSelector: {
          'impactSummary.$': '$.Payload.impactSummary',
          'costProjection.$': '$.Payload.costProjection',
          'readinessFeasibility.$': '$.Payload.readinessFeasibility',
          'readinessBlockers.$': '$.Payload.readinessBlockers',
          'readinessRisk.$': '$.Payload.readinessRisk',
          'readinessRollbackAvailable.$': '$.Payload.readinessRollbackAvailable',
        },
        resultPath: '$.mergeResult',
      });
      // buildAuditOnError('MergeEnrichmentForSpace'), NOT the shared
      // auditOnError — this state is the START STATE OF A NESTED
      // StateGraph (mergeAllEnrichmentMapState's itemProcessor below), and
      // the file's own established rule (see buildAuditOnError's
      // docstring, far above) is that every state inside a Parallel
      // branch — and, confirmed here, a Map's itemProcessor, which builds
      // a StateGraph the identical way — needs ITS OWN dedicated
      // EnrichError/AuditOnError chain. A real `cdk synth -c
      // enableDevOpsAgentGate=true` confirmed reusing the shared
      // auditOnError here is a hard, deploy-blocking
      // "RangeError: Maximum call stack size exceeded" in CDK's own
      // StateGraph.registerContainedState — an infinite recursion from
      // one graph's superGraph pointer chain looping back on itself,
      // not caught by tsc --noEmit or by inspecting the TypeScript alone.
      mergeEnrichmentForSpaceState.addCatch(buildAuditOnError('MergeEnrichmentForSpace'), {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });

      // Folds 'accounts'/'impact' (untouched by resultPath above, still
      // present at the top level of this iteration's own input) together
      // with mergeResult's fields into the flat shape this Map's own
      // itemProcessor output becomes — i.e. one element of
      // $.mergedEnrichmentResults on the outer state, per design §3.0's
      // "MergeEnrichment parses every branch's output into one inventory
      // keyed per account."
      const mergeEnrichmentForSpaceOutputPass = new sfn.Pass(this, 'MergeEnrichmentForSpaceOutput', {
        parameters: {
          'accounts.$': '$.accounts',
          'impact.$': '$.impact',
          'impactSummary.$': '$.mergeResult.impactSummary',
          'costProjection.$': '$.mergeResult.costProjection',
          'readinessFeasibility.$': '$.mergeResult.readinessFeasibility',
          'readinessBlockers.$': '$.mergeResult.readinessBlockers',
          'readinessRisk.$': '$.mergeResult.readinessRisk',
          'readinessRollbackAvailable.$': '$.mergeResult.readinessRollbackAvailable',
        },
      });
      mergeEnrichmentForSpaceState.next(mergeEnrichmentForSpaceOutputPass);

      // itemSelector here carries EACH enrichment-Map branch result
      // ($.enrichmentBranchResults, an array) as this second Map's own
      // items — MergeEnrichmentForSpace parses one branch's markdown at
      // a time, so a malformed table from space B never corrupts space
      // A's already-parsed inventory (the same per-branch-isolation
      // property the outer enrichment Map guarantees, carried through
      // this fold step too).
      const mergeAllEnrichmentMapState = new sfn.Map(this, 'MergeEnrichment', {
        itemsPath: '$.enrichmentBranchResults',
        itemSelector: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'deadline.$': '$.deadline',
          'accounts.$': '$$.Map.Item.Value.accounts',
          'impact.$': '$$.Map.Item.Value.impact',
          'analysisMarkdown.$': '$$.Map.Item.Value.analysisMarkdown',
        },
        resultPath: '$.mergedEnrichmentResults',
      });
      mergeAllEnrichmentMapState.itemProcessor(mergeEnrichmentForSpaceState);

      const mergeAllEnrichmentResultsPass = new sfn.Pass(this, 'MergeAllEnrichmentResults', {
        parameters: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'accountContexts.$': '$.accountContexts',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.disposition',
          'precheck.$': '$.precheck',
          'precheckResult.$': '$.precheckResult',
          // Every branch runs MERGE_ENRICHMENT against the SAME
          // event-level entity list (build_impact_inventory reads
          // event.affectedEntities, not a per-account slice — design §3.1
          // step 1), so any branch's impactSummary/costProjection already
          // reflects the union of accounts this event covers. Taking the
          // FIRST branch's result is therefore not a data loss: a second
          // distinct space only ever contributes distinct rows on the
          // SAME account it's not scoped to accessing, which surfaces as
          // that account's own 'inaccessible' status inside the shared
          // inventory the enrichment agent that DID have access already
          // built — multi-space fan-out changes which accounts get a
          // successful investigation, not how many independent
          // inventories exist (there is always exactly one).
          'impactSummary.$': '$.mergedEnrichmentResults[0].impactSummary',
          'costProjection.$': '$.mergedEnrichmentResults[0].costProjection',
          'readinessFeasibility.$': '$.mergedEnrichmentResults[0].readinessFeasibility',
          'readinessBlockers.$': '$.mergedEnrichmentResults[0].readinessBlockers',
          'readinessRisk.$': '$.mergedEnrichmentResults[0].readinessRisk',
          // Literal nulls here would be silently dropped by sfn.Pass's
          // parameters renderer (see SeedNullDefaults's docstring) —
          // this path has no assessment-link/investigation-link concept
          // of its own (MERGE_ENRICHMENT never produces one; only the
          // incident gate's SummarizeOutcome/SummarizeReadiness states
          // build one from agentSpaceId+taskId), so both are sourced from
          // the already-null-preserving nullDefaults object instead.
          'readinessAssessmentLink.$': '$.nullDefaults.readinessAssessmentLink',
          'impact.$': '$.mergedEnrichmentResults[0].impact',
          'investigationLink.$': '$.nullDefaults.investigationLink',
          'nullDefaults.$': '$.nullDefaults',
        },
      });

      // This whole chain's states are ALWAYS constructed above (so the
      // enrichment path exists as a fully-formed set of TypeScript
      // objects regardless of the flag), but every one of these edges —
      // the ones that actually connect the chain to notifyState, the
      // shared downstream join — is only wired when
      // enrichmentViaDevOpsAgentActive is true. Without ANY of these
      // edges, CDK's State.bindToGraph() propagation never reaches this
      // chain at all when it's the inactive path, so its states are
      // correctly excluded from the synthesized ASL entirely rather than
      // becoming a real, deploy-blocking MISSING_TRANSITION_TARGET error
      // — the same fix this file's SeedNullReadinessFields/preNotifyPass
      // docstring already documents for a single-state case, applied
      // here to a whole multi-state chain. Confirmed by writing and
      // running a local ASL-reachability check script against all three
      // real enableDevOpsAgentGate x enrichmentViaDevOpsAgent
      // combinations BEFORE this fix existed, which is exactly how this
      // bug was found (cdk synth/tsc --noEmit both stayed clean the
      // whole time).
      if (enrichmentViaDevOpsAgentActive) {
        enrichmentMapState.next(mergeAllEnrichmentMapState);
        mergeAllEnrichmentMapState.next(mergeAllEnrichmentResultsPass);
        // Straight to Notify, NOT through preNotifyPass: that Pass
        // exists only to null-default the incident/readiness-gate
        // fields when the gate is disabled entirely
        // (props.enableDevOpsAgentGate === false) — it would overwrite
        // this branch's real impact/readiness values with nulls if
        // reused here. mergeAllEnrichmentResultsPass already sets every
        // field notifyState's own payload reads.
        mergeAllEnrichmentResultsPass.next(notifyState);
        resolveAgentSpacesState.next(enrichmentMapState);
        enrichmentEntryState = resolveAgentSpacesState;
      }
    } else {
      // seedNullReadinessFields.next(preNotifyPass) is only called here,
      // not unconditionally at declaration time above: when
      // devOpsAgentFunction IS supplied, postDispositionState is
      // resolveAgentSpaceState instead, and nothing ever transitions into
      // seedNullReadinessFields — but CDK's StateGraph still registers any
      // state a `.next()` was called on, regardless of whether something
      // transitions INTO it. A real `cdk deploy -c
      // enableDevOpsAgentGate=true` confirmed this is a hard, deploy-
      // blocking Step Functions API validation error (not caught by
      // `cdk synth`/`tsc --noEmit`, which don't check ASL graph
      // reachability): "Invalid State Machine Definition:
      // MISSING_TRANSITION_TARGET: State 'SeedNullReadinessFields' is not
      // reachable." Calling `.next()` only in the branch that actually
      // uses it keeps it out of the graph entirely when unused. Same
      // reasoning applies to preNotifyPass itself, one level up: when
      // devOpsAgentFunction IS supplied, MergeGatesResult transitions
      // directly to notifyState (it already sets every field
      // preNotifyPass would otherwise null-default), so preNotifyPass
      // would be a second orphaned state if `.next(notifyState)` were
      // called on it unconditionally at declaration time — a second real
      // MISSING_TRANSITION_TARGET this fix's first pass exposed (masked
      // by SeedNullReadinessFields's identical error until that one was
      // fixed), caught this time by a local ASL-reachability check script
      // (mirroring the Step Functions API's own graph-reachability
      // validation — cdk synth/tsc --noEmit do not check this) instead of
      // a second real failed deploy.
      preNotifyPass.next(notifyState);
      seedNullReadinessFields.next(preNotifyPass);
      postDispositionState = seedNullReadinessFields;
    }

    // -----------------------------------------------------------------------
    // Phase 3: ProjectCost — pure precision Lambda (only for classes that
    // carry cost implications)
    // -----------------------------------------------------------------------
    const projectCostState = new tasks.LambdaInvoke(this, 'ProjectCost', {
      lambdaFunction: inventoryFunction,
      payload: sfn.TaskInput.fromObject({
        'step': 'PROJECT_COST',
        'eventArn.$': '$.eventArn',
        'inventory.$': '$.impactSummary',
        'deadline.$': '$.deadline',
      }),
      resultSelector: {
        'costProjection.$': '$.Payload.costProjection',
      },
      resultPath: '$.projectCostResult',
    });
    // Gated on !enrichmentViaDevOpsAgentActive for the same reason
    // inventoryState's own addCatch(auditOnError, ...) is, a few lines
    // below in file order (constructed before this in the source, but
    // that block explains the mechanism in full) — a Catch target alone
    // is enough for CDK's State.bindToGraph() to pull a state into the
    // live graph, regardless of whether anything forward-transitions to
    // it. This exact edge produced the MISSING_TRANSITION_TARGET this
    // session's ASL-reachability check found for 'ProjectCost' in the
    // enrichmentViaDevOpsAgentActive===true variant, before this fix.
    if (!enrichmentViaDevOpsAgentActive) {
      projectCostState.addCatch(auditOnError, {
        resultPath: '$.Cause',
        errors: ['States.ALL'],
      });
    }
    const mergeCostProjectionState = new sfn.Pass(this, 'MergeCostProjection', {
      parameters: {
        'eventArn.$': '$.eventArn',
        'event.$': '$.event',
        'accountContexts.$': '$.accountContexts',
        'classification.$': '$.classification',
        'urgency.$': '$.urgency',
        'deadline.$': '$.deadline',
        'reason.$': '$.reason',
        'disposition.$': '$.disposition',
        'precheck.$': '$.precheck',
        'precheckResult.$': '$.precheckResult',
        'impactSummary.$': '$.impactSummary',
        'costProjection.$': '$.projectCostResult.costProjection',
        'nullDefaults.$': '$.nullDefaults',
      },
    });
    // Phase A (task 11): this Inventory/ProjectCost chain's states are
    // ALWAYS constructed (needed for the enrichmentViaDevOpsAgentActive
    // === false rollback path), but this FINAL edge into
    // postDispositionState — the shared downstream join both this chain
    // and the new enrichment chain feed into — is only ever called when
    // this chain is actually the active path for this deploy. Without
    // this edge, CDK's State.bindToGraph() propagation (which walks BOTH
    // incoming and outgoing transitions from whatever IS bound, per its
    // own source — see this file's SeedNullReadinessFields/preNotifyPass
    // docstring above for the identical, previously-discovered class of
    // bug) never reaches this chain's states at all when it's the
    // inactive one, so they are correctly excluded from the synthesized
    // ASL entirely rather than showing up as a real, deploy-blocking
    // MISSING_TRANSITION_TARGET error — confirmed by writing and running
    // a local ASL-reachability check script against all three real
    // enableDevOpsAgentGate x enrichmentViaDevOpsAgent combinations
    // BEFORE this specific fix existed, which is exactly how this bug
    // was found (not by cdk synth/tsc --noEmit, which both stayed clean
    // the whole time). enrichmentViaDevOpsAgentActive is computed ABOVE
    // this point in the file (right after enrichmentEntryState is
    // known) specifically so this decision is available this early —
    // deadlineClassEntryState itself is declared later and cannot be
    // referenced yet.
    if (!enrichmentViaDevOpsAgentActive) {
      projectCostState.next(mergeCostProjectionState);
      mergeCostProjectionState.next(postDispositionState);
    }

    // -----------------------------------------------------------------------
    // Phase B (feat-devops-agent-enrichment, design §3.7/§3.8): the OLD
    // Inventory state (INVENTORY step: AssumeRole + per-service plug-ins)
    // and its MergeInventory Pass were retired. Deadline-class events now
    // ALWAYS enter through InventoryBaseline (the lightweight, no-AWS-call
    // "build baseline" step, design §3.8): when the enrichment path is
    // active it flows on to the DevOps Agent gate; when it is not (the
    // enrichmentViaDevOpsAgent=false rollback lever, or the gate module
    // disabled), the same baseline feeds ProjectCost directly — see the
    // deadlineClassEntryState / mergeBaselinePass wiring below.
    // -----------------------------------------------------------------------

    // Skip path: classes that never get inventory/cost (SERVICE_DISRUPTION,
    // INFORMATIONAL, UNCLASSIFIED) go straight to the DevOps Agent gate (or
    // Notify directly when that module is disabled) with null fields.
    const skipInventoryState = new sfn.Pass(this, 'SkipInventoryAndCost', {
      parameters: {
        'eventArn.$': '$.eventArn',
        'event.$': '$.event',
        'accountContexts.$': '$.accountContexts',
        'classification.$': '$.classification',
        'urgency.$': '$.urgency',
        'deadline.$': '$.deadline',
        'reason.$': '$.reason',
        'disposition.$': '$.disposition',
        'precheck.$': '$.precheck',
        'precheckResult.$': '$.precheckResult',
        'impactSummary.$': '$.nullDefaults.impactSummary',
        'costProjection.$': '$.nullDefaults.costProjection',
        'nullDefaults.$': '$.nullDefaults',
      },
    }).next(postDispositionState);

    // -----------------------------------------------------------------------
    // Phase A (working spec feat-devops-agent-enrichment, design §3.1 steps
    // 1-3 / §3.8, task 11): INVENTORY_BASELINE computes impactSummary (from
    // the entity list + impact locus, no AWS call) and impactLocus for
    // deadline-class events, BEFORE deciding whether that event goes into
    // the new enrichment path or the old Inventory/ProjectCost chain — both
    // branches below need impactSummary; only the enrichment branch also
    // needs impactLocus (for the webhook's [HEALTH_TRIAGE:...] tag).
    // Skipped entirely for non-deadline classes (skipInventoryState below),
    // matching R8/R9's existing scope — this baseline is deliberately not
    // computed for every event, only the ones RequiresInventory already
    // decided need SOME impact answer.
    // -----------------------------------------------------------------------
    const inventoryBaselineState = new tasks.LambdaInvoke(this, 'InventoryBaseline', {
      lambdaFunction: inventoryFunction,
      payload: sfn.TaskInput.fromObject({
        'step': 'INVENTORY_BASELINE',
        'eventArn.$': '$.eventArn',
        'event.$': '$.event',
      }),
      resultSelector: {
        'impactSummary.$': '$.Payload.impactSummary',
        'impactLocus.$': '$.Payload.impactLocus',
      },
      resultPath: '$.baselineResult',
    });
    // Gated on enrichmentViaDevOpsAgentActive, NOT called unconditionally
    // — an earlier draft called this (and inventoryBaselineState.next()
    // below) unconditionally, which left InventoryBaseline/
    // MergeInventoryBaseline showing up as MISSING_TRANSITION_TARGET in
    // the enrichmentViaDevOpsAgentActive===false variants even though
    // RequiresInventory never forward-transitions to InventoryBaseline in
    // those variants: addCatch(auditOnError, ...) alone is enough to pull
    // a state into the live graph, because auditOnError/EnrichError IS
    // always part of the live graph (used by dozens of other states) and
    // CDK's State.bindToGraph() propagates via BOTH incoming AND outgoing
    // edges — a Catch target is an incoming edge from InventoryBaseline's
    // perspective, walked the same as a forward Next. Confirmed via
    // a local ASL-reachability check script against a real synthesized
    // template's own Catch/Next wiring, not assumed.
    // Phase B: InventoryBaseline is now the single entry state for every
    // deadline-class event (both enrichment-active and the rollback path),
    // so its Catch is unconditional.
    inventoryBaselineState.addCatch(auditOnError, { resultPath: '$.Cause', errors: ['States.ALL'] });

    const mergeBaselinePass = new sfn.Pass(this, 'MergeInventoryBaseline', {
      parameters: {
        'eventArn.$': '$.eventArn',
        'event.$': '$.event',
        'accountContexts.$': '$.accountContexts',
        'classification.$': '$.classification',
        'urgency.$': '$.urgency',
        'deadline.$': '$.deadline',
        'reason.$': '$.reason',
        'disposition.$': '$.disposition',
        'precheck.$': '$.precheck',
        'precheckResult.$': '$.precheckResult',
        'impactSummary.$': '$.baselineResult.impactSummary',
        'impactLocus.$': '$.baselineResult.impactLocus',
        'nullDefaults.$': '$.nullDefaults',
      },
    });
    inventoryBaselineState.next(mergeBaselinePass);

    // enrichmentViaDevOpsAgent default true (design §7: Stage 1 IS the
    // intended architecture, not an opt-in) — only takes effect when
    // devOpsAgentFunction/enrichmentEntryState actually exist
    // (enableDevOpsAgentGate=true). This is a BUILD-TIME CDK context
    // decision (which state RequiresInventory's deadline-class branch
    // points to below), not a per-event runtime Choice — every deployed
    // stack has exactly one path wired for deadline-class events, decided
    // at synth time, matching design §7's "feature flag" framing (a
    // rollback lever an operator flips and redeploys, not a live A/B
    // branch).
    //
    // deadlineClassEntryState picks the whole ENTRY CHAIN, not just
    // whether InventoryBaseline runs — mergeBaselinePass only ever exists
    // on the path INTO InventoryBaseline, so it only needs wiring
    // (mergeBaselinePass.next below) when that path is actually chosen.
    // The fallback path (flag off, or gate disabled) routes straight to
    // the existing inventoryState exactly as it did before this task —
    // inventoryState's own INVENTORY step already calls
    // build_impact_inventory() itself (with real lookups this time), so
    // running InventoryBaseline ahead of it there would only recompute
    // the same entity+locus baseline a second time for no benefit, only
    // to have inventoryState's own MergeInventory Pass immediately
    // overwrite it.
    // Reuses enrichmentViaDevOpsAgentActive (computed above, right after
    // enrichmentEntryState itself is known) rather than re-deriving
    // `props.enrichmentViaDevOpsAgent ?? true` a second time here — a
    // second independent derivation of the identical condition is
    // exactly the kind of thing that silently drifts apart from its
    // first derivation during a future edit; one source of truth for
    // "is the enrichment path active" is used at every call site that
    // needs to know it.
    const deadlineClassEntryState: sfn.IChainable = inventoryBaselineState;
    if (enrichmentViaDevOpsAgentActive && enrichmentEntryState) {
      mergeBaselinePass.next(enrichmentEntryState);
    } else {
      // Rollback / gate-disabled path: the baseline impactSummary feeds
      // ProjectCost directly (no DevOps Agent enrichment). ProjectCost's own
      // addCatch + .next(mergeCostProjectionState -> postDispositionState)
      // is wired under the same !enrichmentViaDevOpsAgentActive guard above.
      mergeBaselinePass.next(projectCostState);
    }

    // Choice: only run Inventory/ProjectCost for classes where R8/R9 apply
    const inventoryChoice = new sfn.Choice(this, 'RequiresInventory')
      .when(
        sfn.Condition.or(
          sfn.Condition.stringEquals('$.classification', 'BREAKING_CHANGE'),
          sfn.Condition.stringEquals('$.classification', 'SECURITY_RELATED'),
          sfn.Condition.stringEquals('$.classification', 'COST_IMPLICATION'),
        ),
        deadlineClassEntryState,
      )
      .otherwise(skipInventoryState);

    // -----------------------------------------------------------------------
    // Phase B (feat-devops-agent-enrichment, design §3.7/§3.8): the
    // maintenance-class prechecks and the PRECHECK Lambda step were retired,
    // so RunPrechecks / MergePrecheckOutcome / SkipPrecheck and the
    // HasBoundPrecheck Choice are gone. DecideDisposition now routes straight
    // to RequiresInventory. Downstream states still read $.precheckResult, so
    // MergeDisposition seeds it null from nullDefaults (the field stays on the
    // notification payload for schema compatibility, just always null now —
    // the design's future `at_risk`/escalate_on_precheck_failure reuse is out
    // of this scope). enrichPath = the RequiresInventory Choice below.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // DecideDisposition — pure precision; handled inline in classifier Lambda
    // but exposed as a named state for visibility in execution history
    // -----------------------------------------------------------------------
    const decideDispositionState = new tasks.LambdaInvoke(
      this,
      'DecideDisposition',
      {
        lambdaFunction: workerFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'DECIDE_DISPOSITION',
          'eventArn.$': '$.eventArn',
          'classification.$': '$.classification',
          'eventTypeCode.$': '$.eventTypeCode',
        }),
        resultSelector: {
          'disposition.$': '$.Payload.disposition',
          'precheck.$': '$.Payload.precheck',
          'rule.$': '$.Payload.rule',
        },
        resultPath: '$.dispositionResult',
      },
    );
    decideDispositionState.addCatch(auditOnError, {
      resultPath: '$.Cause',
      errors: ['States.ALL'],
    });
    // Merge disposition into top-level then branch on whether a precheck is bound
    decideDispositionState.next(
      new sfn.Pass(this, 'MergeDisposition', {
        parameters: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'account.$': '$.account',
          'accountContexts.$': '$.accountContexts',
          'classification.$': '$.classification',
          'urgency.$': '$.urgency',
          'deadline.$': '$.deadline',
          'reason.$': '$.reason',
          'disposition.$': '$.dispositionResult.disposition',
          'precheck.$': '$.dispositionResult.precheck',
          // Phase B: no RunPrechecks step runs anymore, so seed a null
          // precheckResult here (from nullDefaults, null-preserving) for the
          // downstream states that still forward $.precheckResult.
          'precheckResult.$': '$.nullDefaults.precheckResult',
          'nullDefaults.$': '$.nullDefaults',
        },
      }).next(inventoryChoice),
    );

    // -----------------------------------------------------------------------
    // ComputeUrgency — pure precision Lambda
    // -----------------------------------------------------------------------
    const computeUrgencyState = new tasks.LambdaInvoke(
      this,
      'ComputeUrgency',
      {
        lambdaFunction: workerFunction,
        payload: sfn.TaskInput.fromObject({
          'step': 'COMPUTE_URGENCY',
          'eventArn.$': '$.eventArn',
          'classification.$': '$.classifyResult.classification',
          'deadline.$': '$.classifyResult.deadline',
        }),
        resultSelector: {
          'urgency.$': '$.Payload.urgency',
        },
        resultPath: '$.urgencyResult',
      },
    );
    computeUrgencyState.addCatch(auditOnError, {
      resultPath: '$.Cause',
      errors: ['States.ALL'],
    });
    computeUrgencyState.next(
      new sfn.Pass(this, 'MergeClassifyAndUrgency', {
        parameters: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.event',
          'eventTypeCode.$': '$.event.eventTypeCode',
          'account.$': '$.account',
          'accountContexts.$': '$.accountContexts',
          'classification.$': '$.classifyResult.classification',
          'urgency.$': '$.urgencyResult.urgency',
          'deadline.$': '$.classifyResult.deadline',
          'reason.$': '$.classifyResult.reason',
          'nullDefaults.$': '$.nullDefaults',
        },
      }).next(decideDispositionState),
    );

    // -----------------------------------------------------------------------
    // Classify — Strands on Lambda
    // -----------------------------------------------------------------------
    const classifyState = new tasks.LambdaInvoke(this, 'Classify', {
      // classifierFunction (src/classifier/handler.py), not workerFunction —
      // worker_handler.py has no CLASSIFY step (confirmed via a real
      // States.Runtime failure during Build validation: "Unknown step:
      // CLASSIFY"). classifierFunction is the dedicated Strands-on-Lambda
      // handler with the heavier strands-agents/bedrock-agentcore
      // dependency tree and its own memory/timeout tuning.
      lambdaFunction: classifierFunction,
      payload: sfn.TaskInput.fromObject({
        'eventArn.$': '$.eventArn',
        'event.$': '$.event',
      }),
      resultSelector: {
        'classification.$': '$.Payload.classification',
        'reason.$': '$.Payload.reason',
        'deadline.$': '$.Payload.deadline',
        'deadline_basis.$': '$.Payload.deadline_basis',
        'verification_steps.$': '$.Payload.verification_steps',
        'notes_for_operator.$': '$.Payload.notes_for_operator',
      },
      resultPath: '$.classifyResult',
    });
    // fix-lambda-reserved-concurrency: LambdaInvoke's own default
    // retryOnServiceExceptions (confirmed by reading the installed
    // aws-cdk-lib's compiled invoke.js) only covers
    // Lambda.ClientExecutionTimeoutException/ServiceException/
    // AWSLambdaException/SdkClientException — NOT
    // Lambda.TooManyRequestsException, the exact error a
    // reservedConcurrentExecutions cap makes routine under a large
    // multi-account fan-out (R2.1). Per AWS's own Step Functions error-
    // handling docs, a throttled Lambda invocation reports specifically
    // as Lambda.TooManyRequestsException, which needs its own Retry entry
    // — without this, capping concurrency would trade an unbounded-fanout
    // risk for healthy events falling into AuditOnError just because they
    // had to wait their turn. addRetry() is additive (confirmed via the
    // installed aws-cdk-lib's TaskStateBase types), so this coexists with
    // classifyState's own addCatch(auditOnError, {errors: ['States.ALL']})
    // below — retries are attempted first, and only exhausted retries
    // fall through to the catch.
    classifyState.addRetry({
      errors: ['Lambda.TooManyRequestsException'],
      interval: cdk.Duration.seconds(2),
      maxAttempts: 5,
      backoffRate: 2,
      maxDelay: cdk.Duration.seconds(30),
      jitterStrategy: sfn.JitterType.FULL,
    });
    classifyState.addCatch(auditOnError, {
      resultPath: '$.Cause',
      errors: ['States.ALL'],
    });
    classifyState.next(computeUrgencyState);

    // -----------------------------------------------------------------------
    // seedNullDefaults / PrepareClassifyInput
    //
    // sfn.Pass's `parameters` prop silently drops any key with a literal
    // `null` value (confirmed by reading CDK's FieldUtils.renderObject —
    // its recurseObject() helper treats `value == null` as "omit this
    // key" for both null and undefined; see SeedNullReadinessFields
    // below for where this was first discovered and fixed for the
    // readiness-gate fields). The workflow has several optional fields
    // (impactSummary, costProjection, precheckResult, investigationLink)
    // that different branches need to explicitly set to null — a real
    // deploy + test event walked SkipPrecheck -> SkipInventoryAndCost ->
    // PrepareNotifyInput and hit a hard States.Runtime failure
    // ("The JSONPath '$.impactSummary' ... could not be found") because
    // every one of those literal-null Pass states upstream had silently
    // dropped the key rather than actually setting it to null.
    //
    // Fixed once, here, by seeding all of these to null via `result`
    // (sfn.Result.fromObject bypasses the broken renderer and preserves
    // nulls) at the very start of the workflow. Every downstream Pass
    // that previously wrote a literal `'field': null` now instead writes
    // `'field.$': '$.nullDefaults.field'` — a plain JsonPath reference
    // to an already-null value, which Step Functions resolves correctly
    // since the source path genuinely exists (it's just null), unlike a
    // literal that never made it into the rendered Parameters at all.
    // -----------------------------------------------------------------------
    const seedNullDefaults = new sfn.Pass(this, 'SeedNullDefaults', {
      resultPath: '$.nullDefaults',
      result: sfn.Result.fromObject({
        impactSummary: null,
        costProjection: null,
        precheckResult: null,
        impact: null,
        investigationLink: null,
        // Phase A (task 11): the enrichment path's MergeAllEnrichmentResults
        // needs a null-preserving source for this field too — a literal
        // 'readinessAssessmentLink': null in that Pass's own parameters
        // would be silently dropped by the exact FieldUtils.renderObject
        // bug this whole nullDefaults pattern exists to work around.
        readinessAssessmentLink: null,
        // Phase B (feat-devops-agent-enrichment, design §3.7/§3.8): the
        // incident-gate path no longer runs a readiness branch, but E4.4
        // requires the four readiness* fields stay on NotificationPayload v1
        // (schema-compatible). MergeGatesResult sources them from here as
        // null literals — a bare 'readinessFeasibility': null in its own
        // `parameters` would be silently dropped by the same
        // FieldUtils.renderObject bug. readinessAssessmentLink is already
        // seeded above; these three complete the set.
        readinessFeasibility: null,
        readinessBlockers: null,
        readinessRisk: null,
      }),
    });
    seedNullDefaults.next(
      new sfn.Pass(this, 'PrepareClassifyInput', {
        parameters: {
          'eventArn.$': '$.eventArn',
          'event.$': '$.loadResult.event',
          'nullDefaults.$': '$.nullDefaults',
          // 'account'/'accountContexts' are not yet enriched per-account in
          // this workflow (a future working spec will add per-account
          // fan-out); RunPrechecks and the DevOps Agent gate's
          // resolve_agent_space() both degrade gracefully on an empty
          // account context (RunPrechecks -> 'not_checked';
          // resolve_agent_space -> DEFAULT registry entry or None).
          'account': {},
          'accountContexts': [],
        },
      }).next(classifyState),
    );

    // -----------------------------------------------------------------------
    // LoadEvent — reads the consolidated event from DynamoDB
    // -----------------------------------------------------------------------
    const loadEventState = new tasks.LambdaInvoke(this, 'LoadEvent', {
      lambdaFunction: workerFunction,
      payload: sfn.TaskInput.fromObject({
        'step': 'LOAD_EVENT',
        'eventArn.$': '$.eventArn',
      }),
      resultSelector: {
        'event.$': '$.Payload.event',
      },
      resultPath: '$.loadResult',
    });
    loadEventState.addCatch(auditOnError, {
      resultPath: '$.Cause',
      errors: ['States.ALL'],
    });
    loadEventState.next(seedNullDefaults);

    // -----------------------------------------------------------------------
    // State machine
    // -----------------------------------------------------------------------
    const stateMachineName = `${projectName}-triage-workflow`;
    this.stateMachineName = stateMachineName;
    this.stateMachine = new sfn.StateMachine(this, 'TriageWorkflow', {
      stateMachineName,
      definition: loadEventState,
      stateMachineType: sfn.StateMachineType.STANDARD,
      logs: {
        destination: workflowLogGroup,
        level: sfn.LogLevel.ALL,
        includeExecutionData: true,
      },
      tracingEnabled: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // NOTE: workerFunction (worker_handler.py) is deliberately NOT granted
    // states:StartExecution on this state machine. It never calls
    // StartExecution — the only real caller is the intake Lambda
    // (src/intake/service.py, built in HealthTriageLeafFunctionsStack),
    // which app.ts already grants this to, one-directionally, since
    // CoreStack/LeafFunctionsStack never depend back on this stack.
    // A prior version of this file granted StartExecution to workerFunction
    // as well, which combined with the state machine's own LambdaInvoke
    // grant TO workerFunction (added automatically by every
    // tasks.LambdaInvoke state using it, e.g. Audit/Notify above) produced
    // a genuine bidirectional dependency between WorkerFunction's role and
    // the state machine — confirmed as a real, deploy-blocking
    // «Circular dependency between resources» error during a real
    // `cdk deploy` (not just the informational F3004 CloudFormation-Validate
    // warning both directions also produce independently). Removing the
    // unused grant breaks the cycle without losing any needed permission.

    // Phase 1b: the DevOps Agent Lambda's TRIGGER_INVESTIGATION step calls
    // SendTaskFailure directly (design.md §7 — secret-read failure or
    // webhook-send failure both fail the task token immediately rather
    // than waiting for a timeout). callback_handler.py (not yet deployed
    // as a real function — see README.md's Phase 1b-deploy section) will
    // need this same grant once it exists as a separate Lambda; granting
    // it here on devOpsAgentFunction covers the synchronous failure path
    // this stack owns today.
    if (devOpsAgentFunction) {
      // grantTaskResponseByArn, NOT this.stateMachine.grantTaskResponse() —
      // see its docstring in python-lambda.ts: the direct call creates a
      // real, deploy-blocking circular dependency with this state
      // machine's own auto-added lambda:InvokeFunction grant TO
      // devOpsAgentFunction (added by every LambdaInvoke task state using
      // it, e.g. TriggerInvestigation/ResolveAgentSpace above). Passing
      // the literal stateMachineName string (not this.stateMachine's
      // stateMachineName getter, which returns a live attribute token via
      // getResourceNameAttribute — that would reintroduce the same live
      // dependency) keeps this a static ARN, breaking the cycle.
      grantTaskResponseByArn(devOpsAgentFunction, stateMachineName);
    }

    // Grant the inventory Lambda access to the AWS Price List API for the
    // PROJECT_COST step. pricing:GetProducts requires Resource: "*" per AWS
    // Price List API limitations (no resource-level permissions supported).
    // This is the Inventory Lambda's ONLY remaining AWS permission: Phase B
    // (feat-devops-agent-enrichment, design §3.7) retired the per-service
    // inventory plug-ins, so the sts:AssumeRole grant on
    // HealthTriageReadOnlyRole is gone, and the maintenance-class prechecks,
    // so the msk_patch_safety cloudwatch:GetMetricData grant is gone too —
    // enrichment now comes from the DevOps Agent investigation, not from
    // this Lambda calling member accounts.
    inventoryFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['pricing:GetProducts'],
        resources: ['*'],
      }),
    );

    // Phase 5: grant the worker Lambda read-only access to the three sink
    // credential secrets, scoped by ARN — never a wildcard
    // (security-policies.md). Granted via iam.Grant.addToPrincipal (not
    // Secret.grantRead) to avoid the same cross-stack KMS key-policy
    // mutation cycle documented on the kmsKey prop above — Secret.grantRead
    // also calls encryptionKey.grantDecrypt() internally.
    const grantSecretReadOnly = (secret: secretsmanager.ISecret | undefined) => {
      if (!secret) return;
      iam.Grant.addToPrincipal({
        grantee: workerFunction,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resourceArns: [secret.secretArn],
      });
      iam.Grant.addToPrincipal({
        grantee: workerFunction,
        actions: ['kms:Decrypt'],
        resourceArns: [props.kmsKey.keyArn],
      });
    };
    grantSecretReadOnly(jiraSecret);
    grantSecretReadOnly(slackSecret);
    grantSecretReadOnly(teamsSecret);

    // SNS publish for SnsSink (R11.1, always-on core sink) — IAM-only grant,
    // same cross-stack-KMS-cycle-avoidance pattern as grantSecretReadOnly
    // above. See the classificationTopicArn prop's docstring for why
    // Topic.grantPublish() is not used here.
    if (classificationTopicArn) {
      iam.Grant.addToPrincipal({
        grantee: workerFunction,
        actions: ['sns:Publish'],
        resourceArns: [classificationTopicArn],
      });
      iam.Grant.addToPrincipal({
        grantee: workerFunction,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
        resourceArns: [props.kmsKey.keyArn],
      });
    }

    // -----------------------------------------------------------------------
    // Stack outputs
    // -----------------------------------------------------------------------
    new cdk.CfnOutput(this, 'StateMachineArn', {
      value: this.stateMachine.stateMachineArn,
      exportName: `${projectName}-triage-workflow-arn`,
      description: 'TriageWorkflow Step Functions state machine ARN',
    });
  }
}
