#!/usr/bin/env node
// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventsTargets from 'aws-cdk-lib/aws-events-targets';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import { CoreStack } from '../lib/core-stack';
import { GuardrailStack } from '../lib/guardrail-stack';
import { DevOpsAgentStack } from '../lib/devops-agent-stack';
import { TriageWorkflowStack } from '../lib/triage-workflow';
import { DigestStack } from '../lib/digest-stack';
import { createTriagePythonFunction, grantTableReadWriteWithoutKeyPolicy, grantTaskResponseByArn } from '../lib/python-lambda';

const app = new cdk.App();

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? 'eu-west-1',
};

const projectName = app.node.tryGetContext('projectName') ?? 'health-triage';
const deployEnvironment = app.node.tryGetContext('deployEnvironment') ?? 'prototype';
// Enable the DevOps Agent incident gate's Step Functions states. Off by
// default: the module requires a real AgentSpaceRegistry (R12.1 "disabled
// unless configured") and a populated webhook secret before it does
// anything useful — see README.md's Phase 1b-deploy section for the
// enablement steps.
const enableDevOpsAgentGate = app.node.tryGetContext('enableDevOpsAgentGate') === 'true';
// Phase A (working spec feat-devops-agent-enrichment, design §3.9, task
// 12): default true (design §7 — Stage 1 IS the intended architecture,
// not an opt-in). Only takes effect when enableDevOpsAgentGate is also
// true; TriageWorkflowStack's own constructor falls back to the
// unmodified Inventory/ProjectCost chain when either is false, so this
// context value's absence/'true' string are the only two meaningful
// states a deployer needs to reason about — 'false' is the explicit
// rollback lever described in design §7.
const enrichmentViaDevOpsAgentContext = app.node.tryGetContext('enrichmentViaDevOpsAgent');
const enrichmentViaDevOpsAgent = enrichmentViaDevOpsAgentContext === undefined
  ? true
  : enrichmentViaDevOpsAgentContext === 'true';
// fix-lambda-reserved-concurrency: caps ClassifierFunction's concurrent
// executions so a large multi-account event fan-out cannot exceed the
// deployment's Amazon Bedrock on-demand RPM quota — see
// TriageWorkflowProps.classifierReservedConcurrency's doc in
// triage-workflow.ts for the full rationale and default. CLI context
// values arrive as strings; tryGetContext's raw value is parsed with
// Number(), matching the pattern intakeSettleSeconds already uses below
// (parseInt there, Number() here — either is fine for a small positive
// integer context flag; Number() is used here to reject non-numeric input
// as NaN rather than silently truncating it).
const lambdaReservedConcurrencyContext = app.node.tryGetContext('lambdaReservedConcurrency');
const classifierReservedConcurrency = lambdaReservedConcurrencyContext === undefined
  ? undefined
  : Number(lambdaReservedConcurrencyContext);
if (classifierReservedConcurrency !== undefined && !Number.isInteger(classifierReservedConcurrency)) {
  throw new Error(
    `lambdaReservedConcurrency context value must be a whole number, got: ${lambdaReservedConcurrencyContext}`,
  );
}

const coreStack = new CoreStack(app, 'HealthTriageCoreStack', {
  env,
  projectName,
  description: 'AWS Health Event Triage Agent — core infrastructure (KMS, DynamoDB, SQS, SNS, observability)',
});

const guardrailStack = new GuardrailStack(app, 'HealthTriageGuardrailStack', {
  env,
  projectName,
  description: 'AWS Health Event Triage Agent — Amazon Bedrock Guardrail',
  kmsKey: coreStack.kmsKey,
});

// Phase 1b: DevOps Agent incident-gate tables (TaskTokenTable,
// AgentSpaceCounters, ActiveInvestigations) + the default Agent Space
// (AWS::DevOpsAgent::AgentSpace/Association + eventChannel webhook custom
// resource). See infra/lib/devops-agent-stack.ts for the full breakdown.
const devOpsAgentStack = new DevOpsAgentStack(app, 'HealthTriageDevOpsAgentStack', {
  env,
  projectName,
  description: 'AWS Health Event Triage Agent — DevOps Agent incident-gate tables and Agent Space',
  kmsKey: coreStack.kmsKey,
  deployEnvironment,
  // Task 9 (req E7 / design §3.6): grants the default Agent Space's
  // AgentSpaceRole s3:GetObject on the snapshot bucket's events/* prefix.
  eventSnapshotBucketArn: coreStack.eventSnapshotBucket.bucketArn,
});

// -----------------------------------------------------------------------
// TriageWorkflowStack — builds its own Lambda functions internally (see
// infra/lib/triage-workflow.ts docstring for why: avoids the cross-stack
// grantStartExecution()/grantTaskResponse() dependency cycle a synthetic
// test harness hit during Phase 1b's verification when functions and the
// state machine lived in different stacks).
// -----------------------------------------------------------------------
const triageWorkflowStack = new TriageWorkflowStack(app, 'HealthTriageWorkflowStack', {
  env,
  projectName,
  description: 'AWS Health Event Triage Agent — Step Functions workflow (Classify, ComputeUrgency, DecideDisposition, Inventory, ProjectCost, Precheck, DevOps Agent incident gate, Notify, Audit)',
  kmsKey: coreStack.kmsKey,
  deployEnvironment,
  consolidatedEventsTable: coreStack.consolidatedEventsTable,
  idempotencyTable: coreStack.idempotencyTable,
  accountContextCacheTable: coreStack.accountContextCacheTable,
  ticketMapTable: coreStack.ticketMapTable,
  auditLogTable: coreStack.auditLogTable,
  classificationTopicArn: coreStack.classificationTopic.topicArn,
  jiraSecret: coreStack.jiraSecret,
  slackSecret: coreStack.slackSecret,
  teamsSecret: coreStack.teamsSecret,
  // fix-guardrail-not-wired (PCSR blocker 3): forwards GuardrailStack's
  // output onto ClassifierFunction's environment — see the prop's doc on
  // TriageWorkflowProps in triage-workflow.ts for why this was missing.
  guardrailId: guardrailStack.guardrailId,
  // guardrailVersion is intentionally NOT forwarded here — see the
  // guardrailId/guardrailArn prop doc in TriageWorkflowProps
  // (triage-workflow.ts) for why. TriageWorkflowStack resolves it itself
  // via an SSM dynamic reference against GuardrailStack's
  // GuardrailVersionParam (`/${projectName}/guardrail-version`),
  // breaking the cross-stack Fn::GetAtt/Fn::ImportValue edge that
  // previously deadlocked GuardrailStack's own CfnGuardrailVersion
  // replacement (real deploy defect #2: "Cannot update export ... as it
  // is in use by HealthTriageWorkflowStack").
  guardrailArn: guardrailStack.guardrailArn,
  // fix-guardrail-topic-false-positives: the classifier's ApplyGuardrail
  // grant needs these cross-Region profile ARNs now that the guardrail's
  // topic policy runs on the STANDARD tier — see the prop's doc on
  // TriageWorkflowProps in triage-workflow.ts.
  guardrailProfileDestinationRegionArns: guardrailStack.guardrailProfileDestinationRegionArns,
  enableDevOpsAgentGate,
  // agentSpaceRegistryPath / devOpsAgentWebhookSecretArnForValidation
  // (TriageWorkflowProps) are left undefined by default in a real
  // deployment — a customer populates their own AgentSpaceRegistry file
  // and passes its path + matching webhook secret ARN(s) through these
  // same two props. Both were live-validated end-to-end against real
  // Agent Spaces (single- and multi-space fan-out) by wiring them
  // temporarily during Build, then removing the temporary registry file
  // and this wiring afterward — as here. See eval/eval-report.md Section 7
  // for the live-validation evidence.
  taskTokenTable: devOpsAgentStack.taskTokenTable,
  agentSpaceCountersTable: devOpsAgentStack.agentSpaceCountersTable,
  activeInvestigationsTable: devOpsAgentStack.activeInvestigationsTable,
  readinessAssessmentsTable: devOpsAgentStack.readinessAssessmentsTable,
  // Phase A (task 12): wires the enrichment-path feature flag and the S3
  // snapshot bucket's name through to TriageWorkflowProps. Confirmed via
  // a real `cdk synth -c enableDevOpsAgentGate=true -c
  // enrichmentViaDevOpsAgent=false` that, before this wiring existed, the
  // CLI context value had NO effect at all — TriageWorkflowStack's own
  // constructor default (`?? true`) always won regardless of what was
  // passed on the command line, since nothing forwarded it from app.ts.
  enrichmentViaDevOpsAgent,
  eventSnapshotBucketName: coreStack.eventSnapshotBucket.bucketName,
  // fix-lambda-reserved-concurrency: undefined here means
  // TriageWorkflowStack's own `?? 5` default applies — passing the
  // parsed value through explicitly (rather than defaulting at this call
  // site too) keeps exactly one place responsible for the default,
  // avoiding the enrichmentViaDevOpsAgent class of bug this same file
  // documents above (a flag whose default silently won because a call
  // site didn't forward the parsed context value at all).
  classifierReservedConcurrency,
});

// -----------------------------------------------------------------------
// Intake Lambda (src/intake/handler.py) — SQS batch consumer that starts
// TriageWorkflow executions. Built here (not inside TriageWorkflowStack)
// because the dependency is one-directional (intake needs the state
// machine ARN; nothing in TriageWorkflowStack depends on intake), so no
// cross-stack cycle risk — unlike workerFunction/devOpsAgentFunction,
// which TriageWorkflowStack grants execution rights BACK to.
// -----------------------------------------------------------------------
// Leaf-function stack: holds the intake and digest Lambdas, both of which
// have purely one-directional dependencies on CoreStack/TriageWorkflowStack
// (they read from those stacks' resources and, for intake, are granted
// StartExecution rights by TriageWorkflowStack — nothing in CoreStack or
// TriageWorkflowStack depends on anything this stack owns, so it cannot
// participate in a dependency cycle no matter what it references).
const leafFunctionsStack = new cdk.Stack(app, 'HealthTriageLeafFunctionsStack', {
  env,
  description: 'AWS Health Event Triage Agent — intake and digest Lambda functions',
});
// Imported by ARN — see TriageWorkflowStack's kmsKey prop doc for why: the
// live kms.Key construct's grant helpers mutate the key's OWN resource
// policy per cross-stack grantee, which would create a CoreStack ->
// leafFunctionsStack dependency on top of this stack's existing
// leafFunctionsStack -> CoreStack dependency (needing table/topic ARNs) —
// a cycle. An imported IKey has no mutable policy, so those grant calls
// safely no-op; the key's default trustAccountIdentities:true policy
// already allows same-account IAM principals via their own role policy.
const importedKmsKeyForLeafFunctions = kms.Key.fromKeyArn(
  leafFunctionsStack,
  'ImportedKmsKey',
  coreStack.kmsKey.keyArn,
);
const intakeFunction = createTriagePythonFunction(leafFunctionsStack, 'IntakeFunction', {
  indexFile: 'src/intake/handler.py',
  description: 'AWS Health Event Triage Agent — SQS batch consumer, merges events and enqueues the settle window',
  timeout: cdk.Duration.minutes(1),
  memorySize: 512,
  environment: {
    LOG_LEVEL: 'INFO',
    CONSOLIDATED_TABLE_NAME: coreStack.consolidatedEventsTable.tableName,
    IDEMPOTENCY_TABLE_NAME: coreStack.idempotencyTable.tableName,
    ACCOUNT_CACHE_TABLE_NAME: coreStack.accountContextCacheTable.tableName,
    TICKET_MAP_TABLE_NAME: coreStack.ticketMapTable.tableName,
    AUDIT_LOG_TABLE_NAME: coreStack.auditLogTable.tableName,
    TRIAGE_WORKFLOW_ARN: triageWorkflowStack.stateMachine.stateMachineArn,
    // Phase -1 (req §1b / design §3.0): the Intake Lambda no longer starts
    // the workflow directly — it enqueues a delayed settle message here.
    SETTLE_QUEUE_URL: coreStack.settleQueue.queueUrl,
    INTAKE_SETTLE_SECONDS: app.node.tryGetContext('intakeSettleSeconds') ?? '60',
    // Phase A (req E7 / design §3.6, task 8): the S3 event-snapshot bucket.
    EVENT_SNAPSHOT_BUCKET: coreStack.eventSnapshotBucket.bucketName,
  },
  kmsKey: importedKmsKeyForLeafFunctions,
  deployEnvironment,
});
// grantTableReadWriteWithoutKeyPolicy (not Table.grantReadWriteData) avoids
// mutating coreStack.kmsKey's resource policy from leafFunctionsStack — see
// infra/lib/python-lambda.ts's docstring for why that would be a cycle.
grantTableReadWriteWithoutKeyPolicy(intakeFunction, coreStack.consolidatedEventsTable, coreStack.kmsKey.keyArn);
grantTableReadWriteWithoutKeyPolicy(intakeFunction, coreStack.idempotencyTable, coreStack.kmsKey.keyArn);
grantTableReadWriteWithoutKeyPolicy(intakeFunction, coreStack.accountContextCacheTable, coreStack.kmsKey.keyArn);
grantTableReadWriteWithoutKeyPolicy(intakeFunction, coreStack.ticketMapTable, coreStack.kmsKey.keyArn);
grantTableReadWriteWithoutKeyPolicy(intakeFunction, coreStack.auditLogTable, coreStack.kmsKey.keyArn);
// Phase -1: the Intake Lambda now only sends to the settle queue — it no
// longer needs states:StartExecution (moved to the settle consumer below).
// grantSendMessages() does mutate coreStack.kmsKey's resource policy
// (QueueGrants.sendMessages requests kms:Encrypt/Decrypt/etc. on the
// queue's encryptionMasterKey), the same underlying mechanism
// grantTableReadWriteWithoutKeyPolicy's docstring warns about for
// DynamoDB. It is safe here specifically because the existing
// intakeFunction.addEventSource(new SqsEventSource(coreStack.intakeQueue))
// below already exercises the identical pattern today (SqsEventSource.bind
// calls queue.grantConsumeMessages() internally, which triggers the same
// grantOnKey path) for a queue whose key lives in CoreStack, granted to a
// function in leafFunctionsStack — proven not to create a construct-level
// stack dependency cycle in this codebase's one-directional
// leafFunctionsStack -> CoreStack dependency shape.
coreStack.settleQueue.grantSendMessages(intakeFunction);
// Phase A (req E7 / design §3.6, task 8): s3:PutObject scoped to the
// events/* prefix only, never bucket-wide -- iam-permission-boundary's
// least-privilege rule. grantPut() mutates the bucket's own KMS key
// policy the same way grantSendMessages()/Table.grantReadWriteData() do
// (BucketBase.grantOnKey calls encryptionKey.grant() internally); safe
// here by the same precedent verified via real cdk synth for
// coreStack.settleQueue.grantSendMessages() above.
coreStack.eventSnapshotBucket.grantPut(intakeFunction, 'events/*');

intakeFunction.addEventSource(
  new SqsEventSource(coreStack.intakeQueue, {
    batchSize: 10,
    reportBatchItemFailures: true,
  }),
);

// -----------------------------------------------------------------------
// Phase -1 (req §1b / design §3.0): the settle consumer Lambda. Reads the
// settle queue after each message's INTAKE_SETTLE_SECONDS delay and is the
// ONLY caller of TriageWorkflow's StartExecution — see
// src/intake/settle_handler.py's docstring for why this split exists.
// Built in the same stack as intakeFunction for the same reason
// intakeFunction lives here rather than in CoreStack (one-directional
// dependency on CoreStack/TriageWorkflowStack; no cycle risk).
// -----------------------------------------------------------------------
const settleFunction = createTriagePythonFunction(leafFunctionsStack, 'SettleFunction', {
  indexFile: 'src/intake/settle_handler.py',
  description: 'AWS Health Event Triage Agent — settle-window consumer, starts TriageWorkflow executions',
  timeout: cdk.Duration.seconds(30),
  memorySize: 256,
  environment: {
    LOG_LEVEL: 'INFO',
    TRIAGE_WORKFLOW_ARN: triageWorkflowStack.stateMachine.stateMachineArn,
  },
  kmsKey: importedKmsKeyForLeafFunctions,
  deployEnvironment,
});
// One-directional grant: TriageWorkflowStack -> settleFunction's role (in
// CoreStack/leafFunctionsStack). Safe for the same reason the equivalent
// intakeFunction grant was safe — CoreStack never depends back on
// TriageWorkflowStack.
triageWorkflowStack.stateMachine.grantStartExecution(settleFunction);

settleFunction.addEventSource(
  new SqsEventSource(coreStack.settleQueue, {
    batchSize: 10,
    reportBatchItemFailures: true,
  }),
);

// -----------------------------------------------------------------------
// DigestStack — the digest function has no bidirectional dependency on
// anything (Scheduler -> Lambda is one-directional; the Lambda reads
// CoreStack's tables/topic), so it can safely be built here and passed in.
// -----------------------------------------------------------------------
const digestFunction = createTriagePythonFunction(leafFunctionsStack, 'DigestFunction', {
  indexFile: 'src/digest/handler.py',
  description: 'AWS Health Event Triage Agent — scheduled digest',
  timeout: cdk.Duration.minutes(2),
  memorySize: 512,
  environment: {
    LOG_LEVEL: 'INFO',
    CONSOLIDATED_TABLE_NAME: coreStack.consolidatedEventsTable.tableName,
    DIGEST_WATERMARK_TABLE_NAME: coreStack.digestWatermarkTable.tableName,
    AUDIT_LOG_TABLE_NAME: coreStack.auditLogTable.tableName,
    DIGEST_TOPIC_ARN: coreStack.digestTopic.topicArn,
  },
  kmsKey: coreStack.kmsKey,
  deployEnvironment,
});

// digestFunction's env carries AUDIT_LOG_TABLE_NAME (digest/handler.py
// writes an audit record after every successful publish, per R6.6), but no
// grant on auditLogTable ever existed — DigestStack's grants only cover
// consolidatedEventsTable/digestWatermarkTable/digestTopic. A real scheduled-
// digest invocation confirmed this: _write_audit() failed with a real
// AccessDeniedException, logged and swallowed (by design — an audit-write
// failure must not block the digest that already published), so the digest
// itself appeared to succeed while silently never writing its required
// audit trail. Same class of gap as the classification-topic grant found
// earlier in this session: an env var wired without its matching IAM grant.
grantTableReadWriteWithoutKeyPolicy(digestFunction, coreStack.auditLogTable, coreStack.kmsKey.keyArn);

new DigestStack(app, 'HealthTriageDigestStack', {
  env,
  projectName,
  description: 'AWS Health Event Triage Agent — scheduled digest (EventBridge Scheduler)',
  digestFunction,
  consolidatedEventsTable: coreStack.consolidatedEventsTable,
  digestWatermarkTable: coreStack.digestWatermarkTable,
  digestTopic: coreStack.digestTopic,
  kmsKeyArn: coreStack.kmsKey.keyArn,
});

// -----------------------------------------------------------------------
// Phase 1b: aws.aidevops callback — forwards investigation-completion
// events to src/devops_agent/callback_handler.py. Phase B
// (feat-devops-agent-enrichment, design §3.7) retired StackSet C
// (devops-agent-forwarder.yaml); delivery now relies on the same-account
// AidevopsCallbackRule this block wires up (the aws.aidevops events land on
// the account's own default bus). Only built when the gate itself is
// enabled (same context flag) — an unused callback Lambda would have no
// events to receive and no task tokens to resolve.
// -----------------------------------------------------------------------
if (enableDevOpsAgentGate) {
  // Built inside triageWorkflowStack (not devOpsAgentStack): the callback
  // Lambda needs states:SendTaskSuccess/SendTaskFailure scoped to the
  // state machine's ARN. Any reference to the live StateMachine construct
  // (even just for its ARN) from a DIFFERENT stack creates that stack ->
  // triageWorkflowStack dependency; combined with
  // triageWorkflowStack -> devOpsAgentStack (unavoidable — the callback
  // needs the TaskTokenTable), building it in devOpsAgentStack produced a
  // real cycle during Build. Building it here means only the second edge
  // exists (one-directional, safe).
  const callbackFunction = createTriagePythonFunction(triageWorkflowStack, 'CallbackFunction', {
    indexFile: 'src/devops_agent/callback_handler.py',
    description: 'AWS Health Event Triage Agent — aws.aidevops EventBridge callback, completes pending investigation task tokens',
    timeout: cdk.Duration.seconds(30),
    memorySize: 512,
    environment: {
      LOG_LEVEL: 'INFO',
      TASK_TOKEN_TABLE_NAME: devOpsAgentStack.taskTokenTable.tableName,
    },
    kmsKey: kms.Key.fromKeyArn(triageWorkflowStack, 'ImportedKmsKeyForCallback', coreStack.kmsKey.keyArn),
    deployEnvironment,
  });
  grantTableReadWriteWithoutKeyPolicy(callbackFunction, devOpsAgentStack.taskTokenTable, coreStack.kmsKey.keyArn);
  // states:SendTaskSuccess/SendTaskFailure, scoped to the specific state
  // machine ARN — never a wildcard (security-policies.md).
  // grantTaskResponseByArn (a static ARN built from the literal
  // stateMachineName), NOT triageWorkflowStack.stateMachine.grantTaskResponse()
  // — see python-lambda.ts's docstring: calling the live grant here
  // combines with devOpsAgentFunction's identical same-stack cycle to
  // produce a real, deploy-blocking `Circular dependency between
  // resources` error spanning both stacks' resources (confirmed via a
  // real `cdk deploy -c enableDevOpsAgentGate=true`), not just the
  // TriageWorkflowStack-internal cycle grantTaskResponseByArn already
  // fixes there.
  grantTaskResponseByArn(callbackFunction, triageWorkflowStack.stateMachineName);
  // Read-only per design.md §10's documented exception: no resource-level
  // ARN scoping exists for this action in the installed devops-agent
  // service model.
  callbackFunction.addToRolePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    actions: ['aidevops:ListJournalRecords'],
    resources: ['*'],
  }));

  new events.Rule(triageWorkflowStack, 'AidevopsCallbackRule', {
    eventBus: coreStack.centralBus,
    ruleName: `${projectName}-aidevops-to-callback`,
    description: 'Route aws.aidevops investigation-completion events from the central bus to the DevOps Agent callback Lambda.',
    eventPattern: {
      source: ['aws.aidevops'],
      detailType: ['Investigation Completed', 'Investigation Failed', 'Investigation Cancelled'],
    },
    targets: [new eventsTargets.LambdaFunction(callbackFunction)],
  });
}

app.synth();
