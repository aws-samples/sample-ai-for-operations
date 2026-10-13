// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * CoreStack — baseline infrastructure for the AWS Health Event Triage Agent.
 *
 * Provisions:
 *  - Customer-managed KMS key with annual rotation
 *  - DynamoDB session table (PITR, SSE-KMS, agent-managed tags)
 *  - SQS intake queue + dead-letter queue (KMS)
 *  - SNS classification result topic (KMS)
 *  - CloudWatch Log Group for the agent
 *  - X-Ray tracing (via IAM policy statement, wired at compute layer)
 *  - Custom metric namespace + baseline alarms (error rate, DLQ depth)
 */

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventsTargets from 'aws-cdk-lib/aws-events-targets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

export interface CoreStackProps extends cdk.StackProps {
  /** Short slug used as a prefix for all resource names, e.g. "health-triage" */
  readonly projectName: string;
  /** Optional SNS topic ARN for CloudWatch alarm notifications */
  readonly alarmTopicArn?: string;
}

export class CoreStack extends cdk.Stack {
  /** The customer-managed KMS key — exported for the Guardrail stack */
  public readonly kmsKey: kms.Key;
  /** The DynamoDB session table */
  public readonly sessionTable: dynamodb.Table;
  /** The SQS intake queue */
  public readonly intakeQueue: sqs.Queue;
  /**
   * Phase -1 (working spec feat-devops-agent-enrichment, req §1b / design
   * §3.0): the settle-window delay queue. The Intake Lambda enqueues one
   * delayed message per AWS Health message here (delay =
   * INTAKE_SETTLE_SECONDS); the settle consumer Lambda drains it and is
   * the only caller of Step Functions StartExecution. Per-message
   * DelaySeconds is set by the sender (IntakeService), not by the queue's
   * own default (kept at 0 so the queue's own default behaviour is
   * unaffected if something else ever sends to it without a delay).
   */
  public readonly settleQueue: sqs.Queue;
  /** The SNS classification result topic */
  public readonly classificationTopic: sns.Topic;
  /** The central EventBridge event bus */
  public readonly centralBus: events.EventBus;
  /** Phase 4: the digest SNS topic */
  public readonly digestTopic: sns.Topic;
  /** Phase 4: the ConsolidatedEvents table (exposed for the Digest Lambda's query permissions) */
  public readonly consolidatedEventsTable: dynamodb.Table;
  /** Phase 4: the DigestWatermark table */
  public readonly digestWatermarkTable: dynamodb.Table;
  /** Phase 1: the Idempotency table (exposed for the worker/intake Lambdas) */
  public readonly idempotencyTable: dynamodb.Table;
  /** Phase 1: the AccountContextCache table (exposed for the worker/intake Lambdas) */
  public readonly accountContextCacheTable: dynamodb.Table;
  /** Phase 1: the TicketMap table (exposed for the worker Lambda's NOTIFY step) */
  public readonly ticketMapTable: dynamodb.Table;
  /** Phase 1: the AuditLog table (exposed for the worker Lambda's AUDIT step) */
  public readonly auditLogTable: dynamodb.Table;
  /**
   * Phase A (working spec feat-devops-agent-enrichment, req E7 / design
   * §3.6, task 8): the event-snapshot bucket. Intake writes the full
   * consolidated event here on every create/update; the investigating
   * Agent Space's role gets s3:GetObject on this bucket only (task 9).
   * Also the substrate for R14.1's 400-day history retention.
   */
  public readonly eventSnapshotBucket: s3.Bucket;
  /**
   * Phase 5: sink credential secret placeholders. Values are NOT set here —
   * the customer populates them post-deploy (Jira API token, Slack/Teams
   * webhook URLs). CDK only provisions the secret ARN and KMS encryption.
   */
  public readonly jiraSecret: secretsmanager.Secret;
  public readonly slackSecret: secretsmanager.Secret;
  public readonly teamsSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: CoreStackProps) {
    super(scope, id, props);

    const { projectName } = props;

    // -----------------------------------------------------------------------
    // Tags applied to all agent-managed resources
    // -----------------------------------------------------------------------
    const commonTags: Record<string, string> = {
      'agent-managed': 'true',
      project: projectName,
      'cost-center': projectName,
      environment: 'prototype',
    };

    // -----------------------------------------------------------------------
    // Customer-managed KMS key
    // -----------------------------------------------------------------------
    this.kmsKey = new kms.Key(this, 'AgentKmsKey', {
      description: `${projectName} — agent-managed KMS key`,
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.kmsKey.addAlias(`alias/${projectName}-key`);
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.kmsKey).add(k, v),
    );

    // Allow SNS and SQS service principals minimal KMS permissions
    this.kmsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowSNSSQSKMS',
        effect: iam.Effect.ALLOW,
        principals: [
          new iam.ServicePrincipal('sns.amazonaws.com'),
          new iam.ServicePrincipal('sqs.amazonaws.com'),
        ],
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: ['*'],
      }),
    );

    // Allow CloudWatch Logs to use this key for log-group encryption. Unlike
    // SNS/SQS/DynamoDB (which accept an IAM-only grant on the calling
    // principal, per the grantTableReadWriteWithoutKeyPolicy helper in
    // python-lambda.ts), CloudWatch Logs specifically requires this
    // statement on the KEY'S OWN policy — logs:CreateLogGroup/PutLogEvents
    // fails with a real, confirmed AccessDenied ("The specified KMS key
    // does not exist or is not allowed to be used") without it, discovered
    // via a real failed `cdk deploy` to eu-west-1 during Build validation.
    // Every AWS::Logs::LogGroup in this app (this stack's AgentLogGroup,
    // every per-Lambda log group in python-lambda.ts, and
    // triage-workflow.ts's WorkflowLogGroup) uses this one shared key, so
    // one statement here covers all of them. Scoped with a source-ARN
    // condition restricted to this account's log groups, per
    // iam-permission-boundary's "never grant more broadly than needed".
    this.kmsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudWatchLogsKMS',
        effect: iam.Effect.ALLOW,
        principals: [
          new iam.ServicePrincipal(`logs.${cdk.Stack.of(this).region}.amazonaws.com`),
        ],
        actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
        resources: ['*'],
        conditions: {
          ArnLike: {
            'kms:EncryptionContext:aws:logs:arn': `arn:${cdk.Stack.of(this).partition}:logs:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:*`,
          },
        },
      }),
    );

    // -----------------------------------------------------------------------
    // DynamoDB tables (Phase 0: sessions; Phase 1: full triage tables)
    // -----------------------------------------------------------------------
    this.sessionTable = new dynamodb.Table(this, 'SessionTable', {
      tableName: `${projectName}-sessions`,
      partitionKey: { name: 'eventArn', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.sessionTable).add(k, v),
    );

    // Phase 1: ConsolidatedEvents — one item per eventArn
    // Phase 4: adds the byDispositionUpdatedAt GSI so the Digest Lambda can
    // query DIGEST-disposition events since the last watermark (design §4).
    const consolidatedEventsTable = new dynamodb.Table(this, 'ConsolidatedEventsTable', {
      tableName: `${projectName}-consolidated-events`,
      partitionKey: { name: 'eventArn', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    consolidatedEventsTable.addGlobalSecondaryIndex({
      indexName: 'byDispositionUpdatedAt',
      partitionKey: { name: 'disposition', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'dispositionUpdatedAt', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(consolidatedEventsTable).add(k, v),
    );
    this.consolidatedEventsTable = consolidatedEventsTable;

    // Phase 1: Idempotency — prevents duplicate processing of the same event update
    const idempotencyTable = new dynamodb.Table(this, 'IdempotencyTable', {
      tableName: `${projectName}-idempotency`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(idempotencyTable).add(k, v),
    );
    this.idempotencyTable = idempotencyTable;

    // Phase 1: AccountContextCache — caches AWS Organizations account metadata
    const accountContextCacheTable = new dynamodb.Table(this, 'AccountContextCacheTable', {
      tableName: `${projectName}-account-context-cache`,
      partitionKey: { name: 'accountId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(accountContextCacheTable).add(k, v),
    );
    this.accountContextCacheTable = accountContextCacheTable;

    // Phase 1: TicketMap — maps eventArn to downstream ticket/SNS message IDs
    const ticketMapTable = new dynamodb.Table(this, 'TicketMapTable', {
      tableName: `${projectName}-ticket-map`,
      partitionKey: { name: 'eventArn', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(ticketMapTable).add(k, v),
    );
    this.ticketMapTable = ticketMapTable;

    // Phase 1: AuditLog — immutable record of every workflow execution
    const auditLogTable = new dynamodb.Table(this, 'AuditLogTable', {
      tableName: `${projectName}-audit-log`,
      partitionKey: { name: 'executionId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(auditLogTable).add(k, v),
    );
    this.auditLogTable = auditLogTable;

    // Phase 4: DigestWatermark — single-item table tracking the last digest run
    const digestWatermarkTable = new dynamodb.Table(this, 'DigestWatermarkTable', {
      tableName: `${projectName}-digest-watermark`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.kmsKey,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(digestWatermarkTable).add(k, v),
    );
    this.digestWatermarkTable = digestWatermarkTable;

    // Outputs for Phase 1 tables
    new cdk.CfnOutput(this, 'ConsolidatedEventsTableName', {
      value: consolidatedEventsTable.tableName,
      exportName: `${projectName}-consolidated-events-table`,
    });
    new cdk.CfnOutput(this, 'IdempotencyTableName', {
      value: idempotencyTable.tableName,
      exportName: `${projectName}-idempotency-table`,
    });
    new cdk.CfnOutput(this, 'AccountContextCacheTableName', {
      value: accountContextCacheTable.tableName,
      exportName: `${projectName}-account-context-cache-table`,
    });
    new cdk.CfnOutput(this, 'TicketMapTableName', {
      value: ticketMapTable.tableName,
      exportName: `${projectName}-ticket-map-table`,
    });
    new cdk.CfnOutput(this, 'AuditLogTableName', {
      value: auditLogTable.tableName,
      exportName: `${projectName}-audit-log-table`,
    });
    new cdk.CfnOutput(this, 'DigestWatermarkTableName', {
      value: digestWatermarkTable.tableName,
      exportName: `${projectName}-digest-watermark-table`,
    });

    // -----------------------------------------------------------------------
    // SQS dead-letter queue
    // -----------------------------------------------------------------------
    const dlq = new sqs.Queue(this, 'IntakeDlq', {
      queueName: `${projectName}-intake-dlq`,
      encryptionMasterKey: this.kmsKey,
      retentionPeriod: cdk.Duration.days(14),
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(dlq).add(k, v),
    );

    // -----------------------------------------------------------------------
    // SQS intake queue
    // -----------------------------------------------------------------------
    this.intakeQueue = new sqs.Queue(this, 'IntakeQueue', {
      queueName: `${projectName}-intake`,
      encryptionMasterKey: this.kmsKey,
      visibilityTimeout: cdk.Duration.minutes(15),
      deadLetterQueue: {
        queue: dlq,
        maxReceiveCount: 3,
      },
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.intakeQueue).add(k, v),
    );

    // -----------------------------------------------------------------------
    // Phase -1: SQS settle-window delay queue + its own dead-letter queue
    // (req §1b / design §3.0). Visibility timeout covers the settle
    // consumer's own short Lambda timeout plus retry headroom; SQS's
    // maximum per-message DelaySeconds is 15 minutes, comfortably above
    // the default INTAKE_SETTLE_SECONDS=60.
    // -----------------------------------------------------------------------
    const settleDlq = new sqs.Queue(this, 'SettleDlq', {
      queueName: `${projectName}-settle-dlq`,
      encryptionMasterKey: this.kmsKey,
      retentionPeriod: cdk.Duration.days(14),
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(settleDlq).add(k, v),
    );

    this.settleQueue = new sqs.Queue(this, 'SettleQueue', {
      queueName: `${projectName}-settle`,
      encryptionMasterKey: this.kmsKey,
      visibilityTimeout: cdk.Duration.minutes(5),
      deadLetterQueue: {
        queue: settleDlq,
        maxReceiveCount: 3,
      },
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.settleQueue).add(k, v),
    );

    // -----------------------------------------------------------------------
    // Phase A: event snapshot bucket (req E7, design §3.6, task 8).
    // KMS-encrypted (the shared agent key), versioned, TLS-only, all four
    // public-access-block flags set, 400-day lifecycle expiration matching
    // R14.1's history retention (security-compliance's S3 bucket
    // checklist: PublicAccessBlockConfiguration all-true, BucketEncryption
    // KMS, VersioningConfiguration enabled, TLS-enforcement bucket policy).
    // -----------------------------------------------------------------------
    this.eventSnapshotBucket = new s3.Bucket(this, 'EventSnapshotBucket', {
      // Region included — S3 bucket names are unique across ALL Regions
      // globally, not per-Region, so account-id-only naming collides for
      // any customer running (or having previously run and torn down) a
      // deployment in more than one Region, or — as this session found —
      // for an operator who accidentally deploys once to the wrong
      // Region and needs the name back in the right one shortly after
      // (a real `cdk deploy` hit a repeated, several-minutes-long S3 409
      // "conflicting conditional operation in progress" after deleting a
      // same-named bucket out-of-band; renaming per-Region avoided
      // needing to wait out whatever internal reservation window caused
      // it, and is also the more correct default going forward).
      bucketName: `${projectName}-event-snapshots-${cdk.Stack.of(this).account}-${cdk.Stack.of(this).region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      bucketKeyEnabled: true,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'expire-after-retention-period',
          enabled: true,
          expiration: cdk.Duration.days(400),
          noncurrentVersionExpiration: cdk.Duration.days(400),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.eventSnapshotBucket).add(k, v),
    );

    // -----------------------------------------------------------------------
    // SNS classification result topic
    // -----------------------------------------------------------------------
    this.classificationTopic = new sns.Topic(this, 'ClassificationTopic', {
      topicName: `${projectName}-classification-results`,
      masterKey: this.kmsKey,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.classificationTopic).add(k, v),
    );

    // -----------------------------------------------------------------------
    // Phase 4: SNS digest topic
    // -----------------------------------------------------------------------
    this.digestTopic = new sns.Topic(this, 'DigestTopic', {
      topicName: `${projectName}-digest`,
      masterKey: this.kmsKey,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.digestTopic).add(k, v),
    );

    // -----------------------------------------------------------------------
    // Central EventBridge event bus (Phase 1)
    // -----------------------------------------------------------------------
    this.centralBus = new events.EventBus(this, 'CentralBus', {
      eventBusName: `${projectName}-central`,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(this.centralBus).add(k, v),
    );

    // Bus policy: allow PutEvents only from the Health admin account's rules.
    // Pass the real account ID via `-c healthAdminAccountId=<12-digit-id>` (StackSet A's
    // deployment doc covers finding the org's Health delegated-admin/management account).
    //
    // `iam.AccountPrincipal` requires a real 12-digit account ID — passing '*' renders as
    // the ARN literal "arn:aws:iam::*:root", which EventBridge's PutResourcePolicy API
    // rejects outright ("Policy contains an invalid principal"), confirmed via a real
    // failed `cdk deploy` to eu-west-1 during Build validation. Wildcard-account cross-
    // account trust is not expressible this way (nor should it be — R1.2 scopes intake to
    // a specific admin account, not the whole partition), so when no real account ID is
    // configured this statement is skipped entirely: the bus still deploys and works for
    // same-account event delivery, just without the cross-account policy until a real
    // Health admin account ID is supplied.
    const healthAdminAccountId = this.node.tryGetContext('healthAdminAccountId');
    if (healthAdminAccountId && healthAdminAccountId !== '*') {
      this.centralBus.addToResourcePolicy(
        new iam.PolicyStatement({
          sid: 'AllowHealthAdminAccount',
          effect: iam.Effect.ALLOW,
          principals: [new iam.AccountPrincipal(healthAdminAccountId)],
          actions: ['events:PutEvents'],
          resources: [this.centralBus.eventBusArn],
        }),
      );
    } else {
      cdk.Annotations.of(this).addWarningV2(
        'HealthTriage:NoHealthAdminAccountId',
        'No healthAdminAccountId context value was supplied — the central EventBridge bus ' +
          'was deployed WITHOUT a cross-account resource policy, so it will not accept ' +
          'aws.health events forwarded from an organizational Health admin account yet. ' +
          'Re-deploy with `-c healthAdminAccountId=<12-digit-account-id>` once you know the ' +
          "AWS Health delegated-admin/management account's ID.",
      );
    }

    // Bus → SQS rule: forward all aws.health events to the intake queue
    new events.Rule(this, 'HealthToIntakeRule', {
      eventBus: this.centralBus,
      ruleName: `${projectName}-health-to-intake`,
      description: 'Route aws.health events from the central bus to the intake SQS queue.',
      eventPattern: {
        source: ['aws.health'],
      },
      targets: [new eventsTargets.SqsQueue(this.intakeQueue)],
    });
    const logGroup = new logs.LogGroup(this, 'AgentLogGroup', {
      logGroupName: `/aws/lambda/${projectName}`,
      retention: logs.RetentionDays.THREE_MONTHS,
      encryptionKey: this.kmsKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    Object.entries(commonTags).forEach(([k, v]) =>
      cdk.Tags.of(logGroup).add(k, v),
    );

    // -----------------------------------------------------------------------
    // CloudWatch alarms
    // -----------------------------------------------------------------------
    const metricNamespace = 'HealthTriage';

    // DLQ depth alarm — fires when any event fails all retries
    const dlqAlarm = new cloudwatch.Alarm(this, 'DlqDepthAlarm', {
      alarmName: `${projectName}-dlq-depth`,
      alarmDescription: 'One or more health events failed all retries and landed in the DLQ.',
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
        statistic: 'Maximum',
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // Phase -1 (req §1b / design §3.0): settle-DLQ depth alarm, same shape
    // as the intake DLQ alarm above — fires when a settle message fails
    // all retries (e.g. the settle consumer cannot reach Step Functions).
    const settleDlqAlarm = new cloudwatch.Alarm(this, 'SettleDlqDepthAlarm', {
      alarmName: `${projectName}-settle-dlq-depth`,
      alarmDescription: 'One or more settle messages failed all retries and landed in the settle DLQ.',
      metric: settleDlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
        statistic: 'Maximum',
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // Custom error-rate alarm using the HealthTriage metric namespace
    const errorRateAlarm = new cloudwatch.Alarm(this, 'ClassificationErrorAlarm', {
      alarmName: `${projectName}-classification-errors`,
      alarmDescription: `Classification errors > 5% in the ${metricNamespace} namespace.`,
      metric: new cloudwatch.Metric({
        namespace: metricNamespace,
        metricName: 'ClassificationErrors',
        dimensionsMap: { Project: projectName },
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 5,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // Wire alarms to an SNS topic if provided
    if (props.alarmTopicArn) {
      const alarmTopic = sns.Topic.fromTopicArn(
        this,
        'AlarmTopic',
        props.alarmTopicArn,
      );
      const action = new cloudwatchActions.SnsAction(alarmTopic);
      dlqAlarm.addAlarmAction(action);
      settleDlqAlarm.addAlarmAction(action);
      errorRateAlarm.addAlarmAction(action);
    }

    // -----------------------------------------------------------------------
    // Stack outputs
    // -----------------------------------------------------------------------
    new cdk.CfnOutput(this, 'KmsKeyArn', {
      value: this.kmsKey.keyArn,
      exportName: `${projectName}-kms-key-arn`,
      description: 'Customer-managed KMS key ARN',
    });
    new cdk.CfnOutput(this, 'CentralBusArn', {
      value: this.centralBus.eventBusArn,
      exportName: `${projectName}-central-bus-arn`,
      description: 'Central EventBridge event bus ARN',
    });
    new cdk.CfnOutput(this, 'SessionTableName', {
      value: this.sessionTable.tableName,
      exportName: `${projectName}-session-table-name`,
      description: 'DynamoDB session table name',
    });
    new cdk.CfnOutput(this, 'EventSnapshotBucketName', {
      value: this.eventSnapshotBucket.bucketName,
      exportName: `${projectName}-event-snapshot-bucket-name`,
      description: 'S3 event-snapshot bucket name (req E7, task 8)',
    });
    new cdk.CfnOutput(this, 'SettleQueueUrl', {
      value: this.settleQueue.queueUrl,
      exportName: `${projectName}-settle-queue-url`,
      description: 'SQS settle-window delay queue URL (Phase -1, req §1b)',
    });
    new cdk.CfnOutput(this, 'IntakeQueueUrl', {
      value: this.intakeQueue.queueUrl,
      exportName: `${projectName}-intake-queue-url`,
      description: 'SQS intake queue URL',
    });
    new cdk.CfnOutput(this, 'ClassificationTopicArn', {
      value: this.classificationTopic.topicArn,
      exportName: `${projectName}-classification-topic-arn`,
      description: 'SNS classification result topic ARN',
    });
    new cdk.CfnOutput(this, 'DigestTopicArn', {
      value: this.digestTopic.topicArn,
      exportName: `${projectName}-digest-topic-arn`,
      description: 'SNS digest topic ARN',
    });

    // -----------------------------------------------------------------------
    // Phase 5: Secrets Manager placeholders for sink credentials
    //
    // These secrets are created EMPTY (a placeholder JSON string) — the
    // customer populates real values (Jira API token, Slack/Teams webhook
    // URLs) after deployment. The agent's IAM role gets read-only
    // GetSecretValue scoped to these three ARNs only, never a wildcard.
    // -----------------------------------------------------------------------
    this.jiraSecret = new secretsmanager.Secret(this, 'JiraSecret', {
      secretName: `${projectName}/jira-credentials`,
      description: 'Jira API credentials (email + apiToken) for JiraSink. Populate after deployment.',
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ email: '', apiToken: '' }),
        generateStringKey: 'placeholder',
      },
    });
    this.slackSecret = new secretsmanager.Secret(this, 'SlackSecret', {
      secretName: `${projectName}/slack-webhook`,
      description: 'Slack incoming webhook URL for SlackSink. Populate after deployment.',
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ webhookUrl: '' }),
        generateStringKey: 'placeholder',
      },
    });
    this.teamsSecret = new secretsmanager.Secret(this, 'TeamsSecret', {
      secretName: `${projectName}/teams-webhook`,
      description: 'Microsoft Teams incoming webhook URL for TeamsSink. Populate after deployment.',
      encryptionKey: this.kmsKey,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ webhookUrl: '' }),
        generateStringKey: 'placeholder',
      },
    });
    [this.jiraSecret, this.slackSecret, this.teamsSecret].forEach((secret) =>
      Object.entries(commonTags).forEach(([k, v]) => cdk.Tags.of(secret).add(k, v)),
    );

    new cdk.CfnOutput(this, 'JiraSecretArn', {
      value: this.jiraSecret.secretArn,
      exportName: `${projectName}-jira-secret-arn`,
      description: 'Secrets Manager ARN for Jira credentials (populate after deployment)',
    });
    new cdk.CfnOutput(this, 'SlackSecretArn', {
      value: this.slackSecret.secretArn,
      exportName: `${projectName}-slack-secret-arn`,
      description: 'Secrets Manager ARN for Slack webhook URL (populate after deployment)',
    });
    new cdk.CfnOutput(this, 'TeamsSecretArn', {
      value: this.teamsSecret.secretArn,
      exportName: `${projectName}-teams-secret-arn`,
      description: 'Secrets Manager ARN for Teams webhook URL (populate after deployment)',
    });
  }
}
