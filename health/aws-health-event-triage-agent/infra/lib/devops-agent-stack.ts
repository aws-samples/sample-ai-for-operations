// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * DevOpsAgentStack — Phase 1b: AWS DevOps Agent incident-gate tables + the
 * default Agent Space.
 *
 * Provisions the DynamoDB tables the incident gate and readiness gate need
 * (design.md §5, and the readiness-gate working spec's design.md §4):
 * TaskTokenTable (Step Functions .waitForTaskToken correlation, shared by
 * both gates), AgentSpaceCounters (R12.8 monthly budgets, shared table with
 * separate incident/readiness attributes), ActiveInvestigations (R12.5
 * dedupe: local_only), and ReadinessAssessments (R12.3 per-(event,account)
 * readiness tracking — keyed differently from ActiveInvestigations because
 * its tracking unit is per-account, not per-Agent-Space, and it is a
 * durable record with no TTL). Also provisions a default
 * AWS::DevOpsAgent::AgentSpace + account association + eventChannel
 * webhook (via `DevOpsAgentSpace`, see
 * infra/lib/constructs/devops-agent-space.ts) unless
 * `provisionDefaultAgentSpace` is set to false, in which case only a
 * placeholder Secrets Manager secret container is created for the
 * registry seed to reference.
 */

import * as cdk from 'aws-cdk-lib';
import { Construct, IConstruct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { DevOpsAgentSpace } from './constructs/devops-agent-space';

export interface DevOpsAgentStackProps extends cdk.StackProps {
  readonly projectName: string;
  readonly kmsKey: kms.Key;
  /**
   * Deployment environment — forwarded to DevOpsAgentSpace for the webhook
   * provisioner Lambda's log retention. Default: "prototype".
   */
  readonly deployEnvironment?: string;
  /**
   * Provision a default AWS DevOps Agent Agent Space (AgentSpaceRole,
   * OperatorRole, AWS::DevOpsAgent::AgentSpace/Association, and the
   * eventChannel webhook custom resource). Default: true. Set to false to
   * provision only the DynamoDB tables (e.g. when Agent Spaces are managed
   * outside this stack, or per-account via a StackSet).
   */
  readonly provisionDefaultAgentSpace?: boolean;
  /**
   * Phase A (req E7 / design §3.6, task 9): CoreStack's event-snapshot
   * bucket ARN. When supplied and provisionDefaultAgentSpace is true, the
   * default space's AgentSpaceRole is granted s3:GetObject on the
   * bucket's events/* prefix, forwarded straight to DevOpsAgentSpace's
   * own eventSnapshotBucketArn prop.
   */
  readonly eventSnapshotBucketArn?: string;
}

export class DevOpsAgentStack extends cdk.Stack {
  /** Step Functions task-token correlation table (design.md §5). */
  public readonly taskTokenTable: dynamodb.Table;
  /** Monthly incident/readiness investigation counters (R12.8). */
  public readonly agentSpaceCountersTable: dynamodb.Table;
  /** Local dedupe record — this agent's own view of in-flight triggers (R12.5). */
  public readonly activeInvestigationsTable: dynamodb.Table;
  /** Per-(eventArn, accountId) readiness-assessment tracking record (R12.3). No TTL — durable. */
  public readonly readinessAssessmentsTable: dynamodb.Table;
  /**
   * Placeholder webhook secret container, used when
   * `provisionDefaultAgentSpace` is false. When true, `defaultAgentSpace`
   * below provisions a real webhook secret via the custom resource
   * instead, and this field is undefined.
   */
  public readonly defaultWebhookSecret?: secretsmanager.Secret;
  /**
   * The default AWS DevOps Agent Agent Space, when
   * `provisionDefaultAgentSpace` is true (the default). Registry entries
   * reference `defaultAgentSpace.agentSpaceId` and
   * `defaultAgentSpace.webhookSecret.secretArn`.
   */
  public readonly defaultAgentSpace?: DevOpsAgentSpace;

  constructor(scope: Construct, id: string, props: DevOpsAgentStackProps) {
    super(scope, id, props);

    const { projectName, kmsKey } = props;
    const deployEnvironment = props.deployEnvironment ?? 'prototype';
    const provisionDefaultAgentSpace = props.provisionDefaultAgentSpace ?? true;

    const commonTags: Record<string, string> = {
      'agent-managed': 'true',
      project: projectName,
      'cost-center': projectName,
      environment: 'prototype',
    };

    this.taskTokenTable = new dynamodb.Table(this, 'TaskTokenTable', {
      tableName: `${projectName}-devops-agent-task-tokens`,
      partitionKey: { name: 'investigationId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl', // 1 hour, set by workflow_handler.py (design.md §5)
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.agentSpaceCountersTable = new dynamodb.Table(this, 'AgentSpaceCountersTable', {
      tableName: `${projectName}-devops-agent-counters`,
      partitionKey: { name: 'counterKey', type: dynamodb.AttributeType.STRING }, // "<agentSpaceId>#<yyyy-mm>"
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecovery: true,
      // No TTL: kept for R14 history/reporting (design.md §5).
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.activeInvestigationsTable = new dynamodb.Table(this, 'ActiveInvestigationsTable', {
      tableName: `${projectName}-devops-agent-active-investigations`,
      partitionKey: { name: 'agentSpaceId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'eventArn', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl', // 24 hours, set by dedupe.py (design.md §5)
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.readinessAssessmentsTable = new dynamodb.Table(this, 'ReadinessAssessmentsTable', {
      tableName: `${projectName}-devops-agent-readiness-assessments`,
      partitionKey: { name: 'eventArn', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'accountId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecovery: true,
      // No TTL: a durable record for the lifetime of the ticket, not a
      // short-lived in-flight marker (readiness_tracker.py docstring).
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const taggedResources: IConstruct[] = [
      this.taskTokenTable,
      this.agentSpaceCountersTable,
      this.activeInvestigationsTable,
      this.readinessAssessmentsTable,
    ];

    if (provisionDefaultAgentSpace) {
      // Provisions AgentSpaceRole, OperatorRole, AWS::DevOpsAgent::AgentSpace,
      // the AWS account monitor association, and the eventChannel webhook
      // custom resource (RegisterService/AssociateService/PutSecretValue —
      // see infra/lib/constructs/devops-agent-space.ts and
      // infra/lambda/devops-agent-webhook-provisioner/index.ts).
      this.defaultAgentSpace = new DevOpsAgentSpace(this, 'DefaultAgentSpace', {
        name: `${projectName}-default-space`,
        description: `${projectName} — default AWS DevOps Agent Agent Space for the incident gate`,
        deployEnvironment,
        eventSnapshotBucketArn: props.eventSnapshotBucketArn,
      });

      new cdk.CfnOutput(this, 'DefaultAgentSpaceId', {
        value: this.defaultAgentSpace.agentSpaceId,
        exportName: `${projectName}-devops-agent-default-space-id`,
        description: 'Populate this Agent Space ID into config/agent_space_registry.example.json',
      });
      new cdk.CfnOutput(this, 'DefaultWebhookUrl', {
        value: this.defaultAgentSpace.webhookUrl,
        exportName: `${projectName}-devops-agent-default-webhook-url`,
        description: 'Populate this webhook URL into the AgentSpaceRegistry entry',
      });
      if (this.defaultAgentSpace.webhookSecret) {
        new cdk.CfnOutput(this, 'DefaultWebhookSecretArn', {
          value: this.defaultAgentSpace.webhookSecret.secretArn,
          exportName: `${projectName}-devops-agent-default-webhook-secret-arn`,
          description: 'Reference this secret ARN from the AgentSpaceRegistry entry — the value is already populated by the webhook provisioner',
        });
      }
    } else {
      // Fallback: a placeholder secret container only, for deployments that
      // manage the Agent Space itself outside this stack and just need a
      // real ARN shape for the registry seed to reference in the interim.
      this.defaultWebhookSecret = new secretsmanager.Secret(this, 'DefaultWebhookSecret', {
        description: `${projectName} — default AWS DevOps Agent eventChannel webhook HMAC secret (populate manually)`,
        encryptionKey: kmsKey,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });
      taggedResources.push(this.defaultWebhookSecret);

      new cdk.CfnOutput(this, 'DefaultWebhookSecretArn', {
        value: this.defaultWebhookSecret.secretArn,
        exportName: `${projectName}-devops-agent-default-webhook-secret-arn`,
        description: 'Populate this secret with the Agent Space eventChannel webhook HMAC secret before enabling the incident gate',
      });
    }

    taggedResources.forEach((resource) => {
      Object.entries(commonTags).forEach(([k, v]) => cdk.Tags.of(resource).add(k, v));
    });
  }
}
