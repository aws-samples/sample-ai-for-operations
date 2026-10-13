// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * DigestStack — schedules the Digest Lambda (src/digest/handler.py) on a
 * configurable cadence (default: daily at 08:00 UTC) via EventBridge
 * Scheduler.
 *
 * The Digest Lambda queries ConsolidatedEvents (byDispositionUpdatedAt GSI,
 * provisioned in CoreStack), formats a digest, publishes to the digest SNS
 * topic, and advances the DigestWatermark table. It runs independently of
 * the TriageWorkflow — not invoked per-event.
 */

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sns from 'aws-cdk-lib/aws-sns';
import { grantTableReadWithoutKeyPolicy, grantTableReadWriteWithoutKeyPolicy } from './python-lambda';

export interface DigestStackProps extends cdk.StackProps {
  readonly projectName: string;
  /** The digest Lambda function (src/digest/handler.py) */
  readonly digestFunction: lambda.IFunction;
  /** Cron expression for the digest cadence (default: daily 08:00 UTC) */
  readonly digestSchedule?: string;
  readonly consolidatedEventsTable: dynamodb.Table;
  readonly digestWatermarkTable: dynamodb.Table;
  readonly digestTopic: sns.Topic;
  /**
   * The CoreStack KMS key ARN (not the live construct — see
   * infra/lib/python-lambda.ts's docstring for why: digestFunction
   * typically lives in a different stack than this one, and
   * Table.grantReadWriteData()'s automatic key-policy mutation would
   * create a dependency cycle).
   */
  readonly kmsKeyArn: string;
}

export class DigestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: DigestStackProps) {
    super(scope, id, props);

    const {
      projectName,
      digestFunction,
      digestSchedule,
      consolidatedEventsTable,
      digestWatermarkTable,
      digestTopic,
    } = props;

    // -----------------------------------------------------------------------
    // IAM grants for the digest Lambda — via the without-key-policy helpers
    // (not Table.grantReadData/grantReadWriteData) since digestFunction
    // lives in a different stack than the tables' KMS key.
    // -----------------------------------------------------------------------
    grantTableReadWithoutKeyPolicy(digestFunction, consolidatedEventsTable, props.kmsKeyArn);
    grantTableReadWriteWithoutKeyPolicy(digestFunction, digestWatermarkTable, props.kmsKeyArn);
    // SNS topic publish: grantPublish only adds an IAM statement to the
    // grantee (SNS topics don't mutate a separate KMS key resource policy
    // the way DynamoDB does), so the standard grant helper is safe here.
    digestTopic.grantPublish(digestFunction);

    // -----------------------------------------------------------------------
    // EventBridge Scheduler role — allows Scheduler to invoke the Lambda
    // -----------------------------------------------------------------------
    const schedulerRole = new iam.Role(this, 'DigestSchedulerRole', {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
    });
    digestFunction.grantInvoke(schedulerRole);

    // -----------------------------------------------------------------------
    // EventBridge Scheduler rule — default daily cron
    // -----------------------------------------------------------------------
    new scheduler.CfnSchedule(this, 'DigestSchedule', {
      name: `${projectName}-digest-schedule`,
      description: 'Triggers the AWS Health Triage digest Lambda on a configurable cadence.',
      scheduleExpression: digestSchedule ?? 'cron(0 8 * * ? *)',
      flexibleTimeWindow: { mode: 'OFF' },
      target: {
        arn: digestFunction.functionArn,
        roleArn: schedulerRole.roleArn,
        input: JSON.stringify({}),
        retryPolicy: {
          maximumRetryAttempts: 2,
          maximumEventAgeInSeconds: 3600,
        },
      },
    });

    new cdk.CfnOutput(this, 'DigestFunctionArn', {
      value: digestFunction.functionArn,
      exportName: `${projectName}-digest-function-arn`,
      description: 'Digest Lambda function ARN',
    });
  }
}
