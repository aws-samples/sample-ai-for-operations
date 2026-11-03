// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import {
  Annotations, Aws, CfnCondition, CfnOutput, CfnParameter, CfnRule, Duration, Fn, RemovalPolicy, Stack, StackProps,
} from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Construct } from 'constructs';
import { lambdaCode } from './lambda-code';

export interface DriftCheckerStackProps extends StackProps {
  readonly skipBundling?: boolean;
}

const METRIC_NAMESPACE = 'NetworkRoutingDriftChecker';
const REGION_LIST = '^$|^[a-z]{2}(-[a-z]+)+-[0-9](,[a-z]{2}(-[a-z]+)+-[0-9])*$';

/**
 * Phase 1 stack (tasks.md 1.3-1.10): scheduled, read-only drift checker.
 * Customer resources: Describe/Get/List/Search only. Writes only to this stack's own
 * bucket, table, topic and log groups (iam-permission-boundary).
 */
export class DriftCheckerStack extends Stack {
  constructor(scope: Construct, id: string, props: DriftCheckerStackProps = {}) {
    super(scope, id, props);

    // ── Parameters (design.md D§8) ─────────────────────────────────────────
    const scheduleExpression = new CfnParameter(this, 'ScheduleExpression', {
      type: 'String', default: 'cron(0 5 * * ? *)',
      description: 'EventBridge Scheduler expression for the daily run.',
    });
    const scheduleTimezone = new CfnParameter(this, 'ScheduleTimezone', {
      type: 'String',
      description: 'REQUIRED. IANA timezone for the schedule, e.g. Europe/Berlin or America/New_York.',
      allowedPattern: '^(UTC|[A-Za-z]+(/[A-Za-z0-9_+-]+){1,2})$',
      constraintDescription: 'must be an IANA timezone name such as Europe/Berlin',
    });
    const regionAllowlist = new CfnParameter(this, 'RegionAllowlist', {
      type: 'String', default: '', allowedPattern: REGION_LIST,
      description: 'Optional comma-separated Regions. Non-empty replaces auto-discovery.',
    });
    const regionExcludeList = new CfnParameter(this, 'RegionExcludeList', {
      type: 'String', default: '', allowedPattern: REGION_LIST,
      description: 'Optional comma-separated Regions never evaluated.',
    });
    const regionConcurrency = new CfnParameter(this, 'RegionConcurrency', {
      type: 'Number', default: 4, minValue: 1, maxValue: 10,
      description: 'Regions collected in parallel.',
    });
    const environmentTagKey = new CfnParameter(this, 'EnvironmentTagKey', {
      type: 'String', default: 'Environment', allowedPattern: '^[A-Za-z0-9 _.:/=+@-]{1,128}$',
      description: 'Tag key that names the routing domain of TGW route tables and attachments.',
    });
    const productionTagValues = new CfnParameter(this, 'ProductionTagValues', {
      type: 'String', default: 'prod,production', allowedPattern: '^[A-Za-z0-9 _.:/=+@,-]{1,256}$',
      description: 'Comma-separated Environment tag values treated as production.',
    });
    const limitThresholdPercent = new CfnParameter(this, 'LimitThresholdPercent', {
      type: 'Number', default: 80, minValue: 1, maxValue: 100,
      description: 'Percent of a route/prefix limit at which check 5 reports.',
    });
    const limitThresholdOverrides = new CfnParameter(this, 'LimitThresholdOverrides', {
      type: 'String', default: '',
      description: 'Optional JSON object of per-limit thresholds, e.g. {"tgw-total-routes": 90}.',
    });
    const intentObjectKey = new CfnParameter(this, 'IntentObjectKey', {
      type: 'String', default: 'intent/routing-intent.yaml', allowedPattern: '^intent/[A-Za-z0-9_.-]+\\.ya?ml$',
      description: 'S3 key of the hybrid intent file in this stack\'s bucket.',
    });
    const logRetentionDays = new CfnParameter(this, 'LogRetentionDays', {
      type: 'Number', default: 90,
      allowedValues: ['90', '120', '150', '180', '365', '400', '545', '731', '1096', '1827', '2192', '2557', '2922',
        '3288', '3653'],
      description: 'CloudWatch Logs retention in days (minimum 90).',
    });
    const notificationEmail = new CfnParameter(this, 'NotificationEmail', {
      type: 'String', default: '', allowedPattern: '^$|^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$',
      description: 'Optional e-mail address subscribed to the report topic.',
    });
    // DevOps Agent hand-off (Phase 3). Declared now so the all-or-none rule is in place.
    const enableHandoff = new CfnParameter(this, 'EnableDevOpsAgentHandoff', {
      type: 'String', default: 'false', allowedValues: ['true', 'false'],
      description: 'Hand NEW findings to an AWS DevOps Agent Agent Space (Phase 3; not active in this build).',
    });
    const webhookUrl = new CfnParameter(this, 'DevOpsAgentWebhookUrl', {
      type: 'String', default: '',
      allowedPattern: '^$|^https://event-ai\\.[a-z0-9-]+\\.api\\.aws/webhook/generic/[A-Za-z0-9_-]+$',
      description: 'Generic HMAC webhook URL of the Agent Space (same Region as this stack).',
    });
    const webhookSecretName = new CfnParameter(this, 'WebhookSecretParameterName', {
      type: 'String', default: '', allowedPattern: '^$|^/[A-Za-z0-9_./-]{1,1010}$',
      description: 'Name of the SSM SecureString parameter that holds the HMAC secret (never the secret).',
    });
    const agentSpaceId = new CfnParameter(this, 'DevOpsAgentSpaceId', {
      type: 'String', default: '', allowedPattern: '^$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
      description: 'Agent Space ID (scopes the completion-event rule and journal reads).',
    });

    const agentAccountId = new CfnParameter(this, 'DevOpsAgentAccountId', {
      type: 'String', default: '', allowedPattern: '^$|^[0-9]{12}$',
      description: 'Account of the Agent Space. Empty or this account = same-account; another account = '
        + 'cross-account (deploy the DevOpsAgentLink companion stack there, design D§3.3a).',
    });
    const investigationTimeout = new CfnParameter(this, 'InvestigationTimeoutSeconds', {
      type: 'Number', default: 2700, minValue: 60, maxValue: 3600,
      description: 'How long one investigation batch may run before it is reported as timed out.',
    });
    const investigationHeartbeat = new CfnParameter(this, 'InvestigationHeartbeatSeconds', {
      type: 'Number', default: 2700, minValue: 60, maxValue: 3600,
      description: 'Heartbeat timeout of an investigation batch (keep equal to the timeout, D§3.4).',
    });
    const investigationConcurrency = new CfnParameter(this, 'InvestigationConcurrency', {
      type: 'Number', default: 2, minValue: 1, maxValue: 5,
      description: 'Investigation batches run in parallel.',
    });
    const maxFindingsPerInvestigation = new CfnParameter(this, 'MaxFindingsPerInvestigation', {
      type: 'Number', default: 25, minValue: 1, maxValue: 100,
      description: 'Maximum NEW findings handed to one investigation.',
    });

    Annotations.of(webhookSecretName).acknowledgeWarning('CloudFormation-Validate::W2509',
      'WebhookSecretParameterName holds the NAME of an SSM SecureString parameter, never the secret itself.');

    const isEmpty = (p: CfnParameter) => Fn.conditionEquals(p.valueAsString, '');
    new CfnRule(this, 'HandoffRequiresAllSettings', {
      ruleCondition: Fn.conditionEquals(enableHandoff.valueAsString, 'true'),
      assertions: [webhookUrl, webhookSecretName, agentSpaceId].map((p) => ({
        assert: Fn.conditionNot(isEmpty(p)),
        assertDescription: `EnableDevOpsAgentHandoff=true requires ${p.logicalId}.`,
      })),
    });
    new CfnRule(this, 'HandoffDisabledRequiresNoSettings', {
      ruleCondition: Fn.conditionEquals(enableHandoff.valueAsString, 'false'),
      assertions: [{
        assert: Fn.conditionAnd(isEmpty(webhookUrl), isEmpty(webhookSecretName), isEmpty(agentSpaceId)),
        assertDescription: 'DevOps Agent settings are set but EnableDevOpsAgentHandoff=false; set it to true or '
          + 'clear DevOpsAgentWebhookUrl, WebhookSecretParameterName and DevOpsAgentSpaceId.',
      }],
    });

    // Hand-off shapes (D§3.3, D§3.3a). One template covers all three: off, same-account,
    // cross-account. Only IAM statements, the rule and the Lambda permissions are conditional;
    // the functions always exist so the state machine definition is static.
    const handoffOn = new CfnCondition(this, 'HandoffEnabled', {
      expression: Fn.conditionEquals(enableHandoff.valueAsString, 'true'),
    });
    const otherAccount = Fn.conditionAnd(
      Fn.conditionNot(Fn.conditionEquals(agentAccountId.valueAsString, '')),
      Fn.conditionNot(Fn.conditionEquals(agentAccountId.valueAsString, Aws.ACCOUNT_ID)));
    const sameAccountHandoff = new CfnCondition(this, 'SameAccountHandoff', {
      expression: Fn.conditionAnd(handoffOn, Fn.conditionNot(otherAccount)),
    });
    const crossAccountHandoff = new CfnCondition(this, 'CrossAccountHandoff', {
      expression: Fn.conditionAnd(handoffOn, otherAccount),
    });

    // ── Encryption, storage, messaging (D§11, security-compliance) ──────────
    const key = new kms.Key(this, 'Key', {
      description: 'Network routing drift checker: bucket, state table, topic',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN, // encrypts the retained bucket and table
    });
    // CloudWatch alarms publish to the encrypted topic; they cannot use the aws/sns key.
    key.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchAlarmsToPublish',
      principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
      resources: ['*'],
      conditions: { StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID } },
    }));

    const bucket = new s3.Bucket(this, 'Bucket', {
      encryption: s3.BucketEncryption.KMS, encryptionKey: key, bucketKeyEnabled: true,
      versioned: true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [{
        id: 'expire-run-artifacts', prefix: 'runs/',
        expiration: Duration.days(30), noncurrentVersionExpiration: Duration.days(1),
      }],
    });

    const table = new dynamodb.Table(this, 'StateTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED, encryptionKey: key,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      timeToLiveAttribute: 'ttl',
      removalPolicy: RemovalPolicy.RETAIN,
    });
    table.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const topic = new sns.Topic(this, 'ReportTopic', {
      displayName: 'Network routing drift checker', masterKey: key, enforceSSL: true,
    });
    // The topic policy replaces SNS's default policy, so the CloudWatch service needs an explicit
    // Allow. Without it every alarm action failed with "not authorized to perform SNS:Publish"
    // (found live 2026-10-14). Scoped to alarms in this account.
    topic.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchAlarmsToPublish',
      principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
      actions: ['sns:Publish'],
      resources: [topic.topicArn],
      conditions: {
        StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID },
        ArnLike: { 'aws:SourceArn': `arn:${Aws.PARTITION}:cloudwatch:${Aws.REGION}:${Aws.ACCOUNT_ID}:alarm:*` },
      },
    }));
    const hasEmail = new CfnCondition(this, 'HasNotificationEmail', {
      expression: Fn.conditionNot(Fn.conditionEquals(notificationEmail.valueAsString, '')),
    });
    const subscription = new sns.CfnSubscription(this, 'EmailSubscription', {
      topicArn: topic.topicArn, protocol: 'email', endpoint: notificationEmail.valueAsString,
    });
    subscription.cfnOptions.condition = hasEmail;

    // ── Lambda functions (D§2.1) ───────────────────────────────────────────
    const code = lambdaCode(props.skipBundling ?? false);
    const baseEnv = { BUCKET_NAME: bucket.bucketName, TABLE_NAME: table.tableName, LOG_LEVEL: 'INFO' };

    const makeFunction = (name: string, handler: string, timeoutSeconds: number, description: string,
      environment: Record<string, string> = {}) => {
      const logGroup = new logs.LogGroup(this, `${name}Logs`, { removalPolicy: RemovalPolicy.DESTROY });
      (logGroup.node.defaultChild as logs.CfnLogGroup).retentionInDays = logRetentionDays.valueAsNumber;
      const role = new iam.Role(this, `${name}Role`, {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        description: `Execution role for ${name}`,
      });
      role.addToPolicy(new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [logGroup.logGroupArn],
      }));
      const fn = new lambda.Function(this, name, {
        runtime: lambda.Runtime.PYTHON_3_12, architecture: lambda.Architecture.ARM_64, code, handler,
        memorySize: 512, timeout: Duration.seconds(timeoutSeconds), tracing: lambda.Tracing.ACTIVE,
        role, logGroup, description, environment: { ...baseEnv, ...environment },
      });
      return { fn, role };
    };

    const init = makeFunction('InitFunction', 'handlers.init_run.handler', 180,
      'Load intent, discover Region scope, write the run manifest', {
        INTENT_OBJECT_KEY: intentObjectKey.valueAsString,
        ENVIRONMENT_TAG_KEY: environmentTagKey.valueAsString,
        PRODUCTION_TAG_VALUES: productionTagValues.valueAsString,
        LIMIT_THRESHOLD_PERCENT: limitThresholdPercent.valueAsString,
        LIMIT_THRESHOLD_OVERRIDES: limitThresholdOverrides.valueAsString,
        REGION_ALLOWLIST: regionAllowlist.valueAsString,
        REGION_EXCLUDE_LIST: regionExcludeList.valueAsString,
        REGION_CONCURRENCY: regionConcurrency.valueAsString,
        ENABLE_DEVOPS_AGENT_HANDOFF: enableHandoff.valueAsString,
      });
    const collectCloudWan = makeFunction('CollectCloudWanFunction', 'handlers.collect.cloudwan_handler', 300,
      'Collect Cloud WAN policy, attachments and routes (read-only)');
    const collectRegion = makeFunction('CollectRegionFunction', 'handlers.collect.region_handler', 300,
      'Collect Transit Gateway and Direct Connect state for one Region (read-only)');
    const evaluateFn = makeFunction('EvaluateFunction', 'handlers.pipeline.evaluate_handler', 120,
      'Run the deterministic drift checks');
    const diffFn = makeFunction('DiffFunction', 'handlers.pipeline.diff_handler', 120,
      'Classify findings as NEW, KNOWN or RESOLVED');
    const reportFn = makeFunction('ReportFunction', 'handlers.pipeline.report_handler', 60,
      'Compose the heartbeat or drift report');
    // Hand-off functions (Phase 3). Always created; idle unless the hand-off is enabled.
    const batchFn = makeFunction('BatchFindingsFunction', 'handlers.investigate.batch_handler', 60,
      'Split NEW drift findings into investigation batches', {
        MAX_FINDINGS_PER_INVESTIGATION: maxFindingsPerInvestigation.valueAsString,
      });
    const investigateFn = makeFunction('InvestigateFunction', 'handlers.investigate.handler', 60,
      'Sign and send one investigation batch to the DevOps Agent webhook', {
        DEVOPS_AGENT_WEBHOOK_URL: webhookUrl.valueAsString,
        WEBHOOK_SECRET_PARAMETER_NAME: webhookSecretName.valueAsString,
        INVESTIGATION_TIMEOUT_SECONDS: investigationTimeout.valueAsString,
      });
    const mergeFn = makeFunction('MergeInvestigationsFunction', 'handlers.investigate.merge_handler', 60,
      'Merge per-batch investigation results');
    const callbackFn = makeFunction('CallbackFunction', 'handlers.callback.handler', 120,
      'Complete investigation tasks from DevOps Agent events', {
        DEVOPS_AGENT_SPACE_ID: agentSpaceId.valueAsString,
        DEVOPS_AGENT_ACCOUNT_ID: agentAccountId.valueAsString,
        PRODUCTION_TAG_VALUES: productionTagValues.valueAsString,
      });
    const checkerFns = [init, collectCloudWan, collectRegion, evaluateFn, diffFn, reportFn];
    const all = [...checkerFns, batchFn, investigateFn, mergeFn, callbackFn];

    // ── Permissions: customer resources, read-only (D§7.1) ─────────────────
    const nm = (resource: string) => `arn:${Aws.PARTITION}:networkmanager::${Aws.ACCOUNT_ID}:${resource}`;
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'DiscoverRegionsAndTransitGateways', actions: ['ec2:DescribeRegions', 'ec2:DescribeTransitGateways'],
      resources: ['*'], // EC2 Describe* do not support resource-level permissions
    }));
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ListCoreNetworks', actions: ['networkmanager:ListCoreNetworks'], resources: ['*'],
    }));
    for (const r of [init.role, collectCloudWan.role]) {
      r.addToPolicy(new iam.PolicyStatement({
        sid: 'ReadCoreNetwork', actions: ['networkmanager:GetCoreNetwork'], resources: [nm('core-network/*')],
      }));
    }
    // Direct Connect gateways and their associations are global (no Region in the ARN); VIFs are
    // Regional. All three actions support resource-level permissions on these ARN types per the
    // AWS Service Authorization Reference (pre-release review finding, 2026-10-18) -- the previous
    // Resource: '*' with a "Describe* are account-scoped" comment was simply wrong, not a
    // documented limitation. Scoped to this account's own gateways/VIFs: VIF/gateway IDs are not
    // known ahead of discovery, so the account-wide wildcard suffix is the narrowest static scope
    // available, same pattern as the per-account wildcards used elsewhere in this file.
    const dxGatewayArn = `arn:${Aws.PARTITION}:directconnect::${Aws.ACCOUNT_ID}:dx-gateway/*`;
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadDirectConnectGateways',
      actions: ['directconnect:DescribeDirectConnectGateways', 'directconnect:DescribeDirectConnectGatewayAssociations'],
      resources: [dxGatewayArn],
    }));
    init.role.addToPolicy(new iam.PolicyStatement({
      // finds the Regions of VIFs named in the intent file; VIFs are Regional, so Region is '*'
      sid: 'ReadDirectConnectVirtualInterfacesForDiscovery', actions: ['directconnect:DescribeVirtualInterfaces'],
      resources: [`arn:${Aws.PARTITION}:directconnect:*:${Aws.ACCOUNT_ID}:dxvif/*`,
        `arn:${Aws.PARTITION}:directconnect:*:${Aws.ACCOUNT_ID}:dxcon/*`,
        `arn:${Aws.PARTITION}:directconnect:*:${Aws.ACCOUNT_ID}:dxlag/*`],
    }));
    collectCloudWan.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadCloudWan', actions: ['networkmanager:ListCoreNetworks'], resources: ['*'],
    }));
    collectCloudWan.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadCloudWanPolicy', actions: ['networkmanager:GetCoreNetworkPolicy'], resources: [nm('core-network/*')],
    }));
    collectCloudWan.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadCloudWanAttachments', actions: ['networkmanager:ListAttachments'], resources: [nm('attachment/*')],
    }));
    collectCloudWan.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadCloudWanRoutes', actions: ['networkmanager:GetNetworkRoutes'], resources: [nm('global-network/*')],
    }));
    collectRegion.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadTransitGateways',
      actions: ['ec2:DescribeTransitGateways', 'ec2:DescribeTransitGatewayRouteTables',
        'ec2:DescribeTransitGatewayAttachments',
        'ec2:DescribeVpnConnections'], // VPN backup health (check 6); none of these support resource-level permissions
      resources: ['*'],
    }));
    // SearchTransitGatewayRoutes DOES support resource-level permissions on transit-gateway-route-table
    // (pre-release review finding, 2026-10-18) -- split out of the statement above, which must stay on
    // '*' for the other, genuinely unscopable Describe* actions. Table IDs are discovered at
    // runtime from DescribeTransitGatewayRouteTables above, so this scopes by resource TYPE
    // (every table this account owns), not by a specific, unknown-ahead-of-time table ID.
    collectRegion.role.addToPolicy(new iam.PolicyStatement({
      sid: 'SearchTransitGatewayRoutes', actions: ['ec2:SearchTransitGatewayRoutes'],
      resources: [`arn:${Aws.PARTITION}:ec2:${Aws.REGION}:${Aws.ACCOUNT_ID}:transit-gateway-route-table/*`],
    }));
    collectRegion.role.addToPolicy(new iam.PolicyStatement({
      // Direct Connect VIFs/connections/LAGs support resource-level permissions (same finding).
      sid: 'ReadVirtualInterfaces', actions: ['directconnect:DescribeVirtualInterfaces'],
      resources: [`arn:${Aws.PARTITION}:directconnect:${Aws.REGION}:${Aws.ACCOUNT_ID}:dxvif/*`,
        `arn:${Aws.PARTITION}:directconnect:${Aws.REGION}:${Aws.ACCOUNT_ID}:dxcon/*`,
        `arn:${Aws.PARTITION}:directconnect:${Aws.REGION}:${Aws.ACCOUNT_ID}:dxlag/*`],
    }));

    // ── Permissions: the stack's own resources (D§7.2) ─────────────────────
    const runObjects = bucket.arnForObjects('runs/*');
    for (const { role } of all) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'RunArtifacts', actions: ['s3:GetObject', 's3:PutObject'], resources: [runObjects],
      }));
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'RunArtifactsKey', actions: ['kms:Decrypt', 'kms:GenerateDataKey'], resources: [key.keyArn],
      }));
    }
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadIntentFile', actions: ['s3:GetObject', 's3:GetObjectVersion'],
      resources: [bucket.arnForObjects(intentObjectKey.valueAsString)],
    }));
    // ListBucket lets S3 answer "no such key" (absent intent file) instead of AccessDenied.
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'DistinguishAbsentIntentFile', actions: ['s3:ListBucket'], resources: [bucket.bucketArn],
    }));
    init.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadMarker', actions: ['dynamodb:GetItem'], resources: [table.tableArn],
    }));
    diffFn.role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadOpenFindings', actions: ['dynamodb:Query'], resources: [`${table.tableArn}/index/status-index`],
    }));
    diffFn.role.addToPolicy(new iam.PolicyStatement({
      sid: 'WriteFindingHistory', actions: ['dynamodb:BatchWriteItem', 'dynamodb:PutItem'],
      resources: [table.tableArn],
      conditions: { StringEquals: { 'aws:ResourceTag/agent-managed': 'true' } },
    }));
    // TOKEN# items and the live-investigation set (state_store.py). Same tag condition as diff.
    investigateFn.role.addToPolicy(new iam.PolicyStatement({
      sid: 'WriteTaskTokens', actions: ['dynamodb:PutItem', 'dynamodb:UpdateItem'], resources: [table.tableArn],
      conditions: { StringEquals: { 'aws:ResourceTag/agent-managed': 'true' } },
    }));
    for (const { role } of [mergeFn, callbackFn]) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'ReadTaskTokens', actions: ['dynamodb:GetItem'], resources: [table.tableArn],
      }));
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'UpdateTaskTokens', actions: ['dynamodb:UpdateItem'], resources: [table.tableArn],
        conditions: { StringEquals: { 'aws:ResourceTag/agent-managed': 'true' } },
      }));
    }
    for (const { role } of [init, diffFn, investigateFn, mergeFn, callbackFn]) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'StateTableKey', actions: ['kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey'], resources: [key.keyArn],
      }));
    }

    // Conditional hand-off grants: absent from the template's effective policy unless enabled.
    const conditionalPolicy = (id: string, role: iam.Role, condition: CfnCondition, statement: iam.PolicyStatement) => {
      const policy = new iam.Policy(this, id, { roles: [role], statements: [statement] });
      (policy.node.defaultChild as iam.CfnPolicy).cfnOptions.condition = condition;
      return policy;
    };
    // The signing secret. A SecureString under the default aws/ssm key needs no IAM KMS grant:
    // that AWS managed key's policy allows use via SSM by principals in the account. A customer
    // managed key needs kms:Decrypt added by the customer (README, task 3.11).
    conditionalPolicy('InvestigateSecretPolicy', investigateFn.role, handoffOn, new iam.PolicyStatement({
      sid: 'ReadWebhookSecret', actions: ['ssm:GetParameter'],
      resources: [`arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter${webhookSecretName.valueAsString}`],
    }));
    conditionalPolicy('CallbackJournalPolicy', callbackFn.role, sameAccountHandoff, new iam.PolicyStatement({
      sid: 'ReadInvestigationJournal', actions: ['aidevops:ListJournalRecords'],
      resources: [`arn:${Aws.PARTITION}:aidevops:${Aws.REGION}:${Aws.ACCOUNT_ID}:agentspace/${agentSpaceId.valueAsString}`],
    }));
    // Name format shared with src/drift_core/cross_account.py and the companion stack.
    const journalReaderArn = `arn:${Aws.PARTITION}:iam::${agentAccountId.valueAsString}:role/`
      + `nrdc-journal-reader-${Aws.ACCOUNT_ID}-${Aws.REGION}`;
    conditionalPolicy('CallbackAssumeJournalReaderPolicy', callbackFn.role, crossAccountHandoff,
      new iam.PolicyStatement({ sid: 'AssumeJournalReader', actions: ['sts:AssumeRole'], resources: [journalReaderArn] }));

    // Async-invoke failure destination for the callback (D§3.3 "Delivery reliability"). Built by
    // hand: CDK's SqsDestination grants kms:ReEncrypt*, which the IAM lint rejects.
    const callbackDlq = new sqs.Queue(this, 'CallbackDlq', {
      encryption: sqs.QueueEncryption.KMS, encryptionMasterKey: key, enforceSSL: true,
      retentionPeriod: Duration.days(14),
    });
    callbackFn.role.addToPolicy(new iam.PolicyStatement({
      sid: 'CallbackDeadLetter', actions: ['sqs:SendMessage'], resources: [callbackDlq.queueArn],
    }));
    callbackFn.role.addToPolicy(new iam.PolicyStatement({
      sid: 'CallbackDeadLetterKey', actions: ['kms:GenerateDataKey', 'kms:Decrypt'], resources: [key.keyArn],
    }));
    const invokeConfig = new lambda.CfnEventInvokeConfig(this, 'CallbackAsyncConfig', {
      functionName: callbackFn.fn.functionName, qualifier: '$LATEST', maximumRetryAttempts: 2,
      maximumEventAgeInSeconds: 3600,
      destinationConfig: { onFailure: { destination: callbackDlq.queueArn } },
    });
    invokeConfig.node.addDependency(callbackFn.role);

    // Who may invoke the callback. Same-account: the rule below (AWS::Lambda::Permission, scoped
    // by aws:SourceArn/aws:SourceAccount — the usual condition keys for an AWS service principal
    // invoking on behalf of a resource it owns). Cross-account: account D's own event-forwarder
    // role is the actual signing caller (the companion stack's rule names it as the target's
    // RoleArn), not an AWS service principal, so SourceArn/SourceAccount do not apply here —
    // those keys are populated by the service, not by a directly-calling cross-account IAM
    // principal. AWS::Lambda::ResourcePolicy (the full-JSON resource policy, not the legacy
    // AWS::Lambda::Permission) supports the complete IAM condition-key range, so the grant is
    // pinned to the forwarder role's exact ARN via aws:PrincipalArn — the same condition the
    // companion stack already uses the other direction for its journal-reader role's trust
    // policy (devops-agent-link-stack.ts). The forwarder role's ARN is deterministic from its
    // fixed name (src/drift_core/cross_account.py EVENT_FORWARDER_ROLE_FORMAT) and this stack's
    // own account/Region, so it can be referenced before the companion stack creates it — unlike
    // a bare account-ID principal, this does not admit every other principal in account D.
    const forwarderRoleArn = `arn:${Aws.PARTITION}:iam::${agentAccountId.valueAsString}:role/`
      + `nrdc-event-forwarder-${Aws.ACCOUNT_ID}-${Aws.REGION}`;
    const eventPattern = {
      source: ['aws.aidevops'],
      'detail-type': ['Investigation Completed', 'Investigation Failed', 'Investigation Timed Out',
        'Investigation Cancelled', 'Investigation Skipped', 'Investigation Linked',
        'Investigation Created', 'Investigation In Progress', 'Investigation Priority Updated'],
      detail: { metadata: { agent_space_id: [agentSpaceId.valueAsString] } },
    };
    const rule = new events.CfnRule(this, 'InvestigationEventsRule', {
      description: 'DevOps Agent investigation events of the configured Agent Space -> callback',
      eventPattern, state: 'ENABLED',
      targets: [{ id: 'callback', arn: callbackFn.fn.functionArn }],
    });
    rule.cfnOptions.condition = sameAccountHandoff;
    const rulePermission = new lambda.CfnPermission(this, 'CallbackFromRule', {
      action: 'lambda:InvokeFunction', functionName: callbackFn.fn.functionName,
      principal: 'events.amazonaws.com', sourceArn: rule.attrArn, sourceAccount: Aws.ACCOUNT_ID,
    });
    rulePermission.cfnOptions.condition = sameAccountHandoff;
    // Not an AWS::Lambda::Permission: mixing it with AWS::Lambda::ResourcePolicy on the same
    // function can cause one to silently overwrite the other's statements (AWS::Lambda::
    // ResourcePolicy docs, "Avoid mixing permission resource types"). The same-account rule
    // above uses Permission; the two conditions (SameAccountHandoff / CrossAccountHandoff) are
    // mutually exclusive, so only one resource type ever actually applies to this function in a
    // given deployment, but they still must not be the same resource type to avoid any risk of
    // CloudFormation applying both.
    const crossResourcePolicy = new lambda.CfnResourcePolicy(this, 'CallbackFromAgentSpaceAccount', {
      resourceArn: callbackFn.fn.functionArn,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Sid: 'InvokeFromEventForwarder', Effect: 'Allow',
          Principal: { AWS: `arn:${Aws.PARTITION}:iam::${agentAccountId.valueAsString}:root` },
          Action: 'lambda:InvokeFunction', Resource: callbackFn.fn.functionArn,
          Condition: { ArnEquals: { 'aws:PrincipalArn': forwarderRoleArn } },
        }],
      },
    });
    crossResourcePolicy.cfnOptions.condition = crossAccountHandoff;

    // ── State machine (D§3.2, checker path) ────────────────────────────────
    const invoke = (id: string, fn: lambda.IFunction, payload: sfn.TaskInput, resultPath: string) => {
      const task = new tasks.LambdaInvoke(this, id, {
        lambdaFunction: fn, payload, payloadResponseOnly: true, resultPath, retryOnServiceExceptions: true,
      });
      return task;
    };
    const runId = { run_id: sfn.JsonPath.stringAt('$.init.run_id') };
    // Only errors that can succeed on retry (drift_core/collectors/errors.py). Access denied and
    // other API errors fail fast to the Catch and are reported as "not evaluated" with the cause.
    const transient = ['CollectionThrottled', 'Sandbox.Timedout'];

    const initTask = invoke('Init', init.fn, sfn.TaskInput.fromObject({
      execution_name: sfn.JsonPath.stringAt('$$.Execution.Name'),
      started_at: sfn.JsonPath.stringAt('$$.Execution.StartTime'),
      input: sfn.JsonPath.objectAt('$$.Execution.Input'),
    }), '$.init');

    const cwTask = invoke('CollectCloudWan', collectCloudWan.fn, sfn.TaskInput.fromObject(runId), '$.cloudwan');
    cwTask.addRetry({ errors: transient, interval: Duration.seconds(5), maxAttempts: 3, backoffRate: 2,
      maxDelay: Duration.seconds(60) });
    const cwNotEvaluated = new sfn.Pass(this, 'CloudWanNotEvaluated', {
      parameters: { status: 'error', 'reason.$': '$.cloudwanError.Error' }, resultPath: '$.cloudwan',
    });
    cwTask.addCatch(cwNotEvaluated, { resultPath: '$.cloudwanError' });
    const cwAbsent = new sfn.Pass(this, 'CloudWanAbsent', {
      result: sfn.Result.fromObject({ status: 'absent' }), resultPath: '$.cloudwan',
    });

    const regionTask = new tasks.LambdaInvoke(this, 'CollectRegion', {
      lambdaFunction: collectRegion.fn, payloadResponseOnly: true, retryOnServiceExceptions: true,
    });
    regionTask.addRetry({ errors: transient, interval: Duration.seconds(5), maxAttempts: 5, backoffRate: 2,
      maxDelay: Duration.seconds(60) });
    regionTask.addCatch(new sfn.Pass(this, 'RegionNotEvaluated', {
      parameters: { 'region.$': '$.region', status: 'error', 'reason.$': '$.regionError.Error' },
    }), { resultPath: '$.regionError' });
    const collectRegions = new sfn.Map(this, 'CollectRegions', {
      itemsPath: '$.init.regions', maxConcurrencyPath: '$.init.concurrency', resultPath: '$.regions',
      itemSelector: { 'run_id.$': '$.init.run_id', 'region.$': '$$.Map.Item.Value' },
    });
    collectRegions.itemProcessor(regionTask);

    const evaluateTask = invoke('Evaluate', evaluateFn.fn, sfn.TaskInput.fromObject({
      ...runId, cloudwan: sfn.JsonPath.objectAt('$.cloudwan'), regions: sfn.JsonPath.listAt('$.regions'),
    }), sfn.JsonPath.DISCARD);
    const diffTask = invoke('Diff', diffFn.fn, sfn.TaskInput.fromObject(runId), '$.diff');
    const reportTask = invoke('Report', reportFn.fn, sfn.TaskInput.fromObject({
      ...runId, investigation: sfn.JsonPath.objectAt('$.investigation'),
    }), '$.report');

    // ── Investigation branch (D§3.2, tasks.md 3.4) ─────────────────────────
    const batchTask = invoke('BatchFindings', batchFn.fn, sfn.TaskInput.fromObject(runId), '$.batches');
    const investigateTask = new tasks.LambdaInvoke(this, 'InvestigateBatch', {
      lambdaFunction: investigateFn.fn,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      payload: sfn.TaskInput.fromObject({
        run_id: sfn.JsonPath.stringAt('$.run_id'), batch_n: sfn.JsonPath.numberAt('$.batch_n'),
        batches: sfn.JsonPath.numberAt('$.batches'), task_token: sfn.JsonPath.taskToken,
      }),
      // With waitForTaskToken the task output is the callback's SendTaskSuccess output; it must be
      // kept (not null) or MergeInvestigations sees every batch as failed (tasks.md 3.2 As built).
      resultPath: '$.result',
      taskTimeout: sfn.Timeout.duration(Duration.seconds(investigationTimeout.valueAsNumber)),
      heartbeatTimeout: sfn.Timeout.duration(Duration.seconds(investigationHeartbeat.valueAsNumber)),
      retryOnServiceExceptions: true,
    });
    // Only failures that may succeed on a second POST; config and 4xx errors are terminal.
    investigateTask.addRetry({ errors: ['WebhookServerError', 'WebhookTimeout', 'WebhookTransportError'],
      interval: Duration.seconds(10), maxAttempts: 2, backoffRate: 2 });
    investigateTask.addCatch(new sfn.Pass(this, 'MarkBatchFailed'), { errors: ['States.ALL'], resultPath: '$.error' });
    const investigateBatches = new sfn.Map(this, 'InvestigateBatches', {
      itemsPath: '$.batches.batches', maxConcurrency: investigationConcurrency.valueAsNumber,
      resultPath: '$.investigations',
      itemSelector: { 'run_id.$': '$.init.run_id', 'batch_n.$': '$$.Map.Item.Value.batch_n',
        'batches.$': '$$.Map.Item.Value.batches' },
    });
    investigateBatches.itemProcessor(investigateTask);
    const mergeTask = invoke('MergeInvestigations', mergeFn.fn, sfn.TaskInput.fromObject({
      ...runId, results: sfn.JsonPath.listAt('$.investigations'),
    }), '$.investigation');
    const skipInvestigation = new sfn.Pass(this, 'SkipInvestigation', {
      result: sfn.Result.fromObject({ status: 'skipped' }), resultPath: '$.investigation',
    });
    const handoffChoice = new sfn.Choice(this, 'HasNewAndHandoff?')
      .when(sfn.Condition.and(
        sfn.Condition.booleanEquals('$.init.handoff_enabled', true),
        sfn.Condition.numberGreaterThan('$.diff.new_drift', 0)),
      batchTask.next(investigateBatches).next(mergeTask).next(reportTask))
      .otherwise(skipInvestigation.next(reportTask));
    const publish = new tasks.SnsPublish(this, 'Publish', {
      topic, message: sfn.TaskInput.fromJsonPathAt('$.report.body'),
      subject: sfn.JsonPath.stringAt('$.report.subject'), resultPath: sfn.JsonPath.DISCARD,
    });
    const updateMarker = new tasks.DynamoUpdateItem(this, 'UpdateMarker', {
      table, key: { pk: tasks.DynamoAttributeValue.fromString('META#marker') },
      updateExpression: 'SET last_successful_full_run = :t, run_id = :r',
      expressionAttributeValues: {
        ':t': tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.report.started_at')),
        ':r': tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.init.run_id')),
      },
      resultPath: sfn.JsonPath.DISCARD,
    });
    const done = new sfn.Succeed(this, 'Done');

    for (const s of [cwTask, cwNotEvaluated, cwAbsent]) s.next(collectRegions);
    collectRegions.next(evaluateTask).next(diffTask).next(handoffChoice);
    reportTask.next(publish)
      .next(new sfn.Choice(this, 'AdvanceMarker?')
        .when(sfn.Condition.booleanEquals('$.report.advance_marker', true), updateMarker.next(done))
        .otherwise(done));
    const definition = initTask.next(new sfn.Choice(this, 'HasCloudWan?')
      .when(sfn.Condition.booleanEquals('$.init.collect_cloudwan', true), cwTask)
      .otherwise(cwAbsent));

    const smLogs = new logs.LogGroup(this, 'StateMachineLogs', { removalPolicy: RemovalPolicy.DESTROY });
    (smLogs.node.defaultChild as logs.CfnLogGroup).retentionInDays = logRetentionDays.valueAsNumber;
    const stateMachine = new sfn.StateMachine(this, 'StateMachine', {
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      stateMachineType: sfn.StateMachineType.STANDARD,
      // 30 min checker budget (§14.2) plus four 45-minute investigation batches at concurrency
      // 2 (measured live: one batch took 16.4 min). Each batch has its own timeout; backstop only.
      timeout: Duration.hours(4), tracingEnabled: true,
      logs: { destination: smLogs, level: sfn.LogLevel.ERROR, includeExecutionData: false },
    });
    key.grant(stateMachine, 'kms:Decrypt', 'kms:GenerateDataKey');
    // Scoped to this state machine; verified live in task 3.3/3.14 (D§7.2, D§14 item 5).
    stateMachine.grantTaskResponse(callbackFn.role);

    // ── Schedule (requirements §9.2) ───────────────────────────────────────
    const schedulerRole = new iam.Role(this, 'SchedulerRole', {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com', {
        conditions: { StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID } },
      }),
    });
    stateMachine.grantStartExecution(schedulerRole);
    new scheduler.CfnSchedule(this, 'DailySchedule', {
      description: 'Daily network routing drift check',
      scheduleExpression: scheduleExpression.valueAsString,
      scheduleExpressionTimezone: scheduleTimezone.valueAsString,
      flexibleTimeWindow: { mode: 'OFF' }, state: 'ENABLED',
      target: {
        arn: stateMachine.stateMachineArn, roleArn: schedulerRole.roleArn, input: '{}',
        retryPolicy: { maximumRetryAttempts: 3, maximumEventAgeInSeconds: 3600 },
      },
    });

    // ── Alarms (D§9) → the same topic ──────────────────────────────────────
    const hourly = { period: Duration.hours(1), statistic: 'Sum' };
    const alarmAction = new cwActions.SnsAction(topic);
    const alarms: cloudwatch.Alarm[] = [];
    alarms.push(new cloudwatch.Alarm(this, 'ExecutionFailedAlarm', {
      alarmDescription: 'A drift-check run failed, timed out or was aborted. No report was published for it.',
      metric: new cloudwatch.MathExpression({
        expression: 'f + t + a', period: Duration.hours(1),
        usingMetrics: { f: stateMachine.metricFailed(hourly), t: stateMachine.metricTimedOut(hourly),
          a: stateMachine.metricAborted(hourly) },
      }),
      threshold: 1, evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));
    const missedRun = new cloudwatch.Alarm(this, 'MissedRunAlarm', {
      alarmDescription: 'No drift-check run started in the last 26 hours (assumes a daily schedule).',
      metric: stateMachine.metricStarted(hourly),
      threshold: 1, evaluationPeriods: 26, datapointsToAlarm: 26,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });
    // Wall clock window, not the default sliding window. A sliding alarm searches a wider
    // "evaluation range" and keeps re-using the last REAL datapoint (yesterday's run), so it
    // stayed OK long after 26 silent hours (found live 2026-10-14). A wall clock window reads
    // exactly the last 26 completed clock hours, so 26 hours without a run fills as breaching.
    (missedRun.node.defaultChild as cloudwatch.CfnAlarm).evaluationWindow = { wallClockWindow: { timezone: 'UTC' } };
    alarms.push(missedRun);
    alarms.push(new cloudwatch.Alarm(this, 'RegionsNotEvaluatedAlarm', {
      alarmDescription: 'At least one Region was not evaluated on 3 consecutive daily runs.',
      metric: new cloudwatch.Metric({ namespace: METRIC_NAMESPACE, metricName: 'RegionsNotEvaluated',
        statistic: 'Maximum', period: Duration.days(1) }),
      threshold: 1, evaluationPeriods: 3, datapointsToAlarm: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));
    alarms.push(new cloudwatch.Alarm(this, 'InvestigationFailedAlarm', {
      alarmDescription: 'At least one DevOps Agent investigation batch failed or timed out. The drift report '
        + 'carries the raw findings and the failure reason.',
      metric: new cloudwatch.Metric({ namespace: METRIC_NAMESPACE, metricName: 'InvestigationFailed',
        statistic: 'Sum', period: Duration.hours(1) }),
      threshold: 1, evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));
    alarms.push(new cloudwatch.Alarm(this, 'CallbackDlqMessagesAlarm', {
      alarmDescription: 'A DevOps Agent investigation event could not be processed by the callback after '
        + 'retries. The affected batch will time out; see the callback logs.',
      metric: callbackDlq.metricApproximateNumberOfMessagesVisible({ period: Duration.minutes(5),
        statistic: 'Maximum' }),
      threshold: 1, evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));
    // One error-rate alarm per checker function: alarm math expressions allow at most 10 metrics.
    // The hand-off functions have none: their failures already surface as InvestigationFailed
    // (investigate), ExecutionFailed (batch, merge) or CallbackDlqMessages (callback).
    checkerFns.forEach(({ fn }, i) => {
      alarms.push(new cloudwatch.Alarm(this, `LambdaErrorRateAlarm${i}`, {
        alarmDescription: `More than 5 % of invocations of drift-checker function ${i} failed in an hour.`,
        metric: new cloudwatch.MathExpression({
          expression: '100 * e / i', period: Duration.hours(1),
          usingMetrics: { e: fn.metricErrors(hourly), i: fn.metricInvocations(hourly) },
        }),
        threshold: 5, evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }));
    });
    for (const alarm of alarms) alarm.addAlarmAction(alarmAction);

    new CfnOutput(this, 'ReportTopicArn', { value: topic.topicArn });
    new CfnOutput(this, 'BucketName', { value: bucket.bucketName });
    new CfnOutput(this, 'StateTableName', { value: table.tableName });
    new CfnOutput(this, 'StateMachineArn', { value: stateMachine.stateMachineArn });
    // Inputs for the cross-account companion stack (scripts/deploy.sh, D§3.3a).
    new CfnOutput(this, 'CallbackFunctionArn', { value: callbackFn.fn.functionArn });
    new CfnOutput(this, 'CallbackRoleArn', { value: callbackFn.role.roleArn });
  }
}
