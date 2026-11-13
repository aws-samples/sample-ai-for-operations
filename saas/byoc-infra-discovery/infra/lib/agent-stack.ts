// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.
import * as path from 'path';
import * as fs from 'fs';
import { execFileSync } from 'child_process';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';

/**
 * BYOC Infrastructure Discovery Agent stack.
 *
 * Provisions a read-only, Amazon Bedrock-backed AWS Lambda agent plus an
 * Amazon Bedrock Guardrail, structured logging, X-Ray tracing, and alarms.
 */
export class AgentStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Configurable via CDK context (cdk deploy -c modelId=...).
    // Current Claude models on Amazon Bedrock are invoked through a
    // region-prefixed inference profile (e.g. "us.anthropic.claude-..."),
    // NOT the bare on-demand model id (which returns ValidationException).
    const modelId =
      this.node.tryGetContext('modelId') ??
      'us.anthropic.claude-sonnet-4-5-20250929-v1:0';
    const bedrockRegion = this.node.tryGetContext('bedrockRegion') ?? 'us-east-1';
    const cacheTtlSeconds = this.node.tryGetContext('cacheTtlSeconds') ?? '3600';

    // An inference-profile id ("us.anthropic...", "global.anthropic...") routes
    // to an underlying foundation model; the role must be allowed to invoke
    // both the profile and the foundation model it fans out to. Strip the
    // region prefix to recover the foundation-model id.
    const inferenceProfilePrefix = /^(us|eu|apac|global)\./;
    const foundationModelId = modelId.replace(inferenceProfilePrefix, '');
    const isInferenceProfile = inferenceProfilePrefix.test(modelId);

    // --- Amazon Bedrock Guardrail (content filtering at the model) ---
    // Always created; there is no context flag to skip it. Its id and version
    // are injected as GUARDRAIL_ID / GUARDRAIL_VERSION below, so every deployed
    // function invokes the model through this guardrail. Only content filters
    // are configured: no prompt-attack filter, denied topics, or
    // sensitive-information (PII) policy. Add those before production if your
    // use case needs them (see README "Scope and limitations").
    const guardrail = new bedrock.CfnGuardrail(this, 'AgentGuardrail', {
      name: 'byoc-infra-discovery-guardrail',
      blockedInputMessaging: 'This request cannot be processed.',
      blockedOutputsMessaging: 'This response cannot be provided.',
      contentPolicyConfig: {
        filtersConfig: [
          { type: 'HATE', inputStrength: 'HIGH', outputStrength: 'HIGH' },
          { type: 'INSULTS', inputStrength: 'HIGH', outputStrength: 'HIGH' },
          { type: 'SEXUAL', inputStrength: 'HIGH', outputStrength: 'HIGH' },
          { type: 'VIOLENCE', inputStrength: 'HIGH', outputStrength: 'HIGH' },
          { type: 'MISCONDUCT', inputStrength: 'HIGH', outputStrength: 'HIGH' },
        ],
      },
    });
    const guardrailVersion = new bedrock.CfnGuardrailVersion(
      this,
      'AgentGuardrailVersion',
      { guardrailIdentifier: guardrail.attrGuardrailId },
    );

    // --- Log group (structured JSON), retained for audit ---
    const logGroup = new logs.LogGroup(this, 'AgentLogGroup', {
      logGroupName: '/aws/lambda/byoc-infra-discovery',
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // --- Read-only execution role (no mutating actions anywhere) ---
    const role = new iam.Role(this, 'AgentExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Read-only role for the BYOC Infrastructure Discovery Agent',
    });

    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadGlobalInfrastructureParameters',
        actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath'],
        resources: ['arn:aws:ssm:*::parameter/aws/service/global-infrastructure/*'],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadPublicAmiParameters',
        actions: ['ssm:GetParameter', 'ssm:GetParameters'],
        resources: ['arn:aws:ssm:*::parameter/aws/service/*'],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadPricing',
        actions: ['pricing:GetProducts'],
        resources: ['*'], // Pricing API does not support resource-level scoping (read-only).
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'DescribeReadOnlyEc2',
        actions: [
          'ec2:DescribeRegions',
          'ec2:DescribeAvailabilityZones',
          'ec2:DescribeInstanceTypes',
          'ec2:DescribeInstanceTypeOfferings',
          'ec2:DescribeImages',
        ],
        resources: ['*'], // EC2 Describe* do not support resource-level scoping (read-only).
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'InvokeBedrockModel',
        actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
        resources: [
          // The underlying foundation model, in any region the profile routes to.
          `arn:aws:bedrock:*::foundation-model/${foundationModelId}`,
          // The inference profile itself (account-scoped), when one is used.
          ...(isInferenceProfile
            ? [`arn:aws:bedrock:*:${this.account}:inference-profile/${modelId}`]
            : []),
        ],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ApplyGuardrail',
        actions: ['bedrock:ApplyGuardrail'],
        resources: [guardrail.attrGuardrailArn],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'WriteOwnLogs',
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [logGroup.logGroupArn, `${logGroup.logGroupArn}:*`],
      }),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'XRayTracing',
        actions: ['xray:PutTraceSegments', 'xray:PutTelemetryRecords'],
        resources: ['*'], // X-Ray requires wildcard (telemetry, non-mutating to customer resources).
      }),
    );

    // --- Lambda function (Python 3.12, ARM64) ---
    const fn = new lambda.Function(this, 'AgentFunction', {
      functionName: 'byoc-infra-discovery',
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: 'handler.handler',
      role,
      logGroup,
      timeout: cdk.Duration.seconds(60),
      memorySize: 512,
      tracing: lambda.Tracing.ACTIVE,
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..'), {
        // Bundle src/ plus dependencies into the deployment package. Prefer a
        // local build (no Docker required); fall back to the container image.
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          command: [
            'bash',
            '-c',
            [
              'pip install -r requirements.txt -t /asset-output',
              'cp -r src/* /asset-output/',
            ].join(' && '),
          ],
          local: {
            tryBundle(outputDir: string): boolean {
              // Dependencies include native extensions (pydantic_core) that
              // MUST match the Lambda runtime (Linux, aarch64). Install the
              // manylinux aarch64 wheels explicitly so a macOS/x86 build host
              // never ships a wrong-platform binary. If the Linux-targeted
              // install cannot be satisfied, return false to fall back to the
              // Docker bundler (which builds inside a Linux image).
              try {
                const projectRoot = path.join(__dirname, '..', '..');
                const venvPip = path.join(projectRoot, '.venv', 'bin', 'pip');
                // Invoke pip WITHOUT a shell: pass the executable and its
                // arguments as a fixed array so outputDir is never interpolated
                // into a shell command string (no command-injection surface).
                const [pipFile, pipPrefixArgs] = fs.existsSync(venvPip)
                  ? [venvPip, [] as string[]]
                  : ['python3', ['-m', 'pip']];
                execFileSync(
                  pipFile,
                  [
                    ...pipPrefixArgs,
                    'install',
                    '-r',
                    'requirements.txt',
                    '--platform',
                    'manylinux2014_aarch64',
                    '--implementation',
                    'cp',
                    '--python-version',
                    '3.12',
                    '--only-binary=:all:',
                    '--target',
                    outputDir,
                  ],
                  { cwd: projectRoot, stdio: 'inherit' },
                );
                // Copy src/ into the bundle with Node's fs instead of chaining a
                // shell `cp`, so no user/arg-controlled value reaches a shell.
                fs.cpSync(path.join(projectRoot, 'src'), outputDir, {
                  recursive: true,
                });
                return true;
              } catch {
                // Fall back to Docker bundling (Linux image => correct binaries).
                return false;
              }
            },
          },
        },
      }),
      environment: {
        BEDROCK_MODEL_ID: modelId,
        BEDROCK_REGION: bedrockRegion,
        GUARDRAIL_ID: guardrail.attrGuardrailId,
        GUARDRAIL_VERSION: guardrailVersion.attrVersion,
        CACHE_TTL_SECONDS: String(cacheTtlSeconds),
        LOG_LEVEL: 'INFO',
      },
    });

    // --- CloudWatch alarms ---
    new cloudwatch.Alarm(this, 'ErrorRateAlarm', {
      alarmDescription: 'Agent error rate exceeds 5% over 5 minutes',
      metric: new cloudwatch.MathExpression({
        expression: '(errors / invocations) * 100',
        usingMetrics: {
          errors: fn.metricErrors({ period: cdk.Duration.minutes(5) }),
          invocations: fn.metricInvocations({ period: cdk.Duration.minutes(5) }),
        },
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    new cloudwatch.Alarm(this, 'P99LatencyAlarm', {
      alarmDescription: 'Agent P99 latency exceeds 30 seconds',
      metric: fn.metricDuration({
        period: cdk.Duration.minutes(5),
        statistic: 'p99',
      }),
      threshold: 30000,
      evaluationPeriods: 3,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    new cdk.CfnOutput(this, 'FunctionName', { value: fn.functionName });
    new cdk.CfnOutput(this, 'GuardrailId', { value: guardrail.attrGuardrailId });
  }
}
