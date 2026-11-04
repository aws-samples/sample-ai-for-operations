// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import * as crypto from "crypto";
import * as path from "path";
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as alarms from "aws-cdk-lib/aws-cloudwatch";
import * as alarmActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as ecrAssets from "aws-cdk-lib/aws-ecr-assets";
import * as s3assets from "aws-cdk-lib/aws-s3-assets";
import * as glue from "aws-cdk-lib/aws-glue";
import * as athena from "aws-cdk-lib/aws-athena";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3n from "aws-cdk-lib/aws-s3-notifications";
import * as scheduler from "aws-cdk-lib/aws-scheduler";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subs from "aws-cdk-lib/aws-sns-subscriptions";
import * as bedrock from "aws-cdk-lib/aws-bedrock";

export interface NetworkFlowInsightProps extends cdk.StackProps {
  /** Existing bucket that holds the VPC Flow Logs (read-only access is granted). */
  flowLogBucketName: string;
  flowLogDatabase: string;
  flowLogTable: string;
  /** Optional customer-managed key that encrypts the flow-log bucket (decrypt is granted). */
  flowLogKmsKeyArn: string;
  modelId: string;
  /** EventBridge Scheduler expression for the describe report; empty disables it. */
  scheduleDescribe: string;
  /** EventBridge Scheduler expression for the drift report; empty disables it. */
  scheduleDrift: string;
  notificationEmail: string;
  /** `container` builds the Dockerfile; `code` deploys infra/dist/runtime.zip (python infra/build_runtime_zip.py). */
  artifact: string;
  /** Optional s3:// URIs (read-only) for the inventory file (provider C), the intent file and a pinned ip-ranges.json. */
  inventoryFile: string;
  intentFile: string;
  ipRangesFile: string;
  /** Name of an AWS Config aggregator in this account and Region (inventory provider B). Empty grants no Config access. */
  configAggregatorName: string;
  /** Tool calls allowed in one agent invocation; empty keeps the code default (60), 0 turns the limit off. */
  maxToolCalls: string;
  /** Seconds one agent invocation may run; empty keeps the code default (780), 0 turns the limit off, at most 800. */
  runDeadlineSeconds: string;
  /** Bytes one Athena query on the agent workgroup may scan before Athena stops it (minimum 10,000,000). */
  athenaBytesScannedCutoff: string;
  owner: string;
  environment: string;
}

const AGENT_DB = "nfi_agent";
const AGENT_WORKGROUP = "nfi-agent";
// The scheduled-run Lambda waits 880 s. The run budget's hard stop comes 60 s after the deadline, so the deadline must
// leave that room.
const MAX_RUN_DEADLINE_SECONDS = 800;
const ATHENA_MIN_BYTES_SCANNED_CUTOFF = 10_000_000;

/** Parse a context value that must be a whole number written in digits; anything else fails synthesis with its name. */
function wholeNumber(name: string, value: string): number {
  if (!/^\d{1,15}$/.test(value)) {
    throw new Error(`${name} must be a whole number written in digits, got "${value}"`);
  }
  return Number(value);
}

export class NetworkFlowInsightStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: NetworkFlowInsightProps) {
    super(scope, id, props);

    cdk.Tags.of(this).add("project", "network-flow-insight");
    cdk.Tags.of(this).add("environment", props.environment);
    cdk.Tags.of(this).add("owner", props.owner);
    cdk.Tags.of(this).add("data-classification", "internal-network-metadata");
    cdk.Tags.of(this).add("agent-managed", "true");

    // ---------------------------------------------------------------- limits (validated first: a bad value fails synthesis)
    const scanCutoff = wholeNumber("athenaBytesScannedCutoff", props.athenaBytesScannedCutoff);
    if (scanCutoff < ATHENA_MIN_BYTES_SCANNED_CUTOFF) {
      throw new Error(`athenaBytesScannedCutoff must be at least ${ATHENA_MIN_BYTES_SCANNED_CUTOFF} bytes (Athena's minimum)`);
    }
    const maxToolCalls = props.maxToolCalls ? wholeNumber("maxToolCalls", props.maxToolCalls) : 0;
    const runDeadline = props.runDeadlineSeconds ? wholeNumber("runDeadlineSeconds", props.runDeadlineSeconds) : 0;
    if (runDeadline > MAX_RUN_DEADLINE_SECONDS) {
      throw new Error(
        `runDeadlineSeconds must be at most ${MAX_RUN_DEADLINE_SECONDS}: the run budget stops 60 s after the deadline and the scheduled-run Lambda waits 880 s`,
      );
    }

    // ---------------------------------------------------------------- agent-managed storage
    const key = new kms.Key(this, "AgentKey", {
      enableKeyRotation: true,
      description: "network-flow-insight reports, aggregates and notifications",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const accessLogs = new s3.Bucket(this, "AccessLogs", {
      encryption: s3.BucketEncryption.S3_MANAGED, // server access log delivery supports SSE-S3 only
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [{ expiration: cdk.Duration.days(90) }],
    });

    const reportBucket = new s3.Bucket(this, "ReportBucket", {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      serverAccessLogsBucket: accessLogs,
      serverAccessLogsPrefix: "report-bucket/",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [
        { prefix: "athena-results/", expiration: cdk.Duration.days(30) },
        { prefix: "nfi/aggregate/", expiration: cdk.Duration.days(90) },
      ],
    });
    const resultsPrefix = "athena-results/";

    const agentDb = new glue.CfnDatabase(this, "AgentDatabase", {
      catalogId: this.account,
      databaseInput: { name: AGENT_DB, description: "network-flow-insight aggregates (agent-managed)", parameters: { "agent-managed": "true" } },
    });

    const workgroup = new athena.CfnWorkGroup(this, "AgentWorkGroup", {
      name: AGENT_WORKGROUP,
      description: "network-flow-insight queries (agent-managed)",
      state: "ENABLED",
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: true,
        // Athena stops a query that scans more than this, whatever the cost gauge estimated. The default is the scan a
        // 5 USD ceiling allows at 5 USD per TB.
        bytesScannedCutoffPerQuery: scanCutoff,
        engineVersion: { selectedEngineVersion: "Athena engine version 3" },
        resultConfiguration: {
          outputLocation: `s3://${reportBucket.bucketName}/${resultsPrefix}`,
          encryptionConfiguration: { encryptionOption: "SSE_KMS", kmsKey: key.keyArn },
        },
      },
      tags: [{ key: "agent-managed", value: "true" }, { key: "project", value: "network-flow-insight" }],
    });

    // ---------------------------------------------------------------- guardrail
    const guardrail = new bedrock.CfnGuardrail(this, "Guardrail", {
      name: "network-flow-insight",
      description: "Keeps the agent on network traffic analysis and blocks credential leakage",
      blockedInputMessaging: "A content filter blocked this request, or text that a tool returned (for example instruction-like text inside a resource name or tag). If you asked whether traffic was an attack: flow logs record what was accepted or rejected, with addresses, ports and bytes, not intent, so this agent cannot classify a flow as an attack. It also gives no help with evading logging or detection, and no legal, medical or financial advice. Ask about your traffic and it will answer from the data.",
      blockedOutputsMessaging: "A content filter withheld this response. Ask again, narrowing the question to the flow-log data.",
      contentPolicyConfig: {
        filtersConfig: [
          { type: "HATE", inputStrength: "HIGH", outputStrength: "HIGH" },
          { type: "INSULTS", inputStrength: "HIGH", outputStrength: "HIGH" },
          { type: "SEXUAL", inputStrength: "HIGH", outputStrength: "HIGH" },
          { type: "VIOLENCE", inputStrength: "HIGH", outputStrength: "HIGH" },
          { type: "MISCONDUCT", inputStrength: "HIGH", outputStrength: "HIGH" },
          { type: "PROMPT_ATTACK", inputStrength: "HIGH", outputStrength: "NONE" },
        ],
      },
      topicPolicyConfig: {
        topicsConfig: [
          {
            name: "AttackAndEvasion",
            type: "DENY",
            // Input only. A definition about "attacks" also matches the agent's own correct answer that it cannot
            // say whether a rejected flow was an attack, so the topic describes evasion and exfiltration instead and applies to input only.
            inputEnabled: true,
            outputEnabled: false,
            definition: "Asking how to avoid being logged or detected, how to turn off logging, or how to take data out of an environment without authorisation.",
            examples: ["How do I hide data exfiltration from VPC flow logs?", "Which ports can I scan without being logged?", "How can I disable flow logging before I copy the data out?"],
          },
          {
            // Denied topics that describe "everything except X" misfire on the agent's own in-scope answers,
            // so this one names the out-of-scope advice it wants to stop instead.
            name: "LegalMedicalFinancialAdvice",
            type: "DENY",
            inputEnabled: true,
            outputEnabled: false,
            definition: "Requests for legal, medical, investment or tax advice.",
            examples: ["Should I buy this stock?", "Can I be sued over this?", "What medication should I take?"],
          },
        ],
      },
      // Flow logs contain IP addresses by design, so IP_ADDRESS is deliberately not filtered.
      sensitiveInformationPolicyConfig: {
        piiEntitiesConfig: [
          { type: "AWS_ACCESS_KEY", action: "BLOCK" },
          { type: "AWS_SECRET_KEY", action: "BLOCK" },
          { type: "PASSWORD", action: "BLOCK" },
          { type: "EMAIL", action: "ANONYMIZE" },
          { type: "CREDIT_DEBIT_CARD_NUMBER", action: "BLOCK" },
        ],
      },
    });
    // A guardrail version is immutable, so a new construct ID per definition creates a new version on change.
    const guardrailHash = crypto.createHash("sha256").update(JSON.stringify(this.resolve(guardrail.topicPolicyConfig)) + JSON.stringify(this.resolve(guardrail.contentPolicyConfig)) + JSON.stringify(this.resolve(guardrail.sensitiveInformationPolicyConfig))).digest("hex").slice(0, 8);
    const guardrailVersion = new bedrock.CfnGuardrailVersion(this, `GuardrailVersion${guardrailHash}`, {
      guardrailIdentifier: guardrail.attrGuardrailId,
      description: "initial",
    });

    // ---------------------------------------------------------------- runtime role (read-only on the estate)
    const role = new iam.Role(this, "RuntimeRole", {
      assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com", {
        conditions: {
          StringEquals: { "aws:SourceAccount": this.account },
          ArnLike: { "aws:SourceArn": `arn:${this.partition}:bedrock-agentcore:${this.region}:${this.account}:*` },
        },
      }),
      description: "network-flow-insight execution role: read-only on the estate, write only to agent-managed resources",
    });

    const flowBucketArn = `arn:${this.partition}:s3:::${props.flowLogBucketName}`;
    // Customer environment: read only.
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ReadFlowLogs", actions: ["s3:GetObject"], resources: [`${flowBucketArn}/*`],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ListFlowLogBucket", actions: ["s3:ListBucket", "s3:GetBucketLocation"], resources: [flowBucketArn],
    }));
    if (props.flowLogKmsKeyArn) {
      role.addToPolicy(new iam.PolicyStatement({ sid: "DecryptFlowLogs", actions: ["kms:Decrypt"], resources: [props.flowLogKmsKeyArn] }));
    }
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ReadGlueCatalog",
      actions: ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions"],
      resources: [
        `arn:${this.partition}:glue:${this.region}:${this.account}:catalog`,
        `arn:${this.partition}:glue:${this.region}:${this.account}:database/*`,
        `arn:${this.partition}:glue:${this.region}:${this.account}:table/*/*`,
      ],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: "RunAthenaQueries",
      actions: ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution", "athena:GetWorkGroup"],
      resources: [`arn:${this.partition}:athena:${this.region}:${this.account}:workgroup/${AGENT_WORKGROUP}`],
    }));
    // Provider A calls exactly these EC2 describe actions (core/inventory/ec2.py; a test keeps the two lists equal).
    // None has an IAM resource type in AWS's published data, so "*" is the only scope AWS accepts for them. The role
    // does not use ec2:Describe*, which would also cover actions that do support resource scoping.
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ReadEc2Inventory",
      actions: [
        "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNatGateways", "ec2:DescribeVpcEndpoints", "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeTransitGatewayAttachments",
      ],
      resources: ["*"],
    }));
    // AWS lists a `dataset` resource type for these two actions, documented for OpenTelemetry metrics (one default dataset
    // per Region). The agent reads classic metrics, and classic reads are not shown to be authorized against a dataset, so
    // a dataset ARN here could silently break the NAT gateway metrics check. They stay on "*" until that is verified.
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ReadGatewayMetrics",
      actions: ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
      resources: ["*"],
    }));
    // The Price List API has no resource types; "*" is required.
    role.addToPolicy(new iam.PolicyStatement({ sid: "ReadPrices", actions: ["pricing:GetProducts"], resources: ["*"] }));
    // Provider A needs this read for gateway-endpoint routes (it is a Get action, not one of the describes above). It
    // supports the prefix-list resource type. The account segment stays open on purpose: the AWS-managed lists (S3 and
    // DynamoDB gateway endpoints) are owned by another account, so an account-scoped ARN would deny them.
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ReadManagedPrefixLists",
      actions: ["ec2:GetManagedPrefixListEntries"],
      resources: [`arn:${this.partition}:ec2:${this.region}:*:prefix-list/*`],
    }));
    // Provider B is optional and only reachable when an AWS Config aggregator exists in this account and Region.
    if (props.configAggregatorName) {
      if (!/^[\w-]{1,256}$/.test(props.configAggregatorName)) {
        throw new Error("configAggregatorName must be 1 to 256 characters of letters, digits, underscore or hyphen");
      }
      role.addToPolicy(new iam.PolicyStatement({
        sid: "QueryConfigAggregator",
        actions: ["config:SelectAggregateResourceConfig"],
        resources: [`arn:${this.partition}:config:${this.region}:${this.account}:config-aggregator/*`],
      }));
    }
    const configFiles = [props.inventoryFile, props.intentFile, props.ipRangesFile].filter((u) => u.startsWith("s3://"));
    if (configFiles.length > 0) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: "ReadConfigFiles", actions: ["s3:GetObject"], resources: configFiles.map((u) => `arn:${this.partition}:s3:::${u.slice(5)}`),
      }));
    }

    // Agent-managed resources: write, scoped by ARN.
    reportBucket.grantReadWrite(role);
    key.grantEncryptDecrypt(role);
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ManageAgentAggregates",
      actions: ["glue:CreateTable", "glue:UpdateTable", "glue:DeleteTable", "glue:BatchCreatePartition", "glue:CreatePartition"],
      resources: [
        `arn:${this.partition}:glue:${this.region}:${this.account}:catalog`,
        `arn:${this.partition}:glue:${this.region}:${this.account}:database/${AGENT_DB}`,
        `arn:${this.partition}:glue:${this.region}:${this.account}:table/${AGENT_DB}/*`,
      ],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: "InvokeApprovedModels",
      actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      resources: [
        `arn:${this.partition}:bedrock:${this.region}:${this.account}:inference-profile/${props.modelId}`,
        `arn:${this.partition}:bedrock:*::foundation-model/${props.modelId.replace(/^(eu|us|global|apac)\./, "")}`,
      ],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: "ApplyGuardrail", actions: ["bedrock:ApplyGuardrail"], resources: [guardrail.attrGuardrailArn],
    }));
    key.addToResourcePolicy(new iam.PolicyStatement({
      actions: ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
      principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      resources: ["*"],
      conditions: { ArnLike: { "kms:EncryptionContext:aws:logs:arn": `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:*` } },
    }));
    // AgentCore Runtime creates and writes /aws/bedrock-agentcore/runtimes/<runtime id>-DEFAULT itself. Declaring that
    // group in this stack fails with AlreadyExists, and the role cannot name it (cycle), so it is scoped to the prefix.
    role.addToPolicy(new iam.PolicyStatement({
      sid: "WriteRuntimeLogs",
      actions: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
      resources: [`arn:${this.partition}:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*`,
                  `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*`],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: "WriteTraces", actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], resources: ["*"],
    }));

    // ---------------------------------------------------------------- container and runtime
    let artifact: Record<string, unknown>;
    let artifactOutput: { id: string; value: string };
    if (props.artifact === "code") {
      const zip = path.join(__dirname, "..", "dist", "runtime.zip");
      const code = new s3assets.Asset(this, "AgentCode", { path: zip });
      code.grantRead(role);
      artifact = {
        CodeConfiguration: {
          Code: { S3: { Bucket: code.s3BucketName, Prefix: code.s3ObjectKey } },
          EntryPoint: ["main.py"],
          Runtime: "PYTHON_3_12",
        },
      };
      artifactOutput = { id: "CodeLocation", value: code.s3ObjectUrl };
    } else {
      const image = new ecrAssets.DockerImageAsset(this, "AgentImage", {
        directory: path.join(__dirname, "..", ".."),
        file: "Dockerfile",
        platform: ecrAssets.Platform.LINUX_ARM64,
        exclude: ["infra", ".git", ".kiro", ".venv", "reports", "tests", "node_modules", "cdk.out", "**/__pycache__"],
      });
      image.repository.grantPull(role);
      artifact = { ContainerConfiguration: { ContainerUri: image.imageUri } };
      artifactOutput = { id: "ImageUri", value: image.imageUri };
    }

    // Amazon Bedrock AgentCore Runtime is declared with the CloudFormation resource type directly so the
    // stack does not depend on a particular aws-cdk-lib minor version having an L1 for it. If the resource
    // is not yet available in the target Region, deploy the role, bucket and guardrail from this stack and
    // create the runtime with `agentcore deploy`, pointing it at the role and image in the stack outputs.
    const runtime = new cdk.CfnResource(this, "Runtime", {
      type: "AWS::BedrockAgentCore::Runtime",
      properties: {
        // The artifact type of a runtime cannot be changed in place, so each type gets its own name and a switch replaces the runtime.
        AgentRuntimeName: props.artifact === "code" ? "network_flow_insight_code" : "network_flow_insight_container",
        Description: "network-flow-insight agent",
        RoleArn: role.roleArn,
        AgentRuntimeArtifact: artifact,
        NetworkConfiguration: { NetworkMode: "PUBLIC" },
        EnvironmentVariables: {
          NFI_AWS_REGION: this.region,
          BEDROCK_REGION: this.region,
          BEDROCK_MODEL_ID: props.modelId,
          GUARDRAIL_ID: guardrail.attrGuardrailId,
          GUARDRAIL_VERSION: guardrailVersion.attrVersion,
          NFI_FLOW_LOG_BUCKET: props.flowLogBucketName,
          NFI_FLOW_LOG_DATABASE: props.flowLogDatabase,
          NFI_FLOW_LOG_TABLE: props.flowLogTable,
          NFI_ATHENA_WORKGROUP: AGENT_WORKGROUP,
          NFI_ATHENA_RESULTS_LOCATION: `s3://${reportBucket.bucketName}/${resultsPrefix}`,
          NFI_AGENT_DATABASE: AGENT_DB,
          NFI_REPORT_BUCKET: reportBucket.bucketName,
          ...(props.inventoryFile ? { NFI_INVENTORY_FILE: props.inventoryFile } : {}),
          ...(props.intentFile ? { NFI_INTENT_FILE: props.intentFile } : {}),
          ...(props.ipRangesFile ? { NFI_IP_RANGES_FILE: props.ipRangesFile } : {}),
          ...(props.configAggregatorName ? { NFI_CONFIG_AGGREGATOR: props.configAggregatorName } : {}),
          ...(props.maxToolCalls ? { NFI_MAX_TOOL_CALLS: String(maxToolCalls) } : {}),
          ...(props.runDeadlineSeconds ? { NFI_RUN_DEADLINE_SECONDS: String(runDeadline) } : {}),
        },
        Tags: { project: "network-flow-insight", "agent-managed": "true" },
      },
    });
    runtime.node.addDependency(role);
    runtime.node.addDependency(agentDb);
    runtime.node.addDependency(workgroup);
    const runtimeArn = runtime.getAtt("AgentRuntimeArn").toString();


    // ---------------------------------------------------------------- notification, schedule, alarms
    const topic = new sns.Topic(this, "ReportTopic", { masterKey: key, displayName: "network-flow-insight reports and alarms" });
    key.addToResourcePolicy(new iam.PolicyStatement({
      actions: ["kms:GenerateDataKey*", "kms:Decrypt"],
      principals: [new iam.ServicePrincipal("s3.amazonaws.com"), new iam.ServicePrincipal("cloudwatch.amazonaws.com")],
      resources: ["*"],
      conditions: { StringEquals: { "aws:SourceAccount": this.account } },
    }));
    if (props.notificationEmail) {
      topic.addSubscription(new subs.EmailSubscription(props.notificationEmail));
    }
    reportBucket.addEventNotification(s3.EventType.OBJECT_CREATED, new s3n.SnsDestination(topic), { prefix: "reports/", suffix: "report.md" });

    const invoker = new lambda.Function(this, "Invoker", {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: "invoker.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "lambda")),
      timeout: cdk.Duration.minutes(15),
      tracing: lambda.Tracing.ACTIVE,
      environment: { RUNTIME_ARN: runtimeArn },
      // A failed run must raise the alarm, not start a second full agent run, so asynchronous retries are off.
      retryAttempts: 0,
      logGroup: new logs.LogGroup(this, "InvokerLogs", { retention: logs.RetentionDays.THREE_MONTHS, encryptionKey: key, removalPolicy: cdk.RemovalPolicy.RETAIN }),
      description: "Calls InvokeAgentRuntime with the scheduled payload and fails when the runtime reports a failure",
    });
    invoker.addToRolePolicy(new iam.PolicyStatement({
      sid: "InvokeRuntime",
      actions: ["bedrock-agentcore:InvokeAgentRuntime"],
      resources: [runtimeArn, `${runtimeArn}/runtime-endpoint/*`],
    }));

    const schedulerRole = new iam.Role(this, "SchedulerRole", { assumedBy: new iam.ServicePrincipal("scheduler.amazonaws.com", {
      conditions: { StringEquals: { "aws:SourceAccount": this.account } } }) });
    invoker.grantInvoke(schedulerRole);
    const addSchedule = (name: string, expr: string, mode: string): void => {
      if (!expr) return;
      new scheduler.CfnSchedule(this, `Schedule${name}`, {
        name: `nfi-${mode}`,
        scheduleExpression: expr,
        flexibleTimeWindow: { mode: "OFF" },
        target: { arn: invoker.functionArn, roleArn: schedulerRole.roleArn, input: JSON.stringify({ mode }) },
      });
    };
    addSchedule("Describe", props.scheduleDescribe, "describe");
    addSchedule("Drift", props.scheduleDrift, "drift");

    const errorAlarm = invoker.metricErrors({ period: cdk.Duration.minutes(5) }).createAlarm(this, "InvokerErrors", {
      threshold: 1, evaluationPeriods: 1, alarmDescription: "Scheduled network-flow-insight invocation failed",
      treatMissingData: alarms.TreatMissingData.NOT_BREACHING,
    });
    const latencyAlarm = invoker.metricDuration({ period: cdk.Duration.minutes(5), statistic: "p99" }).createAlarm(this, "InvokerLatencyP99", {
      threshold: cdk.Duration.minutes(12).toMilliseconds(), evaluationPeriods: 1,
      alarmDescription: "Scheduled run approaching the 15 minute limit", treatMissingData: alarms.TreatMissingData.NOT_BREACHING,
    });

    for (const a of [errorAlarm, latencyAlarm]) {
      a.addAlarmAction(new alarmActions.SnsAction(topic));
    }

    // ---------------------------------------------------------------- outputs
    new cdk.CfnOutput(this, "RuntimeArn", { value: runtimeArn });
    new cdk.CfnOutput(this, "RuntimeRoleArn", { value: role.roleArn });
    new cdk.CfnOutput(this, artifactOutput.id, { value: artifactOutput.value });
    new cdk.CfnOutput(this, "ReportBucketName", { value: reportBucket.bucketName });
    new cdk.CfnOutput(this, "GuardrailIdOut", { value: guardrail.attrGuardrailId });
    new cdk.CfnOutput(this, "GuardrailVersionOut", { value: guardrailVersion.attrVersion });
    new cdk.CfnOutput(this, "AthenaWorkGroup", { value: AGENT_WORKGROUP });
  }
}
