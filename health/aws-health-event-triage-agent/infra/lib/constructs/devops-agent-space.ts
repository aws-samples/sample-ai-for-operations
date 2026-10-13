// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * DevOpsAgentSpace — a reusable construct that provisions a complete,
 * ready-to-use AWS DevOps Agent Agent Space:
 *
 *   1. AgentSpaceRole  — assumed by the DevOps Agent service to monitor the
 *                        account (AIDevOpsAgentAccessPolicy + Resource
 *                        Explorer SLR creation)
 *   2. OperatorRole    — assumed for the operator app / web console
 *                        (AIDevOpsOperatorAppAccessPolicy)
 *   3. Agent Space     — AWS::DevOpsAgent::AgentSpace, operator app enabled
 *                        (IAM auth)
 *   4. AWS association — AWS::DevOpsAgent::Association (accountType
 *                        "monitor"), wiring the account's resources into
 *                        the space's topology
 *   5. Webhook         — a generic eventChannel webhook for triggering
 *                        investigations, provisioned by a Lambda-backed
 *                        custom resource (see devops-agent-webhook-provisioner)
 *
 * Ported from the canonical reference implementation
 * (aws-samples/sample-aws-genai-ops-demos,
 * observability/proactive-health-event-impact-analyzer,
 * lib/constructs/devops-agent-space.ts) per this working spec's
 * confirmation gate (see the master spec's design.md §6, Identity and access).
 *
 * Why the webhook needs a custom resource
 * ---------------------------------------
 * Confirmed directly against the installed aws-cdk-lib@2.271.0
 * AWS::DevOpsAgent::* L1 constructs during Build: AWS::DevOpsAgent::Service
 * has no eventChannel entry in its ServiceDetailsProperty union (so
 * RegisterService(eventChannel) cannot be expressed in CloudFormation), and
 * AWS::DevOpsAgent::Association exposes only attrAssociationId /
 * attrCreatedAt / attrUpdatedAt as CloudFormation attributes — no
 * webhookUrl or webhookSecret attribute exists, and the webhook's HMAC
 * secret is returned ONLY in the AssociateService SDK call's create
 * response; no Describe/List API ever returns it again. The custom
 * resource performs RegisterService(eventChannel) + AssociateService at
 * deploy time, writes the secret straight into a Secrets Manager secret
 * (it never enters CloudFormation state or outputs), and returns only the
 * webhook URL.
 *
 * Any property change on the custom resource rotates the webhook
 * (replacement = delete + recreate), which is the only correct behavior
 * given the secret cannot be re-read.
 *
 * Skill and AGENTS.md deployment is NOT automated (confirmed 2026-09-28,
 * working spec feat-devops-agent-enrichment, task 9, design §9.1's
 * "verify, never invent API shapes" rule)
 * ------------------------------------------------------------------------
 * Design §9.1 asked whether CreateAsset (skill zip, agents_md) exists in
 * the installed boto3 devops-agent service model, to decide whether
 * task 10's re-targeted skill and new AGENTS.md file could be wired into
 * this construct's provisioner Lambda automatically. Checked directly
 * against the real model file (botocore 1.43.103's
 * botocore/data/devops-agent/2026-01-01/service-2.json), not inferred:
 * the model has 44 operations total (AssociateService, CreateAgentSpace,
 * RegisterService, ListJournalRecords, etc.) and NONE of them relate to
 * "asset," "skill," or "AgentsMd" upload in any form — CreateAsset does
 * not exist. Confirmed the same result via boto3.client("devops-agent")
 * .meta.service_model.operation_names, independently.
 *
 * The fallback per design §9.1 applies: deploying
 * devops-agent-skill/SKILL.md and devops-agent-skill/agents-md/
 * AGENTS-incident-triage.md onto a real Agent Space is a documented,
 * one-time manual step (see QUICKSTART.md Step 4.1), not a guessed
 * CDK/custom-resource integration.
 *
 * UPDATE (2026-09-29): the premise above is now stale — CreateAsset DOES
 * exist as of a newer boto3/botocore (confirmed live: 1.43.104 has 63
 * devops-agent operations including the full Asset family, versus 44 with
 * no asset ops on the version this comment originally checked), and
 * AWS::DevOpsAgent::Asset is a real CloudFormation resource
 * (aws-cdk-lib's CfnAsset/CfnAssetProps). Automating this via CfnAsset is a
 * reasonable future improvement to this construct; it isn't built yet, so
 * QUICKSTART.md Step 4.1 remains the manual fallback.
 *
 * This construct also only ever associates ONE account (monitorAccountId,
 * defaulting to the deploying account) as the Agent Space's "monitor"
 * account. Connecting additional "source" accounts for cross-account
 * investigation is a separate, currently manual, per-account AWS-side
 * operation with no CDK automation in this repo — see QUICKSTART.md
 * Step 7.4 for the full procedure and why it can't be a CDK stack here
 * (the role AWS DevOps Agent assumes must live IN the target account,
 * which this construct's own stack never deploys into).
 */
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda-nodejs';
import * as lambdaBase from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as devopsagent from 'aws-cdk-lib/aws-devopsagent';
import { Construct } from 'constructs';
import * as path from 'path';

export interface DevOpsAgentSpaceProps {
  /** Agent Space name. Also used as the prefix for the two IAM role names. */
  readonly name: string;

  /** Human-readable description shown in the DevOps Agent console. */
  readonly description?: string;

  /**
   * Deployment environment — drives the webhook provisioner Lambda's log
   * retention (production=90d, non-production=14d), matching the
   * repo-wide convention of longer retention for production.
   */
  readonly deployEnvironment: string;

  /**
   * AWS account to associate for monitoring. Defaults to the containing
   * stack's account. The DevOps Agent discovers and maps resources across
   * ALL regions of this account — no per-region association is needed.
   */
  readonly monitorAccountId?: string;

  /**
   * Enable the operator app (web console, IAM auth). Default: true.
   */
  readonly enableOperatorApp?: boolean;

  /**
   * Provision the generic eventChannel webhook (URL + HMAC secret in
   * Secrets Manager). Default: true.
   */
  readonly enableWebhook?: boolean;

  /**
   * Phase A (working spec feat-devops-agent-enrichment, req E7 / design
   * §3.6, task 9): the S3 event-snapshot bucket (CoreStack.
   * eventSnapshotBucket). When supplied, agentSpaceRole is granted
   * s3:GetObject on the bucket's events/* prefix, so the investigating
   * agent can read the full consolidated event beyond what the webhook's
   * title/description fields carry. Undefined (the default) grants
   * nothing — a caller that doesn't wire enrichment yet (or is still on
   * an older working spec) gets exactly today's role, unchanged.
   */
  readonly eventSnapshotBucketArn?: string;
}

export class DevOpsAgentSpace extends Construct {
  /** The underlying AWS::DevOpsAgent::AgentSpace resource. */
  public readonly agentSpace: devopsagent.CfnAgentSpace;
  /** Agent Space ID (CFN token). */
  public readonly agentSpaceId: string;
  /** Agent Space ARN (CFN token). */
  public readonly agentSpaceArn: string;
  /** Monitoring role the DevOps Agent assumes to inspect the account. */
  public readonly agentSpaceRole: iam.Role;
  /** Operator app (web console) role. */
  public readonly operatorRole: iam.Role;
  /**
   * Webhook URL for triggering investigations (CFN token).
   * Empty string when `enableWebhook` is false.
   */
  public readonly webhookUrl: string;
  /**
   * Secrets Manager secret holding the webhook HMAC secret. The value is
   * written by the provisioner Lambda during deployment — it never passes
   * through CloudFormation parameters, outputs, or resource state.
   * Undefined when `enableWebhook` is false.
   */
  public readonly webhookSecret?: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: DevOpsAgentSpaceProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);
    const monitorAccountId = props.monitorAccountId ?? stack.account;
    const enableOperatorApp = props.enableOperatorApp ?? true;
    const enableWebhook = props.enableWebhook ?? true;

    // ─── Trust policy shared by both roles ─────────────────────────────────
    // aidevops.amazonaws.com, scoped to this account and to Agent Spaces in
    // this region (ArnLike on aws:SourceArn).
    const aidevopsTrustConditions = {
      StringEquals: { 'aws:SourceAccount': stack.account },
      ArnLike: {
        'aws:SourceArn': `arn:${stack.partition}:aidevops:${stack.region}:${stack.account}:agentspace/*`,
      },
    };
    const aidevopsTrust = () =>
      new iam.ServicePrincipal('aidevops.amazonaws.com').withConditions(aidevopsTrustConditions);
    const addTagSessionTrust = (role: iam.Role) => {
      role.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:TagSession'],
        principals: [aidevopsTrust()],
      }));
    };

    // ─── 1. Monitoring role ────────────────────────────────────────────────
    this.agentSpaceRole = new iam.Role(this, 'AgentSpaceRole', {
      roleName: `${props.name}-AgentSpaceRole`,
      assumedBy: aidevopsTrust(),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AIDevOpsAgentAccessPolicy'),
      ],
      description: `Monitoring role assumed by AWS DevOps Agent for Agent Space '${props.name}'`,
    });
    addTagSessionTrust(this.agentSpaceRole);

    // The agent creates the Resource Explorer service-linked role on first
    // topology discovery. Scoped to SLR paths only.
    this.agentSpaceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCreateServiceLinkedRoles',
      effect: iam.Effect.ALLOW,
      actions: ['iam:CreateServiceLinkedRole'],
      resources: [`arn:${stack.partition}:iam::${stack.account}:role/aws-service-role/*`],
    }));

    // Task 9 (req E7 / design §3.6): s3:GetObject on the event-snapshot
    // bucket's events/* prefix only — never the whole bucket, and never
    // any other action (this is a read-only grant; the agent never writes
    // here). This is an agent-internal resource per iam-permission-
    // boundary (the bucket belongs to this solution's own CoreStack, not
    // a customer resource), so granting read access to the investigating
    // role is within the default permission boundary.
    if (props.eventSnapshotBucketArn) {
      this.agentSpaceRole.addToPolicy(new iam.PolicyStatement({
        sid: 'AllowReadEventSnapshots',
        effect: iam.Effect.ALLOW,
        actions: ['s3:GetObject'],
        resources: [`${props.eventSnapshotBucketArn}/events/*`],
      }));
    }

    // ─── 2. Operator app role ──────────────────────────────────────────────
    this.operatorRole = new iam.Role(this, 'OperatorRole', {
      roleName: `${props.name}-OperatorRole`,
      assumedBy: aidevopsTrust(),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AIDevOpsOperatorAppAccessPolicy'),
      ],
      description: `Operator app (web console) role for Agent Space '${props.name}'`,
    });
    addTagSessionTrust(this.operatorRole);

    // ─── 3. Agent Space ────────────────────────────────────────────────────
    this.agentSpace = new devopsagent.CfnAgentSpace(this, 'AgentSpace', {
      name: props.name,
      description: props.description,
      ...(enableOperatorApp ? {
        operatorApp: {
          iam: { operatorAppRoleArn: this.operatorRole.roleArn },
        },
      } : {}),
    });
    // Roles (and their policies) must be fully in place first: the service
    // validates assumability during resource creation, and IAM is
    // eventually consistent.
    this.agentSpace.node.addDependency(this.agentSpaceRole);
    this.agentSpace.node.addDependency(this.operatorRole);

    this.agentSpaceId = this.agentSpace.attrAgentSpaceId;
    this.agentSpaceArn = this.agentSpace.attrArn;

    // ─── 4. AWS account association (monitor) ──────────────────────────────
    const awsAssociation = new devopsagent.CfnAssociation(this, 'AwsMonitorAssociation', {
      agentSpaceId: this.agentSpaceId,
      // For Aws/SourceAws configurations the service id is the literal "aws".
      serviceId: 'aws',
      configuration: {
        aws: {
          accountId: monitorAccountId,
          accountType: 'monitor',
          assumableRoleArn: this.agentSpaceRole.roleArn,
        },
      },
    });
    awsAssociation.node.addDependency(this.agentSpaceRole);

    // ─── 5. Webhook (custom resource) ──────────────────────────────────────
    if (!enableWebhook) {
      this.webhookUrl = '';
      return;
    }

    // Holds the HMAC secret. No explicit name: avoids collisions with
    // scheduled-deletion name retention on destroy/redeploy cycles.
    this.webhookSecret = new secretsmanager.Secret(this, 'WebhookSecret', {
      description: `DevOps Agent webhook HMAC secret for Agent Space '${props.name}'`,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const provisionerFn = new lambda.NodejsFunction(this, 'WebhookProvisioner', {
      runtime: lambdaBase.Runtime.NODEJS_22_X,
      entry: path.join(__dirname, '..', '..', 'lambda', 'devops-agent-webhook-provisioner', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.minutes(2),
      description: 'Custom resource: provisions the DevOps Agent eventChannel webhook and stores its HMAC secret in Secrets Manager',
      bundling: {
        // Bundle the SDK clients into the artifact rather than leaving them
        // external, since the newer devops-agent client is not guaranteed
        // to ship with the Lambda runtime's own AWS SDK bundle.
        externalModules: [],
        minify: true,
      },
      logGroup: new logs.LogGroup(this, 'WebhookProvisionerLogs', {
        retention: props.deployEnvironment === 'production'
          ? logs.RetentionDays.THREE_MONTHS
          : logs.RetentionDays.TWO_WEEKS,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });

    // RegisterService/ListServices are account-scoped calls without a
    // resource ARN in their request; AssociateService/DisassociateService
    // target the space and a generated service id. The aidevops
    // resource-level scoping for these registration APIs is not
    // documented, so this statement uses '*' with the actions enumerated
    // tightly — see SECURITY.md's Phase 1b addendum for the documented
    // exception rationale.
    provisionerFn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'DevOpsAgentWebhookLifecycle',
      effect: iam.Effect.ALLOW,
      actions: [
        'aidevops:RegisterService',
        'aidevops:ListServices',
        'aidevops:AssociateService',
        'aidevops:DisassociateService',
        'aidevops:ListAssociations',
      ],
      resources: ['*'],
    }));
    this.webhookSecret.grantWrite(provisionerFn);

    const webhook = new cdk.CustomResource(this, 'Webhook', {
      resourceType: 'Custom::DevOpsAgentWebhook',
      serviceToken: provisionerFn.functionArn,
      properties: {
        AgentSpaceId: this.agentSpaceId,
        SecretArn: this.webhookSecret.secretArn,
      },
    });
    webhook.node.addDependency(this.agentSpace);

    this.webhookUrl = webhook.getAttString('WebhookUrl');
  }
}
