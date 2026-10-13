// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
/**
 * GuardrailStack — provisions an Amazon Bedrock Guardrail for the triage agent.
 *
 * The guardrail enables:
 *  - Content filters (hate, insults, sexual, violence, misconduct) — all HIGH sensitivity
 *  - PII anonymization (redact, not block) for account IDs and email addresses
 *  - Denied topic: "remediation without human approval"
 *
 * The Guardrail ID and version are exported as CfnOutputs and SSM parameters
 * so the agent's compute layer (Lambda / ECS) can reference them at runtime.
 */

import * as crypto from 'crypto';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as kms from 'aws-cdk-lib/aws-kms';

export interface GuardrailStackProps extends cdk.StackProps {
  readonly projectName: string;
  /** KMS key from CoreStack (used to encrypt SSM parameters) */
  readonly kmsKey: kms.Key;
}

export class GuardrailStack extends cdk.Stack {
  public readonly guardrailId: string;
  public readonly guardrailVersion: string;
  /**
   * The guardrail's ARN (not version-specific — Bedrock guardrail ARNs are
   * per-guardrail; the version is a separate parameter on ApplyGuardrail/
   * InvokeModel calls). Exposed so callers can scope a `bedrock:ApplyGuardrail`
   * IAM grant to this exact resource instead of a wildcard.
   */
  public readonly guardrailArn: string;
  /**
   * fix-guardrail-topic-false-positives: the destination-Region
   * `guardrail-profile` ARNs the `eu.guardrail.v1:0` cross-Region profile
   * can route this guardrail's STANDARD-tier topic evaluation to, given
   * this stack's own Region (eu-west-1) as the source. Cross-Region
   * inference needs `bedrock:ApplyGuardrail` on the guardrail itself PLUS
   * every one of these — never a wildcard (security-policies.md) — so
   * callers scope their grant to `[this.guardrailArn,
   * ...this.guardrailProfileDestinationRegionArns]` instead of guessing
   * the profile's Region set themselves.
   */
  public readonly guardrailProfileDestinationRegionArns: string[];

  constructor(scope: Construct, id: string, props: GuardrailStackProps) {
    super(scope, id, props);

    const { projectName } = props;

    // -----------------------------------------------------------------------
    // Amazon Bedrock Guardrail
    // -----------------------------------------------------------------------
    //
    // Every policy piece below is defined as a plain literal constant
    // BEFORE being passed into CfnGuardrail, and the exact same constants
    // (not `guardrail.<prop>` read back off the L1 construct afterward)
    // feed the content-hash below that guards HealthTriageGuardrailVersion.
    // This is deliberate, not stylistic — see that hash's own comment for
    // why reading properties back off the construct is unsafe here.
    const blockedInputMessaging =
      'This request contains content that cannot be processed by the triage agent.';
    const blockedOutputsMessaging =
      'The agent response was blocked by content safety controls.';

    // Content filters — HIGH sensitivity for all categories
    const contentFilters = [
      { type: 'HATE', inputStrength: 'HIGH', outputStrength: 'HIGH' },
      { type: 'INSULTS', inputStrength: 'HIGH', outputStrength: 'HIGH' },
      { type: 'SEXUAL', inputStrength: 'HIGH', outputStrength: 'HIGH' },
      { type: 'VIOLENCE', inputStrength: 'HIGH', outputStrength: 'HIGH' },
      { type: 'MISCONDUCT', inputStrength: 'HIGH', outputStrength: 'HIGH' },
      // Prompt attacks — prevent injection attempts in health event payloads
      { type: 'PROMPT_ATTACK', inputStrength: 'HIGH', outputStrength: 'NONE' },
    ];

    // PII anonymization — redact (not block) to preserve agent functionality
    const piiEntities = [
      { type: 'EMAIL', action: 'ANONYMIZE' },
      { type: 'PHONE', action: 'ANONYMIZE' },
      { type: 'NAME', action: 'ANONYMIZE' },
      { type: 'AWS_ACCESS_KEY', action: 'BLOCK' },
      { type: 'AWS_SECRET_KEY', action: 'BLOCK' },
    ];

    // Denied topics — block attempts to trigger autonomous remediation.
    //
    // fix-guardrail-topic-false-positives: the CLASSIC topic tier (the
    // default when topicsTierConfig is omitted) false-positives heavily
    // on ordinary AWS Health notification text that merely DESCRIBES an
    // action AWS itself will take — e.g. "this instance will be
    // automatically upgraded... unless you upgrade manually beforehand"
    // (RDS end-of-support) reads as topically close enough to
    // "AutonomousRemediation" to get BLOCKED. Live-measured against the
    // real deployed guardrail (10 real Converse calls per case, full
    // guardrail trace inspected): RDS end-of-support text blocked
    // 9-10/10 of the time; EKS Fargate patching, ElastiCache update
    // notices, and AWS Config redaction notices each blocked 0-4/6.
    // Every one of those texts is real notification prose with no
    // request directed at the agent at all — a deterministic and
    // probabilistic false-positive rate real enough to be the direct
    // cause of the classifier's schema_failure fallback under load.
    //
    // Rewording the topic's own `definition`/`examples` (tested two
    // variants on CLASSIC) made no measurable difference — the CLASSIC
    // classifier keys on the event text's semantic content, not on how
    // the topic itself is worded, so this is not a prompt-engineering
    // fix. Switching to the `STANDARD` tier (AWS's newer, more accurate
    // topic classifier — requires cross-Region inference, wired via
    // crossRegionConfig below) resolved it completely in the same live
    // test harness: the false-positive cases dropped to 0-1/10 while a
    // real prompt-injection attempt asking the agent to bypass its own
    // approval flow still blocked 10/10 — the actual security boundary
    // this topic exists to enforce is unaffected.
    const topicsConfig = [
      {
        name: 'AutonomousRemediation',
        definition:
          'Requests to execute, initiate, or approve infrastructure changes ' +
          'without explicit human approval via the approval token flow.',
        examples: [
          'Upgrade this cluster automatically',
          'Apply the fix without waiting for approval',
          'Execute the remediation now',
        ],
        type: 'DENY',
      },
    ];
    const topicsTierName = 'STANDARD';

    // STANDARD topic tier (above) requires cross-Region inference — the
    // guardrail profile routes policy evaluation across the geography's
    // Regions rather than pinning it to this stack's own Region. `eu.
    // guardrail.v1:0` is the system-defined EU-geography profile; its
    // valid source Regions are eu-central-1/eu-west-1/eu-west-3/
    // eu-north-1/eu-south-1/eu-south-2/il-central-1 (AWS Bedrock user
    // guide, "Supported Regions for cross-Region guardrail inference").
    // A deployment outside that set must swap this profile ID and its
    // matching IAM destination-Region ARNs below (or drop back to
    // topicsTierName: CLASSIC, accepting the false-positive rate
    // documented above) — this is a real deployment assumption, not a
    // no-op default.
    const crossRegionProfileId = 'eu.guardrail.v1:0';

    const guardrail = new bedrock.CfnGuardrail(this, 'HealthTriageGuardrail', {
      name: `${projectName}-guardrail`,
      description: 'Content safety guardrail for the AWS Health Event Triage Agent.',
      blockedInputMessaging,
      blockedOutputsMessaging,
      contentPolicyConfig: {
        filtersConfig: contentFilters,
      },
      sensitiveInformationPolicyConfig: {
        piiEntitiesConfig: piiEntities,
      },
      topicPolicyConfig: {
        topicsConfig,
        topicsTierConfig: {
          tierName: topicsTierName,
        },
      },
      crossRegionConfig: {
        guardrailProfileArn:
          `arn:${cdk.Stack.of(this).partition}:bedrock:${cdk.Stack.of(this).region}:` +
          `${cdk.Stack.of(this).account}:guardrail-profile/${crossRegionProfileId}`,
      },
      tags: [
        { key: 'agent-managed', value: 'true' },
        { key: 'project', value: projectName },
        { key: 'environment', value: 'prototype' },
      ],
    });

    this.guardrailId = guardrail.attrGuardrailId;
    this.guardrailArn = guardrail.attrGuardrailArn;
    // Destination Regions the eu.guardrail.v1:0 profile can route to from
    // this stack's source Region (eu-west-1) — needed by the classifier's
    // `bedrock:ApplyGuardrail` IAM grant below AND by any other caller
    // that invokes this guardrail with cross-Region inference (AWS Bedrock
    // user guide, "Permissions for using cross-Region inference with
    // Amazon Bedrock Guardrails": the caller needs ApplyGuardrail on the
    // guardrail itself plus every destination-Region profile ARN, not
    // just the source Region's). Exposed as a public property rather than
    // re-derived by each caller, since the profile's Region set is a
    // property of the profile choice above, not of the caller.
    this.guardrailProfileDestinationRegionArns = [
      'eu-central-1', 'eu-west-1', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'eu-south-2',
    ].map((region) => `arn:${cdk.Stack.of(this).partition}:bedrock:${region}:` +
      `${cdk.Stack.of(this).account}:guardrail-profile/eu.guardrail.v1:0`);

    // Publish a version — a real, immutable snapshot of the DRAFT guardrail
    // above at deploy time; classifierFunction is wired to invoke this
    // version, never DRAFT (AWS's own guidance: DRAFT is for console
    // iteration/testing, a published version is the deploy artifact for
    // production traffic).
    //
    // fix-guardrail-topic-false-positives (real deploy defect found while
    // shipping this fix): CfnGuardrailVersion has exactly two settable
    // properties, `guardrailIdentifier` and `description`. Bedrock
    // guardrail versions are content-addressed and immutable — there is
    // no UpdateGuardrailVersion API — so when this stack's first deploy
    // changed the underlying guardrail's topic tier (STANDARD) and added
    // crossRegionConfig, `cdk deploy` correctly reported UPDATE_COMPLETE
    // and the CfnGuardrail resource genuinely updated... but
    // CfnGuardrailVersion's own properties hadn't changed, so
    // CloudFormation correctly left that resource untouched — silently
    // leaving the classifier pointed at guardrail version "1", an
    // immutable snapshot of the OLD, pre-fix (CLASSIC-tier) configuration
    // taken at Phase 0. `cdk deploy`'s own UPDATE_COMPLETE output was
    // indistinguishable from a deploy that had actually taken effect —
    // confirmed live via `get-guardrail --guardrail-version 1` still
    // showing `tier: CLASSIC` immediately after a `deploy` that reported
    // success. Fixed by making `description` a hash of the guardrail's
    // own policy content: any real change to `contentPolicyConfig`/
    // `topicPolicyConfig`/`sensitiveInformationPolicyConfig`/
    // `crossRegionConfig` above changes this string, `description` is an
    // immutable CFN property so CloudFormation replaces (delete + create)
    // this resource rather than attempting an in-place update that
    // doesn't exist, and the replacement is a genuine
    // `CreateGuardrailVersion` call snapshotting whatever the DRAFT
    // guardrail looks like at that moment. A config change that does NOT
    // alter the hash (e.g. editing this comment) correctly produces no
    // new version — exactly the behaviour a content-addressed snapshot
    // should have.
    // Hash from the same plain-literal constants passed into CfnGuardrail
    // above (contentFilters, topicsConfig, topicsTierName, piiEntities,
    // crossRegionProfileId, the two messaging strings) — deliberately
    // NEVER from `guardrail.<prop>` read back off the L1 construct, and
    // never anything containing `cdk.Stack.of(this).partition`/`.account`/
    // `.region`. Confirmed by running `cdk synth` twice and diffing:
    // reading a property back off the construct (or hashing a template
    // string built from `Stack.of(this).partition`) stringifies to
    // `${Token[AWS.Partition.N]}`, where N is a per-synthesis-run counter
    // unrelated to the actual partition value — hashing that would churn
    // this resource (and every downstream Bedrock permission/env-var
    // wired to its version) on every single `cdk deploy`, defeating the
    // point of a content-addressed guard. The literals above have no such
    // token, so the hash is genuinely stable across repeated synths of an
    // unchanged config (verified) and genuinely changes when the config
    // does (also verified).
    const guardrailPolicyContentHash = crypto
      .createHash('sha256')
      .update(JSON.stringify({
        contentFilters,
        topicsConfig,
        topicsTierName,
        piiEntities,
        crossRegionProfileId,
        blockedInputMessaging,
        blockedOutputsMessaging,
      }))
      .digest('hex')
      .slice(0, 16);

    const guardrailVersionResource = new bedrock.CfnGuardrailVersion(
      this,
      'HealthTriageGuardrailVersion',
      {
        guardrailIdentifier: guardrail.attrGuardrailId,
        description: `Snapshot of policy content hash ${guardrailPolicyContentHash}`,
      },
    );
    guardrailVersionResource.addDependency(guardrail);
    this.guardrailVersion = guardrailVersionResource.attrVersion;

    // -----------------------------------------------------------------------
    // SSM parameters for runtime consumption
    // -----------------------------------------------------------------------
    const guardrailIdParam = new ssm.StringParameter(this, 'GuardrailIdParam', {
      parameterName: `/${projectName}/guardrail-id`,
      stringValue: guardrail.attrGuardrailId,
      description: 'Amazon Bedrock Guardrail ID for the health triage agent',
    });

    const guardrailVersionParam = new ssm.StringParameter(
      this,
      'GuardrailVersionParam',
      {
        parameterName: `/${projectName}/guardrail-version`,
        stringValue: guardrailVersionResource.attrVersion,
        description: 'Amazon Bedrock Guardrail version',
      },
    );

    // -----------------------------------------------------------------------
    // Stack outputs
    // -----------------------------------------------------------------------
    new cdk.CfnOutput(this, 'GuardrailId', {
      value: guardrail.attrGuardrailId,
      exportName: `${projectName}-guardrail-id`,
      description: 'Amazon Bedrock Guardrail ID',
    });
    new cdk.CfnOutput(this, 'GuardrailVersion', {
      value: guardrailVersionResource.attrVersion,
      exportName: `${projectName}-guardrail-version`,
      description: 'Amazon Bedrock Guardrail version',
    });
    new cdk.CfnOutput(this, 'GuardrailIdSsmParam', {
      value: guardrailIdParam.parameterName,
      description: 'SSM parameter name for the Guardrail ID',
    });
    new cdk.CfnOutput(this, 'GuardrailVersionSsmParam', {
      value: guardrailVersionParam.parameterName,
      description: 'SSM parameter name for the Guardrail version',
    });
  }
}
