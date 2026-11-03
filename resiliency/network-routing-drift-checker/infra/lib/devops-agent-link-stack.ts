// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import { Aws, CfnOutput, CfnParameter, Stack, StackProps } from 'aws-cdk-lib';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/** Fixed rule name, so the forwarder role can pin aws:SourceArn without a circular reference. */
export const LINK_RULE_NAME = 'nrdc-devops-agent-investigation-events';

/**
 * Companion stack for the cross-account hand-off (design.md D§3.3a, tasks.md 3.13).
 * Deployed into the Agent Space account (D), same Region as the checker (N). It holds no data,
 * no compute, and no permission on anything but the one Agent Space's journal and the one
 * callback function:
 *   - a rule forwarding this Agent Space's aws.aidevops events straight to the callback in N;
 *   - the rule's execution role (nrdc-event-forwarder-<N>-<region>);
 *   - the journal-reader role the callback assumes (nrdc-journal-reader-<N>-<region>).
 * Role names must match src/drift_core/cross_account.py.
 */
export class DevOpsAgentLinkStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, props);

    const checkerAccount = new CfnParameter(this, 'CheckerAccountId', {
      type: 'String', allowedPattern: '^[0-9]{12}$',
      description: 'Account where the NetworkRoutingDriftChecker stack runs (N).',
    });
    const callbackArn = new CfnParameter(this, 'CallbackFunctionArn', {
      type: 'String', allowedPattern: '^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+$',
      description: 'CallbackFunctionArn output of the checker stack.',
    });
    const callbackRoleArn = new CfnParameter(this, 'CallbackRoleArn', {
      type: 'String', allowedPattern: '^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$',
      description: 'CallbackRoleArn output of the checker stack. Only this role may read the journal.',
    });
    const agentSpaceId = new CfnParameter(this, 'DevOpsAgentSpaceId', {
      type: 'String', allowedPattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
      description: 'Agent Space ID in this account.',
    });
    const suffix = `${checkerAccount.valueAsString}-${Aws.REGION}`;
    const ruleArn = `arn:${Aws.PARTITION}:events:${Aws.REGION}:${Aws.ACCOUNT_ID}:rule/${LINK_RULE_NAME}`;

    const forwarder = new iam.Role(this, 'EventForwarderRole', {
      roleName: `nrdc-event-forwarder-${suffix}`,
      description: 'EventBridge execution role: deliver Agent Space events to the drift-checker callback',
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com', {
        conditions: { StringEquals: { 'aws:SourceAccount': Aws.ACCOUNT_ID, 'aws:SourceArn': ruleArn } },
      }),
    });
    forwarder.addToPolicy(new iam.PolicyStatement({
      sid: 'InvokeCallback', actions: ['lambda:InvokeFunction'], resources: [callbackArn.valueAsString],
    }));

    const reader = new iam.Role(this, 'JournalReaderRole', {
      roleName: `nrdc-journal-reader-${suffix}`,
      description: 'Assumed by the drift-checker callback to read this Agent Space\'s investigation journal',
      // An account principal pinned by aws:PrincipalArn works before the callback role exists and
      // admits no other principal of account N. No external ID: both accounts are the customer's
      // own and the principal is pinned, so there is no confused deputy.
      assumedBy: new iam.AccountPrincipal(checkerAccount.valueAsString).withConditions({
        ArnEquals: { 'aws:PrincipalArn': callbackRoleArn.valueAsString },
      }),
    });
    reader.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadInvestigationJournal', actions: ['aidevops:ListJournalRecords'],
      resources: [`arn:${Aws.PARTITION}:aidevops:${Aws.REGION}:${Aws.ACCOUNT_ID}:agentspace/${agentSpaceId.valueAsString}`],
    }));

    const rule = new events.CfnRule(this, 'InvestigationEventsRule', {
      name: LINK_RULE_NAME,
      description: 'Forward this Agent Space\'s investigation events to the drift-checker callback',
      state: 'ENABLED',
      eventPattern: {
        source: ['aws.aidevops'],
        'detail-type': ['Investigation Completed', 'Investigation Failed', 'Investigation Timed Out',
          'Investigation Cancelled', 'Investigation Skipped', 'Investigation Linked',
          'Investigation Created', 'Investigation In Progress', 'Investigation Priority Updated'],
        detail: { metadata: { agent_space_id: [agentSpaceId.valueAsString] } },
      },
      targets: [{ id: 'drift-checker-callback', arn: callbackArn.valueAsString, roleArn: forwarder.roleArn }],
    });
    rule.node.addDependency(forwarder);

    new CfnOutput(this, 'EventForwarderRoleArn', { value: forwarder.roleArn });
    new CfnOutput(this, 'JournalReaderRoleArn', { value: reader.roleArn });
  }
}
