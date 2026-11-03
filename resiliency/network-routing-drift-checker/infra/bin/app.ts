#!/usr/bin/env node
// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import { App, Tags } from 'aws-cdk-lib';
import { DevOpsAgentLinkStack } from '../lib/devops-agent-link-stack';
import { DriftCheckerStack } from '../lib/drift-checker-stack';

const app = new App();

const stack = new DriftCheckerStack(app, 'NetworkRoutingDriftChecker', {
  description: 'Read-only daily drift checker for AWS Cloud WAN, Transit Gateway and Direct Connect routing',
  // `-c skipBundling=true` packages src/ without dependencies; used by synth-only tests.
  skipBundling: app.node.tryGetContext('skipBundling') === 'true' || app.node.tryGetContext('skipBundling') === true,
});

// Cross-account hand-off only (design.md D§3.3a): deployed into the Agent Space account by
// scripts/deploy.sh with the DEVOPS_AGENT_PROFILE credentials. Never deployed by default.
const link = new DevOpsAgentLinkStack(app, 'NetworkRoutingDriftChecker-DevOpsAgentLink', {
  description: 'Network routing drift checker: forward DevOps Agent investigation events and allow journal reads',
});

// Required resource tags (security-policies, iam-permission-boundary Rule 5).
for (const s of [stack, link]) {
  Tags.of(s).add('project', 'network-routing-drift-checker');
  Tags.of(s).add('agent-managed', 'true');
  Tags.of(s).add('data-classification', 'internal');
  Tags.of(s).add('environment', String(app.node.tryGetContext('environment') ?? 'prototype'));
  Tags.of(s).add('owner', String(app.node.tryGetContext('owner') ?? 'network-team'));
}
