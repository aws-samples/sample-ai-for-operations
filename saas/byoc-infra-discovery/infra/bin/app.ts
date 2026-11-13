#!/usr/bin/env node
// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.
import * as cdk from 'aws-cdk-lib';
import { AgentStack } from '../lib/agent-stack';

const app = new cdk.App();

new AgentStack(app, 'ByocInfraDiscoveryStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  description: 'BYOC Infrastructure Discovery Agent (Strands on AWS Lambda)',
  tags: {
    project: 'byoc-infra-discovery',
    'data-classification': 'public',
  },
});
