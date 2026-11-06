#!/usr/bin/env node
// Copyright (c) 2026 Amazon Web Services
// Licensed under the MIT-0 License
// See LICENSE file in the project root for full license information.
import * as cdk from "aws-cdk-lib";
import { NetworkFlowInsightStack } from "../lib/agent-stack";

const app = new cdk.App();
const ctx = (k: string, d = ""): string => String(app.node.tryGetContext(k) ?? d);

new NetworkFlowInsightStack(app, "NetworkFlowInsight", {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: ctx("region", process.env.CDK_DEFAULT_REGION ?? "eu-west-2") },
  description: "network-flow-insight: hosted agent on Amazon Bedrock AgentCore Runtime (read-only on the customer estate)",
  flowLogBucketName: ctx("flowLogBucketName", "example-flow-logs"),
  flowLogDatabase: ctx("flowLogDatabase", "default"),
  flowLogTable: ctx("flowLogTable", "vpc_flow_logs"),
  flowLogKmsKeyArn: ctx("flowLogKmsKeyArn"),
  modelId: ctx("modelId", "eu.anthropic.claude-sonnet-5"),
  scheduleDescribe: ctx("scheduleDescribe", "cron(0 6 ? * MON *)"),
  scheduleDrift: ctx("scheduleDrift"),
  notificationEmail: ctx("notificationEmail"),
  artifact: ctx("artifact", "container"),
  inventoryFile: ctx("inventoryFile"),
  intentFile: ctx("intentFile"),
  ipRangesFile: ctx("ipRangesFile"),
  configAggregatorName: ctx("configAggregatorName"),
  maxToolCalls: ctx("maxToolCalls"),
  runDeadlineSeconds: ctx("runDeadlineSeconds"),
  athenaBytesScannedCutoff: ctx("athenaBytesScannedCutoff", "1000000000000"),
  owner: ctx("owner", "platform-team"),
  environment: ctx("environment", "dev"),
});
