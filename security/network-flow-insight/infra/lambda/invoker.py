# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""EventBridge Scheduler target: calls InvokeAgentRuntime with the scheduled payload and fails if the runtime reports a failure."""

import json
import logging
import os
import uuid

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)
# A scheduled run takes minutes. The default 60 second read timeout would abandon the call and retry it,
# starting a second run, so wait for the one call and never retry.
_client = boto3.client("bedrock-agentcore", config=Config(read_timeout=880, retries={"max_attempts": 1}))
ALLOWED_MODES = ("describe", "drift")


def handler(event, _context):
    mode = event.get("mode")
    if mode not in ALLOWED_MODES:
        raise ValueError(f"mode must be one of {ALLOWED_MODES}")
    payload = {"mode": mode}
    for key in ("first_day", "last_day"):
        if event.get(key):
            payload[key] = str(event[key])
    resp = _client.invoke_agent_runtime(
        agentRuntimeArn=os.environ["RUNTIME_ARN"],
        runtimeSessionId=uuid.uuid4().hex + uuid.uuid4().hex,
        payload=json.dumps(payload).encode(),
    )
    body = resp["response"].read().decode()
    logger.info(json.dumps({"event": "scheduled_run", "mode": mode, "bytes": len(body)}))
    # The runtime catches its own exceptions and answers with {"error": ...}, which is still a successful HTTP call.
    # Raise here so the Lambda Errors metric, and with it the InvokerErrors alarm, sees the failed run.
    try:
        reply = json.loads(body)
    except ValueError:
        reply = None
    if not isinstance(reply, dict) or "error" in reply:
        # Lambda records a raised exception and its message in the function's log group, so no separate log line.
        raise RuntimeError(f"scheduled {mode} run failed; see the runtime log group")
    degraded = [k for k in ("agent_error", "fallback") if k in reply]
    if degraded:  # a report was still produced; only the model interpretation failed
        logger.warning(json.dumps({"event": "scheduled_run_degraded", "mode": mode, "markers": degraded}))
    return {"mode": mode, "status": "ok"}
