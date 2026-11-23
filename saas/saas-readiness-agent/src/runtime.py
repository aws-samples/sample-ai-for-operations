# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Amazon Bedrock AgentCore Runtime entrypoint for the published v2 profile."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp, RequestContext

from src.agent import build_agent
from src.assessment_core import Redactor
from src.config import ConfigurationError, load_log_level, load_settings
from src.observability import configure_logging, get_logger
from src.session_profiles import build_session_store, build_strands_session_manager

configure_logging(load_log_level())
logger = get_logger("runtime")

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: Mapping[str, Any], context: RequestContext) -> dict[str, str]:
    """Resume one authorized shared assessment and process a single prompt.

    The deployment's authentication layer must verify that the caller is a
    member of the requested assessment before this handler runs. Assessment
    IDs route state; they are not secrets or authorization credentials.

    Logs record identifiers, durations, and error types only. The prompt and
    the model response are never logged.
    """

    started = time.monotonic()
    log_context: dict[str, Any] = {"runtime_session_id": context.session_id or ""}
    try:
        prompt = str(payload.get("prompt", "")).strip()
        assessment_id = str(payload.get("assessment_id", "")).strip()
        contributor_id = str(payload.get("contributor_id", "")).strip()
        if not prompt:
            raise ConfigurationError("The request payload must include a non-empty prompt.")

        # Request-scoped IDs let multiple authenticated personas share one
        # assessment without sharing laptop files or AWS credentials.
        settings = load_settings(
            profile_override="v2",
            assessment_id_override=assessment_id,
            contributor_id_override=contributor_id,
        )
        # Only log identifiers after load_settings() has validated them as
        # pseudonymous, path-safe values.
        log_context.update(
            assessment_id=settings.assessment_id,
            contributor_id=settings.contributor_id,
            model_id=settings.model_id,
            guardrail_enabled=bool(settings.bedrock_guardrail_id),
        )
        logger.info("invocation_started", extra=log_context)

        store = build_session_store(settings, Redactor())
        session_manager = build_strands_session_manager(settings)
        agent = build_agent(
            model_id=settings.model_id,
            region=settings.model_region,
            guardrail_id=settings.bedrock_guardrail_id,
            guardrail_version=settings.bedrock_guardrail_version,
            session_store=store,
            session_manager=session_manager,
            # Remote callers cannot place files in the container; never let
            # the model read container files on a caller's behalf.
            enable_document_reader=False,
        )
        response = agent(prompt)
    except Exception as exc:
        # Structured summary only; the exception is re-raised and the AgentCore
        # SDK records it at ERROR, so this line is a WARNING to avoid
        # double-reporting the same failure as an error.
        logger.warning(
            "invocation_failed",
            extra={
                **log_context,
                "error_type": type(exc).__name__,
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )
        raise

    logger.info(
        "invocation_completed",
        extra={**log_context, "duration_ms": round((time.monotonic() - started) * 1000)},
    )
    return {
        "assessment_id": settings.assessment_id,
        "runtime_session_id": context.session_id or "",
        "response": str(response),
    }


if __name__ == "__main__":
    app.run()
