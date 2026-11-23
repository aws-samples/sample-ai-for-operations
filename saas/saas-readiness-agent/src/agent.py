# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# ruff: noqa: E501

"""SaaS Readiness Agent - the primary AI agent, built on the Strands Agents SDK
and Amazon Bedrock (Claude Sonnet 5).

This is the main entrypoint for this project. Running the
`saas-readiness-agent` console script (or `python -m src.agent` from the
repository root, after `pip install -e . --no-deps`) starts a conversational
agent: you tell it what you want assessed, it decides which
tools to call (scan your live AWS account, load a JSON payload, write a
report), and it explains the results back to you in plain language. It
deploys the same way to Amazon Bedrock AgentCore Runtime with no code
changes - see README.md "Publishing the v2 AgentCore Profile".

Why the scoring/discovery tools themselves are deterministic Python, not
free-form model judgment:
  The model's job is to decide *what to investigate* and *how to explain
  it*; the tools' job is to fetch real AWS data and compute exact scores
  from it. This is what makes every score, status, and confidence value in
  a report reproducible and auditable rather than a hallucination risk.
  Concretely: every tool in src/tools/ returns exactly what
  assess_payload()/run_aws_discovery() computed, as plain data (via
  to_plain()). There is no parameter or code path through which the model
  could write a different score back in.

The tools live in src/tools/, one per module. The deterministic scoring and
discovery functions they call live in assessment_core.py, rubric.py, and
discovery.py - kept framework-free (no Strands, no Bedrock imports) so they
stay independently unit-testable. This module wires the tools, the system
prompt, and the Bedrock model into an Agent and runs the local REPL.

It never calls a mutating AWS API. The only AWS-calling code path is
discovery.run_aws_discovery(), reached through merge_aws_preflight(), which
only ever issues Describe/List/Get/Simulate calls (see discovery.py's
module docstring).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from strands import Agent
from strands.models import BedrockModel

from src.assessment_core import Redactor
from src.config import DEFAULT_MODEL_ID, DEFAULT_REGION, load_limits, load_settings
from src.session_profiles import build_session_store, build_strands_session_manager
from src.session_store import SessionStore
from src.tools import build_default_tools, build_session_tools
from src.tools._common import _parse_input_json, _resolve_within_cwd
from src.tools.get_assessment_questions import (
    QUESTION_MODES,
    _get_assessment_questions,
    _normalize_question_mode,
    get_assessment_questions,
)
from src.tools.get_findings_summary import _get_findings_summary, get_findings_summary
from src.tools.read_customer_document import read_customer_document
from src.tools.run_saas_readiness_assessment import (
    _run_saas_readiness_assessment,
    run_saas_readiness_assessment,
)
from src.tools.save_assessment_answer import (
    SAVE_VERIFICATION_ATTEMPTS,
    SAVE_VERIFICATION_INITIAL_DELAY_SECONDS,
    _persist_and_verify_answer,
)
from src.tools.write_html_report import _write_html_report, write_html_report
from src.tools.write_summary_report import _write_summary_report, write_summary_report

# Re-exported so existing callers that import tools from src.agent keep working.
__all__ = [
    "QUESTION_MODES",
    "SAVE_VERIFICATION_ATTEMPTS",
    "SAVE_VERIFICATION_INITIAL_DELAY_SECONDS",
    "SYSTEM_PROMPT",
    "_get_assessment_questions",
    "_get_findings_summary",
    "_normalize_question_mode",
    "_parse_input_json",
    "_persist_and_verify_answer",
    "_run_saas_readiness_assessment",
    "_write_html_report",
    "_write_summary_report",
    "build_agent",
    "get_assessment_questions",
    "get_findings_summary",
    "main",
    "read_customer_document",
    "run_saas_readiness_assessment",
    "write_html_report",
    "write_summary_report",
]

# The system prompt is the only place that tells the model how to behave.
# It is deliberately explicit that the model never computes scores itself;
# explainer.py's build_explanation_prompt() enforces the same rule for the
# one-shot narrative path.

# Prompts are versioned separately from code. Keeping the read at import time
# makes local and published profiles use the same reviewed instructions.
SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text(
    encoding="utf-8"
)


def build_agent(
    model_id: str = DEFAULT_MODEL_ID,
    region: str = DEFAULT_REGION,
    *,
    guardrail_id: str | None = None,
    guardrail_version: str | None = None,
    session_store: SessionStore | None = None,
    session_manager: Any | None = None,
    max_tokens: int | None = None,
    enable_document_reader: bool = True,
) -> Agent:
    """Construct the Strands Agent wired to the deterministic assessment tools.

    enable_document_reader=False removes read_customer_document. The AgentCore
    Runtime entrypoint passes False: remote callers cannot place files in the
    container, so a filesystem-reading tool would only expose container files.

    model_id/region are parameters (not hard-coded into a BedrockModel call
    at import time) so callers - the local CLI entrypoint below, tests, or a
    future AgentCore Runtime entrypoint - can override them via config/env
    without editing this function.
    """

    model_config: dict[str, Any] = {
        "model_id": model_id,
        "region_name": region,
        # Caps output tokens per model call (BEDROCK_MAX_TOKENS) so one
        # request cannot run up unbounded cost.
        "max_tokens": max_tokens if max_tokens is not None else load_limits().bedrock_max_tokens,
    }
    if guardrail_id and guardrail_version:
        model_config.update(
            {
                "guardrail_id": guardrail_id,
                "guardrail_version": guardrail_version,
                "guardrail_trace": "enabled",
                "guardrail_redact_input": True,
                "guardrail_redact_output": True,
            }
        )
    model = BedrockModel(**model_config)
    tools = (
        build_session_tools(session_store)
        if session_store is not None
        else build_default_tools()
    )
    if not enable_document_reader:
        tools = [t for t in tools if getattr(t, "tool_name", None) != "read_customer_document"]
    agent_kwargs: dict[str, Any] = {
        "model": model,
        "tools": tools,
        "system_prompt": SYSTEM_PROMPT,
    }
    if session_manager is not None:
        agent_kwargs["session_manager"] = session_manager
    return Agent(**agent_kwargs)


def main() -> None:
    """Start the local REPL using either the v1 or v2 persistence profile."""

    import sys
    import traceback

    settings = load_settings()
    local_path: Path | None = None
    if settings.session_profile == "v1":
        resolved = _resolve_within_cwd(settings.session_path)
        if isinstance(resolved, str):
            raise ValueError(resolved)
        local_path = resolved

    session_store = build_session_store(
        settings,
        Redactor(),
        local_path=local_path,
    )
    session_manager = build_strands_session_manager(settings)
    agent = build_agent(
        model_id=settings.model_id,
        region=settings.model_region,
        guardrail_id=settings.bedrock_guardrail_id,
        guardrail_version=settings.bedrock_guardrail_version,
        session_store=session_store,
        session_manager=session_manager,
    )

    profile_label = (
        "v1 local JSON"
        if settings.session_profile == "v1"
        else f"v2 AgentCore Memory (assessment {settings.assessment_id})"
    )
    print(f"Persistence profile: {profile_label}")

    # Deterministic resume check: do not rely on the model remembering to
    # call get_assessment_progress and narrate it before acting. Decide the
    # resume/fresh-start message in plain code so it's guaranteed, not
    # guidance, and print it right before the menu prompt so it's the last
    # thing the user reads before choosing an option.
    existing_answers = session_store.list_answers()
    identifier = (
        settings.assessment_id
        if settings.session_profile == "v2"
        else settings.session_path
    )
    if existing_answers:
        resume_notice = (
            f"\nFound an existing assessment with {len(existing_answers)} "
            f"saved answer(s) under this assessment ID ({identifier}).\n"
            "Type 'resume' to continue that assessment and skip "
            "already-answered questions, without re-running an AWS scan "
            "(this also works if you just pick option 2 below). "
            "If you intended to start a separate, new assessment instead, "
            "exit now (type 'exit') and restart with a different "
            "ASSESSMENT_ID set outside this conversation."
        )
    else:
        resume_notice = (
            f"\nNo prior progress found for this assessment ID ({identifier}). "
            "Starting fresh — any option below is fine."
        )

    print("""
╭───────────────────────────────────────────────────────────────╮
│  SaaS Readiness Assessment Agent                              │
╰───────────────────────────────────────────────────────────────╯

I help you understand how ready your AWS-hosted product is to
operate as scalable, multi-tenant SaaS — across 7 dimensions:

  • Tenant Architecture & Isolation
  • Identity & Tenant Context
  • Tenant Lifecycle & Onboarding
  • Observability & Operational Readiness
  • Deployment & Platform Automation
  • Cost Attribution & Metering
  • Service Model & Business Readiness

What I can do:

  1. Scan your AWS account (read-only) to detect signals
     automatically, then ask targeted follow-up questions.

  2. Walk you through discovery questions directly if you
     prefer not to scan an AWS account right now.

  3. Assess a JSON payload you provide.

  4. Read your documentation (architecture docs, wikis, runbooks)
     to pre-fill answers and reduce question burden.
""")
    print(resume_notice)
    print("\nHow would you like to start? (type 'exit' to quit)\n")
    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break
        if user_input.lower() in {"exit", "quit"}:
            break
        if not user_input:
            continue

        try:
            agent(user_input)
        except Exception as exc:
            error_name = type(exc).__name__

            # Context window full — partial response already saved in
            # conversation history, so the agent can continue.
            if "MaxTokensReached" in error_name:
                print(
                    "\n⚠️  The conversation got too long for a single response. "
                    "Progress is saved — continuing from where I left off.\n"
                    "Please repeat your last request or say 'continue'."
                )
                continue

            # AWS credential expiry.
            error_str = str(exc).lower()
            if any(term in error_str for term in [
                "expired",
                "expiredtoken",
                "invalid security token",
                "security token included in the request is expired",
                "unable to locate credentials",
                "no credentials",
            ]):
                print(
                    "\n⚠️  AWS credentials have expired or are not configured.\n"
                    "Please refresh and try again:\n"
                    "  • AWS SSO: run 'aws sso login --profile <your-profile>'\n"
                    "  • Session tokens: refresh your temporary credentials\n"
                    "  • IAM user: check ~/.aws/credentials\n\n"
                    "Once refreshed, say 'scan' or repeat your request."
                )
                continue

            # Unexpected error — clean message, full traceback to stderr.
            print(f"\n❌ Something went wrong: {error_name}: {exc}")
            print("   You can try again or type 'exit' to quit.")
            traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()
