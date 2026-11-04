# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The Strands agent. Local runs and Amazon Bedrock AgentCore Runtime share this module.

The agent decides what to investigate and writes the explanation. It never computes a number: every
figure comes from a tool in ``toolset.ToolSession``. Guardrails are attached to the model in both modes.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from importlib import resources  # Python 3.12+ only  # nosemgrep: python37-compatibility-importlib2
from typing import Any

from .config import Settings
from .core.runbudget import RunBudget, RunBudgetExceeded
from .toolset import ToolSession, tool_methods

logger = logging.getLogger(__name__)


class GuardrailMissing(RuntimeError):
    pass


def load_system_prompt() -> str:
    return (
        resources.files("network_flow_insight")
        .joinpath("prompts/system_prompt.md")
        .read_text(encoding="utf-8")
    )


def build_model(settings: Settings) -> Any:
    from strands.models.bedrock import BedrockModel, CacheConfig

    if not settings.guardrail_id:
        if not settings.allow_no_guardrail:
            raise GuardrailMissing(
                "No Amazon Bedrock Guardrail configured. Set GUARDRAIL_ID (and GUARDRAIL_VERSION); the stack outputs "
                "one. For local development only, NFI_ALLOW_NO_GUARDRAIL=true overrides this and is logged."
            )
        logger.warning('{"event": "guardrail_disabled", "reason": "NFI_ALLOW_NO_GUARDRAIL"}')
    kw: dict[str, Any] = {
        "model_id": settings.bedrock_model_id,
        "region_name": settings.bedrock_region,
        "max_tokens": settings.bedrock_max_tokens,
        "cache_config": CacheConfig(strategy="auto"),
    }
    if settings.bedrock_temperature >= 0:
        kw["temperature"] = settings.bedrock_temperature
    if settings.guardrail_id:
        kw.update(
            guardrail_id=settings.guardrail_id,
            guardrail_version=settings.guardrail_version,
            guardrail_trace="enabled",
        )
    return BedrockModel(**kw)


def build_tools(session: ToolSession) -> list[Callable[..., Any]]:
    from strands import tool

    return [tool(m) for m in tool_methods(session)]


def build_run_budget_hooks(settings: Settings) -> Any:
    """Strands hooks that bound one invocation (core/runbudget.py).

    Nothing in the model-and-tool loop ends it except the model, and a schedule runs it unattended. A tool call past the
    budget is cancelled with a message the model reads in place of the tool result; a model that keeps asking, or a model
    call long after the deadline, stops the invocation with ``RunBudgetExceeded``.
    """
    from strands.hooks import (
        BeforeInvocationEvent,
        BeforeModelCallEvent,
        BeforeToolCallEvent,
        HookProvider,
        HookRegistry,
    )

    budget = RunBudget(settings.max_tool_calls, settings.run_deadline_seconds)

    class RunBudgetHooks(HookProvider):
        def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
            registry.add_callback(BeforeInvocationEvent, self.on_invocation)
            registry.add_callback(BeforeToolCallEvent, self.on_tool)
            registry.add_callback(BeforeModelCallEvent, self.on_model)

        def on_invocation(self, event: Any) -> None:
            budget.start()

        def on_tool(self, event: Any) -> None:
            message = budget.before_tool()
            if message:
                logger.warning(
                    json.dumps({"event": "run_budget_tool_cancelled", "tool": event.tool_use.get("name", "")})
                )
                event.cancel_tool = message

        def on_model(self, event: Any) -> None:
            budget.before_model()

    return RunBudgetHooks()


def ask(agent: Any, prompt: str) -> Any:
    """Run one invocation. Strands wraps an exception raised in a hook in EventLoopException; unwrap the budget's own.

    Callers (the scheduled run, hosted chat, local chat) then see ``RunBudgetExceeded`` and can name it in logs and replies.
    """
    try:
        return agent(prompt)
    except Exception as exc:
        original = getattr(exc, "original_exception", None)
        if isinstance(original, RunBudgetExceeded):
            raise original from exc
        raise


def create_agent(
    session: ToolSession, settings: Settings, model: Any | None = None, callback_handler: Any = None
) -> Any:
    from strands import Agent

    kw: dict[str, Any] = {}
    if callback_handler is not None:
        kw["callback_handler"] = callback_handler
    return Agent(
        model=model or build_model(settings),
        system_prompt=load_system_prompt(),
        tools=build_tools(session),
        hooks=[build_run_budget_hooks(settings)],
        **kw,
    )


def answer_figures_not_from_tools(agent: Any, prompt: str, answer: str) -> list[str]:
    """Figures in a chat answer that no tool returned and the user did not type.

    The report narrative is gated before it is written; a chat answer is free text, so this check runs after the
    fact and the caller adds a visible caution (the model must not do arithmetic: use the precision tools).
    """
    from .core.grounding import known_numbers, numbers_in

    evidence: list[Any] = [prompt]
    for msg in getattr(agent, "messages", []) or []:
        for block in msg.get("content", []) if isinstance(msg, dict) else []:
            for part in (block.get("toolResult", {}) or {}).get("content", []):
                if "json" in part:
                    evidence.append(part["json"])
                elif "text" in part:
                    try:
                        evidence.append(json.loads(part["text"]))
                    except ValueError:
                        evidence.append(part["text"])
    known = known_numbers(evidence)
    return sorted(n for n in numbers_in(answer) if n not in known)


def with_figure_caution(answer: str, figures: list[str]) -> str:
    if not figures:
        return answer
    return (
        f"{answer}\n\nCaution: these figures appear in the answer but no tool returned them: {', '.join(figures)}. "
        "Treat them as unverified and ask for the figure from a tool."
    )


DESCRIBE_PROMPT = (
    "Produce the traffic map for {window}. Follow the method: probe first and state the tier and inventory provider; "
    "describe the window; check integrity and the reconciliation result before presenting any NAT shares; then call "
    "render_report with a short interpretation per section (keys: summary, integrity, paths, egress, services, "
    "inter_vpc, nat, concentration, time, options), two or three sentences each. Put the interpretation in that call; "
    "do not write the report out in chat first. Do not state any figure that a tool did not return."
)
DRIFT_PROMPT = (
    "Run a drift check for {window} against the committed baseline: probe, describe, then drift, and report matched "
    "entries, new traffic, stale entries and path changes. Do not modify the baseline."
)


def run_scheduled(
    session: ToolSession,
    settings: Settings,
    mode: str,
    first_day: str,
    last_day: str,
    model: Any | None = None,
) -> dict:
    """Unattended run (EventBridge Scheduler -> AgentCore Runtime). Ceiling breaches are skipped, never prompted."""
    window = f"{first_day} to {last_day}"
    prompt = (DRIFT_PROMPT if mode == "drift" else DESCRIBE_PROMPT).format(window=window)
    out: dict = {"mode": mode, "window": [first_day, last_day]}
    try:
        out["summary"] = str(ask(create_agent(session, settings, model), prompt))
    except Exception as exc:  # the figures matter more than the prose: keep going without the interpretation
        logger.error(
            json.dumps({"event": "invocation_failed", "stage": "agent", "error": type(exc).__name__})
        )
        out["summary"] = ""
        out["agent_error"] = type(exc).__name__
    if session.findings is None and mode == "describe":
        session.describe(first_day, last_day)  # deterministic fallback so a report is still produced
        out["fallback"] = "report rendered without model interpretation"
    out["scan"] = session.a.b.engine.gauge.summary()
    return out
