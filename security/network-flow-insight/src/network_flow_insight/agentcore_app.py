# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Amazon Bedrock AgentCore Runtime entrypoint. Wraps the same agent as the local CLI.

Payload: ``{"mode": "describe" | "drift" | "chat", "first_day": "...", "last_day": "...", "prompt": "..."}``.
Scheduled invocations (mode describe or drift) run unattended: queries above the ceiling are skipped and
recorded, and the report is written to the agent report bucket.
"""

from __future__ import annotations

import json
import logging
import tempfile
from datetime import date
from typing import Any

from . import agent as agent_mod
from . import aws_backend
from .config import Settings, load_settings
from .tools import write_report
from .toolset import ToolSession

logger = logging.getLogger(__name__)
VALID_MODES = ("describe", "drift", "chat")


def validate_payload(payload: dict) -> dict:
    mode = payload.get("mode", "chat")
    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of {VALID_MODES}")
    for k in ("first_day", "last_day"):
        if payload.get(k):
            date.fromisoformat(payload[k])
    if mode == "chat" and not str(payload.get("prompt", "")).strip():
        raise ValueError("chat mode needs a prompt")
    return {
        "mode": mode,
        "first_day": payload.get("first_day", ""),
        "last_day": payload.get("last_day", ""),
        "prompt": str(payload.get("prompt", ""))[:8000],
    }


def handle(
    payload: dict, settings: Settings | None = None, *, model: Any | None = None, session_factory: Any = None
) -> dict:
    s = (settings or load_settings()).with_overrides(
        reports_dir=tempfile.mkdtemp(prefix="nfi-")
    )  # the container file system is scratch
    p = validate_payload(payload)
    first, last = (
        (p["first_day"], p["last_day"]) if p["first_day"] and p["last_day"] else aws_backend.default_window(s)
    )
    scheduled = p["mode"] in ("describe", "drift")
    make = session_factory or (
        lambda: ToolSession(
            aws_backend.build_analysis(
                s, first, last, interactive=not scheduled, create_agent_resources=scheduled
            )
        )
    )
    session = make()
    if scheduled:
        out = agent_mod.run_scheduled(session, s, p["mode"], first, last, model)
        if session.findings is not None and s.report_bucket:
            from .tools import render_report

            art = render_report.render_report(session.findings, session.narrative)
            import boto3

            prefix = f"reports/{p['mode']}/{first}_{last}"
            out["report"] = write_report.write_report(
                art, s3=boto3.client("s3"), bucket=s.report_bucket, prefix=prefix
            )
        return out
    agent = agent_mod.create_agent(session, s, model)
    answer = str(agent_mod.ask(agent, p["prompt"]))
    figures = agent_mod.answer_figures_not_from_tools(agent, p["prompt"], answer)
    return {
        "mode": "chat",
        "answer": agent_mod.with_figure_caution(answer, figures),
        "ungrounded_figures": figures,
        "scan": session.a.b.engine.gauge.summary(),
    }


def build_app() -> Any:  # pragma: no cover - requires the AgentCore runtime package at deploy time
    from bedrock_agentcore.runtime import BedrockAgentCoreApp

    app = BedrockAgentCoreApp()

    @app.entrypoint
    def invoke(payload: dict) -> dict:
        try:
            return handle(payload)
        except Exception as exc:
            logger.error(json.dumps({"event": "invocation_failed", "error": type(exc).__name__}))
            return {"error": "invocation failed; see logs"}

    return app


if __name__ == "__main__":  # pragma: no cover
    build_app().run()
