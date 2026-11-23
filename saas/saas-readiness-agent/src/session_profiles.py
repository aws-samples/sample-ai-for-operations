# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Lazy construction for v1 local and v2 AgentCore persistence profiles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import AppSettings
from src.session_store import SessionStore


def build_session_store(
    settings: AppSettings,
    redactor: Any,
    *,
    local_path: Path | None = None,
    memory_client: Any | None = None,
) -> SessionStore:
    """Build the selected store without touching AgentCore in profile v1."""

    settings.validate()
    if settings.session_profile == "v1":
        from src.assessment_core import JsonSessionStore

        return JsonSessionStore(local_path or Path(settings.session_path), redactor)

    from src.agentcore_session_store import AgentCoreMemorySessionStore

    return AgentCoreMemorySessionStore(settings, redactor, client=memory_client)


def build_strands_session_manager(settings: AppSettings) -> Any | None:
    """Build shared chat persistence only for the published v2 profile."""

    settings.validate()
    if settings.session_profile == "v1":
        return None

    try:
        from bedrock_agentcore.memory.integrations.strands.config import (
            AgentCoreMemoryConfig,
        )
        from bedrock_agentcore.memory.integrations.strands.session_manager import (
            AgentCoreMemorySessionManager,
        )
    except ImportError as exc:  # pragma: no cover - installation failure
        raise RuntimeError(
            "The bedrock-agentcore Strands integration is required for profile v2."
        ) from exc

    memory_id = settings.agentcore_memory_id
    if memory_id is None:  # guarded by settings.validate(), keeps mypy honest
        raise ValueError("AGENTCORE_MEMORY_ID is required for profile v2.")

    config = AgentCoreMemoryConfig(
        memory_id=memory_id,
        actor_id=settings.memory_actor_id,
        session_id=settings.memory_session_id,
        batch_size=1,
        default_metadata={
            "assessmentId": {"stringValue": settings.assessment_id},
            "contributorId": {"stringValue": settings.contributor_id},
        },
    )
    return AgentCoreMemorySessionManager(
        agentcore_memory_config=config,
        region_name=settings.agentcore_region,
    )
