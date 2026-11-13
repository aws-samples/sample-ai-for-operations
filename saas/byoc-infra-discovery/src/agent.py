# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Agent assembly for the BYOC Infrastructure Discovery Agent.

Builds a Strands Agent backed by Amazon Bedrock, wired with the data-retrieval
and precision tools and the externalized system prompt. The LLM only routes
queries and narrates verdicts/reconciliation — all facts and computation come
from the tools.
"""

import os
from functools import lru_cache

from strands import Agent
from strands.models.bedrock import BedrockModel

from config import (
    BEDROCK_MAX_TOKENS,
    BEDROCK_MODEL_ID,
    BEDROCK_REGION,
    BEDROCK_TEMPERATURE,
    GUARDRAIL_ID,
    GUARDRAIL_VERSION,
)
from schemas import GatheredFacts
from tools.count_azs import count_azs
from tools.filter_instance_types import filter_instance_types
from tools.lookup_curated_data import lookup_curated_data
from tools.resolve_amis import resolve_amis
from tools.resolve_availability_zones import resolve_availability_zones
from tools.resolve_instance_offerings import resolve_instance_offerings
from tools.resolve_instance_types import resolve_instance_types
from tools.resolve_regions import resolve_regions
from tools.resolve_service_availability import resolve_service_availability

_PROMPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "prompts", "system_prompt.md"
)

# The agent GATHERS facts only. The deployability verdict, confidence, and the
# final JSON contract are computed deterministically downstream (assemble.py),
# so the model can never decide or override them. compute_deployability and
# format_response are therefore intentionally NOT in the agent's toolset.
_TOOLS = [
    # data retrieval
    resolve_regions,
    resolve_availability_zones,
    resolve_service_availability,
    resolve_instance_types,
    resolve_instance_offerings,
    resolve_amis,
    lookup_curated_data,
    # precision helpers used while gathering/interpreting
    count_azs,
    filter_instance_types,
]


def _load_system_prompt() -> str:
    with open(_PROMPT_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


def _build_model() -> BedrockModel:
    # Only pass guardrail settings when configured, so a missing guardrail in
    # local/dev does not break model construction. Production MUST set both.
    model_config = {
        "model_id": BEDROCK_MODEL_ID,
        "temperature": BEDROCK_TEMPERATURE,
        "max_tokens": BEDROCK_MAX_TOKENS,
    }
    if GUARDRAIL_ID and GUARDRAIL_VERSION:
        model_config["guardrail_id"] = GUARDRAIL_ID
        model_config["guardrail_version"] = GUARDRAIL_VERSION
        model_config["guardrail_trace"] = "enabled"
    return BedrockModel(region_name=BEDROCK_REGION, **model_config)


@lru_cache(maxsize=1)
def _cached_model() -> BedrockModel:
    """Build the Bedrock model once per warm environment (safe to reuse)."""
    return _build_model()


def _new_agent() -> Agent:
    """A fresh agent with empty conversation history for one invocation.

    The agent must NOT be cached across invocations: gather_facts runs a tool
    loop that accumulates conversation state, which would otherwise leak between
    (possibly concurrent) Lambda requests.
    """
    return Agent(
        model=_cached_model(),
        system_prompt=_load_system_prompt(),
        tools=_TOOLS,
    )


def gather_facts(query: str) -> GatheredFacts:
    """Run the agent to gather facts for a query, returned as a typed object.

    Two passes on one fresh agent:
      1. agent(query) runs the tool loop so the data-retrieval tools actually
         execute and their results land in the conversation history.
      2. agent.structured_output(GatheredFacts) — WITHOUT a prompt — coerces that
         gathered history into the schema. Passing a prompt here would bypass the
         tool results and yield an all-null bundle.

    No verdict/confidence is produced here; that is decided in assemble.py.
    """
    agent = _new_agent()
    agent(query)  # pass 1: execute tools, populate conversation history
    return agent.structured_output(GatheredFacts)  # pass 2: coerce from history
