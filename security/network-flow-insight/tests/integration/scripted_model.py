# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A scripted Strands model: replays a fixed sequence of tool calls and a final answer.

It lets the integration tests run the real agent loop (system prompt, tool schemas, tool execution)
without calling a hosted model. The script is the recorded behaviour the tests assert on.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from typing import Any

from strands.models.model import Model


class ScriptedModel(Model):
    def __init__(self, steps: list[tuple]) -> None:
        self.steps = list(steps)
        self.seen_tool_names: list[str] = []
        self.system_prompts: list[str] = []
        self.config: dict[str, Any] = {"model_id": "scripted"}

    def update_config(self, **kw: Any) -> None:
        self.config.update(kw)

    def get_config(self) -> Any:
        return self.config

    async def structured_output(self, *a: Any, **k: Any):  # pragma: no cover
        raise NotImplementedError
        yield

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterator[dict]:
        self.system_prompts.append(system_prompt or "")
        if tool_specs and not self.seen_tool_names:
            self.seen_tool_names = [t["name"] for t in tool_specs]
        step = self.steps.pop(0) if self.steps else ("text", "done")
        if step[0] == "raise":
            raise RuntimeError(step[1])
        yield {"messageStart": {"role": "assistant"}}
        if step[0] == "tool":
            _, name, args = step
            yield {
                "contentBlockStart": {
                    "start": {"toolUse": {"toolUseId": f"t-{uuid.uuid4().hex[:8]}", "name": name}}
                }
            }
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(args)}}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": step[1]}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}
        yield {
            "metadata": {
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                "metrics": {"latencyMs": 1},
            }
        }
