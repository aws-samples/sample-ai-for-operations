# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A stdio MCP server over the tool layer. No model and no agent loop: the host brings its own.

The host's model calls the same session tools the packaged agent uses (``toolset.ToolSession``), so figures
are identical across surfaces. Nothing here listens on a socket; stdio only.
"""

from __future__ import annotations

from typing import Any

from .toolset import ToolSession, tool_methods

INSTRUCTIONS = (
    "Evidence-backed traffic map from VPC Flow Logs. Call probe first and state the tier and inventory provider. "
    "Call describe once per window (one raw scan), then read sections. Every figure must come from a tool result; "
    "never compute a number yourself. Show the reconciliation result beside any NAT share. State blind spots."
)


def _server_class() -> Any:
    try:
        from mcp.server.mcpserver import MCPServer

        return MCPServer
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP

        return FastMCP


def build_server(session: ToolSession) -> Any:
    server = _server_class()("network-flow-insight", instructions=INSTRUCTIONS)
    for fn in tool_methods(session):
        server.add_tool(fn, name=fn.__name__, description=(fn.__doc__ or "").strip())
    return server


def serve(session: ToolSession) -> None:  # pragma: no cover - blocks on stdio
    build_server(session).run(transport="stdio")
