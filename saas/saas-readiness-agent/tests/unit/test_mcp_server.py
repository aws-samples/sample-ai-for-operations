# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the optional MCP wrapper (src/mcp_server.py).

The MCP path must return exactly what the deterministic core computed and
must surface validation errors as structured data, never as tracebacks.
These tests never start a server process or open a socket.
"""

import asyncio
import importlib.util
import json
import unittest
from pathlib import Path

from src import mcp_server
from src.assessment_core import assess_payload, to_plain
from src.mcp_server import assess, build_server

MCP_INSTALLED = importlib.util.find_spec("mcp") is not None


class McpAssessTests(unittest.TestCase):
    def test_assess_matches_direct_assess_payload_call(self):
        sample = json.loads(Path("samples/minimal_assessment.json").read_text(encoding="utf-8"))

        via_mcp = assess(sample)
        direct = to_plain(assess_payload(sample))

        self.assertEqual(direct["overall_score"], via_mcp["overall_score"])
        self.assertEqual(direct["overall_confidence"], via_mcp["overall_confidence"])
        self.assertEqual(direct["assessment_id"], via_mcp["assessment_id"])
        self.assertTrue(via_mcp["report_html"].lstrip().lower().startswith("<!doctype html"))

    def test_assess_returns_structured_error_for_invalid_payload(self):
        result = assess([])  # type: ignore[arg-type]

        self.assertEqual("validation_error", result["error"]["code"])
        self.assertNotIn("report_html", result)


class McpServerConstructionTests(unittest.TestCase):
    @unittest.skipUnless(MCP_INSTALLED, "mcp package not installed")
    def test_build_server_registers_only_the_assessment_tool(self):
        server = build_server()

        tools = asyncio.run(server.list_tools())

        self.assertEqual({"run_saas_readiness_assessment"}, {tool.name for tool in tools})

    def test_build_server_raises_clear_error_when_mcp_missing(self):
        original = mcp_server.FastMCP
        mcp_server.FastMCP = None  # type: ignore[assignment]
        try:
            with self.assertRaises(RuntimeError) as ctx:
                build_server()
        finally:
            mcp_server.FastMCP = original  # type: ignore[assignment]

        self.assertIn("mcp", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
