# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The tool layer, one module per tool.

Data retrieval tools call AWS and return structured data. Precision tools are pure Python over
structured data and are the only source of any number in any output. No tool runs a model.
``network_flow_insight.toolset`` binds these functions to a session so that a model (or an MCP host)
passes short references instead of data.
"""
