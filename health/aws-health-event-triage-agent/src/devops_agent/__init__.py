# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""AWS DevOps Agent incident gate (Phase 1b, R12 incident gate only).

Deterministic wrapper around AWS DevOps Agent investigations: decides
whether an event is eligible for investigation, resolves the target Agent
Space, triggers a webhook investigation with a Step Functions task token,
and folds the outcome back into the existing ticket via the Phase 5 sink
dispatcher. No tool in this package calls an LLM — DevOps Agent's own agent
loop does the reasoning; this package is pure orchestration and parsing.
"""
