# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Classifier Lambda handler.

Step Functions invokes this Lambda with a payload containing the eventArn and
the loaded consolidated event dict, and delegates only to ClassifierService.
ComputeUrgency and DecideDisposition are separate states in the workflow
(design.md's state diagram: Classify --> ComputeUrgency --> DecideDisposition),
each its own Lambda invocation — this handler does not compute either, per
the tool-classification rule (ai-agent-standards): the classifier is the
agentic-reasoning step, urgency/disposition are precision steps, and they
must not be fused into one Lambda invocation from the workflow's perspective.

Input (from Step Functions LoadEvent output):
    {
        "eventArn": "arn:aws:health:...",
        "event": { ...consolidated event dict... }
    }

Output:
    {
        "eventArn": "...",
        "classification": "...",
        "reason": "...",
        "deadline": "...",
        "deadline_basis": "...",
        "verification_steps": [...],
        "notes_for_operator": "..."
    }
"""

from __future__ import annotations

import json
import logging
import os

from src import config
from src.classifier.service import ClassifierService

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Module-level service (warm Lambda re-use)
_service = ClassifierService()


def handler(event: dict, context) -> dict:
    """Lambda handler: classify only.

    Args:
        event: Step Functions task input with 'eventArn' and 'event' keys.
        context: Lambda context (unused).

    Returns:
        The ClassificationResult dict, plus eventArn, for the next Step
        Functions state (ComputeUrgency).
    """
    event_arn = event.get("eventArn", "")
    consolidated = event.get("event", event)  # fallback: treat whole input as event

    if isinstance(consolidated, str):
        try:
            consolidated = json.loads(consolidated)
        except json.JSONDecodeError:
            consolidated = {}

    logger.info(json.dumps({
        "message": "Classifier Lambda invoked",
        "event_arn": event_arn,
        "service": consolidated.get("service", ""),
        "event_type_code": consolidated.get("eventTypeCode", ""),
    }))

    result = _service.classify(consolidated)
    classification = result.get("classification", "UNCLASSIFIED")

    output = {
        "eventArn": event_arn,
        "classification": classification,
        "reason": result.get("reason", ""),
        "deadline": result.get("deadline"),
        "deadline_basis": result.get("deadline_basis"),
        "verification_steps": result.get("verification_steps", []),
        "notes_for_operator": result.get("notes_for_operator"),
    }

    logger.info(json.dumps({
        "message": "Classification complete",
        "event_arn": event_arn,
        "classification": classification,
    }))

    return output
