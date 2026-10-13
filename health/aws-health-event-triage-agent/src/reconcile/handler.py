# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Optional reconciliation Lambda — catches missed events via polling.

Disabled by default (RECONCILE_ENABLED must be set to "true").

Polls DescribeEventsForOrganization from a stored watermark, then calls
DescribeEventDetailsForOrganization (10 per batch) and
DescribeAffectedAccountsForOrganization, and enqueues the results as
EventBridge-shaped messages on the SQS intake queue so the Intake Lambda
handles them identically to native EventBridge deliveries.

This is a Phase 1 placeholder — the full implementation will be completed
in a dedicated working spec.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)

RECONCILE_ENABLED = os.environ.get("RECONCILE_ENABLED", "false").lower() == "true"


def handler(event: dict, context) -> dict:
    """Lambda handler for the optional reconciliation job.

    Triggered on a schedule (e.g., EventBridge Scheduler, every 15 minutes).
    Returns early if RECONCILE_ENABLED is not set to 'true'.
    """
    if not RECONCILE_ENABLED:
        logger.info("RECONCILE_ENABLED is not set — reconciliation is disabled")
        return {"status": "disabled"}

    # Placeholder — full implementation in a dedicated Phase 1+ working spec.
    logger.info("Reconciliation Lambda invoked (full implementation pending)")
    return {"status": "not_implemented", "message": "Reconciliation not yet implemented"}
