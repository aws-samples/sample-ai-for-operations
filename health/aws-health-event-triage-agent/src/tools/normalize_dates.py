# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Agent tool: normalize_dates.

Precision tool that converts date phrases found in event descriptions into
ISO 8601 (YYYY-MM-DD) dates. Deterministic — never calls the LLM.

Uses dateutil.parser for flexible date parsing. Returns an empty list (never
raises) so the agent can proceed even if no dates can be extracted.
"""

from __future__ import annotations

import logging
import re

from strands import tool

logger = logging.getLogger(__name__)


def _try_parse(phrase: str) -> str | None:
    """Attempt to parse a date phrase and return ISO 8601 or None."""
    # Fast path: already ISO 8601
    iso_re = re.fullmatch(r"\d{4}-\d{2}-\d{2}", phrase.strip())
    if iso_re:
        return phrase.strip()

    try:
        from dateutil import parser as dateutil_parser
        dt = dateutil_parser.parse(phrase, fuzzy=True)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return None


@tool
def normalize_dates(text: str) -> list:
    """Parse date phrases in event text and return ISO 8601 representations.

    Scans the provided text for date-like patterns (e.g. "June 30, 2026",
    "2026-09-01", "before October 31st 2026") and returns each as a pair of
    the original phrase and its ISO 8601 equivalent.

    The classifier agent calls this to convert any deadline phrase extracted
    from the event description into a canonical date. The agent then reports
    the returned `isoDate` as the `deadline` field.

    Args:
        text: Free-form text containing one or more date phrases.

    Returns:
        List of dicts, each with keys:
          - phrase: the matched text fragment
          - isoDate: the ISO 8601 date string (YYYY-MM-DD)
        Returns an empty list when no parseable dates are found.
    """
    if not text or not isinstance(text, str):
        return []

    results: list[dict] = []
    seen_dates: set[str] = set()

    # Patterns for common date formats in AWS Health events
    patterns = [
        # ISO: 2026-09-01
        r"\b\d{4}-\d{2}-\d{2}\b",
        # Month D, YYYY:  June 30, 2026  /  June 30th, 2026
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)" +
        r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b",
        # D Month YYYY: 30 June 2026
        r"\b\d{1,2}(?:st|nd|rd|th)?\s+(?:January|February|March|April|May|June|July|August" +
        r"|September|October|November|December)\s+\d{4}\b",
        # Quarter expressions: Q1 2026
        r"\bQ[1-4]\s+\d{4}\b",
    ]

    for pattern in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            phrase = m.group(0).strip()
            iso = _try_parse(phrase)
            if iso and iso not in seen_dates:
                results.append({"phrase": phrase, "isoDate": iso})
                seen_dates.add(iso)

    return results
