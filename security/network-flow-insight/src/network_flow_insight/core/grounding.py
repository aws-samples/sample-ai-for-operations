# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check that prose contains no figure a tool did not produce.

Model-written text is allowed to repeat numbers that appear in the findings (raw, or formatted in decimal
units) and nothing else. Identifiers, addresses and dates are removed before the check.
"""

from __future__ import annotations

import re
from typing import Any

from .units import to_units

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}(?::\d{2})?)?\b")
_TIME = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")  # clock times such as 14:00
_ID = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+\b")  # runs in linear time on hostile input; matches ids such as subnet-0a1b, eni-0w1, vpc-0a01  # nosemgrep: regex_dos
_ACCOUNT = re.compile(r"\b\d{12}\b")
_DASHES = re.compile("[\u2010-\u2015\u2212]")  # hyphen, non-breaking hyphen, en/em dash, minus
_LIST_MARKER = re.compile(r"(?m)^[ \t]*(?:[-*+][ \t]+)?\d{1,2}[.)][ \t]+")  # "1. ", "- 2) " at the start of a line
# Flow logs aggregate over 1 or 10 minutes: a fact about the service that the method requires the agent to state.
_AGGREGATION_INTERVAL = re.compile(r"\b1\s*(?:or|-|to)\s*10[ -]min(?:ute)?s?\b", re.IGNORECASE)
_NUM = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?")


def _norm(tok: str) -> str:
    t = tok.replace(",", "")
    if "." in t:
        t = t.rstrip("0").rstrip(".")
    return t


def numbers_in(text: str) -> set[str]:
    t = _DASHES.sub("-", text)
    t = _LIST_MARKER.sub(" ", t)
    t = _AGGREGATION_INTERVAL.sub(" ", t)
    t = _DATE.sub(" ", t)
    t = _TIME.sub(" ", t)
    t = _IP.sub(" ", t)
    t = _ACCOUNT.sub(" ", t)
    t = _ID.sub(" ", t)
    return {_norm(m) for m in _NUM.findall(t)}


def known_numbers(obj: Any) -> set[str]:
    out: set[str] = set()

    def walk(o: Any) -> None:
        if isinstance(o, bool) or o is None:
            return
        if isinstance(o, int | float):
            out.add(_norm(str(o)))
            if isinstance(o, float):
                for places in (1, 2, 3, 4):  # the same figure shown to fewer decimals
                    out.add(_norm(f"{o:.{places}f}"))
            if isinstance(o, int) and abs(o) >= 1000:
                u = to_units(o)
                out.add(_norm(str(u["value"])))
        elif isinstance(o, str):
            out.update(numbers_in(o))
        elif isinstance(o, dict):
            for k, v in o.items():
                out.update(numbers_in(str(k)))
                walk(v)
        elif isinstance(o, list | tuple | set):
            for v in o:
                walk(v)

    walk(obj)
    return out


def ungrounded(text: str, findings: Any) -> list[str]:
    """Numbers in ``text`` that appear nowhere in ``findings``."""
    known = known_numbers(findings)
    return sorted(n for n in numbers_in(text) if n not in known)
