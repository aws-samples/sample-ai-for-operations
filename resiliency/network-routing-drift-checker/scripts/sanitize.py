# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Consistent, deterministic sanitization of recorded AWS responses before they touch disk.

- 12-digit account IDs  -> 123456789012, 210987654321, ... (stable per real value)
- resource IDs (tgw-, tgw-rtb-, tgw-attach-, vpc-, dxvif-, dxcon-, core-network-, attachment-,
  global-network-, vpn-, dxlag-, ...) -> same prefix + counter (tgw-0000000000000001)
- UUIDs (DX gateway IDs, association IDs) -> 0000000N-aaaa-4aaa-8aaa-aaaaaaaaaaaa
- IPv4 addresses in 10/8, 172.16/12, 192.168/16 and 169.254/16 are kept (private, structural);
  any other IPv4 is replaced from 198.51.100.0/24 (documentation range)
- tag values are kept; tag VALUES that look like e-mail addresses are replaced
- keys known to hold secrets (authKey) are blanked
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_ID_RE = re.compile(
    r"\b(tgw-rtb|tgw-attach|tgw|vpc-attach|vpc|subnet|dxvif|dxcon|dxlag|dxgw|vpn|vgw|cgw|"
    r"core-network|attachment|global-network|eni|pl|rtb)-([0-9a-f]{8,17})\b")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.IGNORECASE)
_SECRET_KEYS = {"authKey", "AuthKey"}
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                              "0.0.0.0/32")]
_PLACEHOLDER_ACCOUNTS = ["123456789012", "210987654321", "111122223333", "444455556666", "777788889999"]


class Sanitizer:
    def __init__(self) -> None:
        self.accounts: dict[str, str] = {}
        self.ids: dict[str, str] = {}
        self.uuids: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def _account(self, m: re.Match) -> str:
        real = m.group(1)
        if real in _PLACEHOLDER_ACCOUNTS:
            return real
        if real not in self.accounts:
            n = len(self.accounts)
            self.accounts[real] = _PLACEHOLDER_ACCOUNTS[n] if n < len(_PLACEHOLDER_ACCOUNTS) else f"{999000000000 + n}"
        return self.accounts[real]

    def _id(self, m: re.Match) -> str:
        full, prefix, suffix = m.group(0), m.group(1), m.group(2)
        if full not in self.ids:
            self._counters[prefix] = self._counters.get(prefix, 0) + 1
            self.ids[full] = f"{prefix}-{self._counters[prefix]:0{len(suffix)}x}"
        return self.ids[full]

    def _uuid(self, m: re.Match) -> str:
        real = m.group(0)
        if real not in self.uuids:
            # Letters in every group so no later pass (e.g. the 12-digit account pattern) can match it.
            self.uuids[real] = f"{len(self.uuids) + 1:08d}-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        return self.uuids[real]

    def _ip(self, m: re.Match) -> str:
        text = m.group(1)
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return text
        if any(addr in net for net in _PRIVATE):
            return text
        if text not in self.ips:
            self.ips[text] = f"198.51.100.{(len(self.ips) % 254) + 1}"
        return self.ips[text]

    def string(self, value: str) -> str:
        value = _UUID_RE.sub(self._uuid, value)
        value = _ID_RE.sub(self._id, value)
        value = _ACCOUNT_RE.sub(self._account, value)
        value = _IPV4_RE.sub(self._ip, value)
        return _EMAIL_RE.sub("user@example.com", value)

    def __call__(self, obj: Any, key: str | None = None) -> Any:
        if key in _SECRET_KEYS:
            return ""
        if isinstance(obj, dict):
            return {self.string(str(k)) if k not in _SECRET_KEYS else k: self(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self(v) for v in obj]
        if isinstance(obj, str):
            return self.string(obj)
        if isinstance(obj, int) and not isinstance(obj, bool) and len(str(obj)) == 12:
            return int(self.string(str(obj)))
        return obj


def leaks(obj: Any, real_values: set[str]) -> list[str]:
    """Return any real value still present anywhere in obj (post-sanitization self-check)."""
    text = repr(obj)
    return sorted(v for v in real_values if v and v in text)
