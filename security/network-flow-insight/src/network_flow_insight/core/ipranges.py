# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""AWS public IP ranges (``ip-ranges.json``) with most-specific matching.

A match returns the services listed on the longest matching prefix. ``AMAZON`` and ``EC2`` are
generic: an address whose longest match carries only those is "AWS-hosted, unverified", never an AWS
service. Only IPv4 is handled in v1; IPv6 addresses are reported as unclassified.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import ssl
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GENERIC_SERVICES = frozenset({"AMAZON", "EC2", "AMAZON_CONNECT", "ROUTE53_HEALTHCHECKS_PUBLISHING"})
_RFC1918 = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)
CACHE_MAX_AGE_SECONDS = 24 * 3600


def is_private(ip: str) -> bool:
    """RFC 1918 plus 100.64.0.0/10. Documentation ranges are deliberately *not* private."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in _RFC1918)


@dataclass(frozen=True)
class RangeMatch:
    cidr: str
    services: tuple[str, ...]
    regions: tuple[str, ...]

    @property
    def specific_services(self) -> tuple[str, ...]:
        return tuple(s for s in self.services if s not in GENERIC_SERVICES)


class IpRanges:
    def __init__(self, document: dict[str, Any]) -> None:
        # prefix length -> network int -> (cidr, services, regions)
        self._by_len: dict[int, dict[int, tuple[str, set[str], set[str]]]] = {}
        self.sync_token = str(document.get("syncToken", ""))
        self.create_date = str(document.get("createDate", ""))
        for p in document.get("prefixes", []):
            net = ipaddress.ip_network(p["ip_prefix"])
            slot = self._by_len.setdefault(net.prefixlen, {})
            key = int(net.network_address)
            cidr, svcs, regs = slot.setdefault(key, (p["ip_prefix"], set(), set()))
            svcs.add(p["service"])
            regs.add(p.get("region", ""))
        self._lens = sorted(self._by_len, reverse=True)
        self._cache: dict[str, RangeMatch | None] = {}

    def lookup(self, ip: str) -> RangeMatch | None:
        if ip in self._cache:
            return self._cache[ip]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        res: RangeMatch | None = None
        if a.version == 4:
            n = int(a)
            for plen in self._lens:
                mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
                hit = self._by_len[plen].get(n & mask)
                if hit:
                    res = RangeMatch(hit[0], tuple(sorted(hit[1])), tuple(sorted(hit[2])))
                    break
        self._cache[ip] = res
        return res


def _ssl_context() -> ssl.SSLContext:
    """Verify against the CA bundle boto3 uses, so python.org builds without system roots still work."""
    try:
        from botocore.httpsession import get_cert_path

        return ssl.create_default_context(cafile=get_cert_path(True))
    except Exception:  # fall back to the interpreter's default trust store
        return ssl.create_default_context()


def load_document(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def fetch_document(url: str, cache_dir: str | Path | None = None, timeout: int = 30) -> dict[str, Any]:
    """Download ``ip-ranges.json`` over HTTPS, with a one-day file cache."""
    if not url.startswith("https://"):
        raise ValueError("ip ranges URL must use https://")
    cache = Path(cache_dir) / "ip-ranges.json" if cache_dir else None
    if cache and cache.is_file() and time.time() - cache.stat().st_mtime < CACHE_MAX_AGE_SECONDS:
        return json.loads(cache.read_text())
    req = urllib.request.Request(url, headers={"User-Agent": "network-flow-insight"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:  # noqa: S310  # nosec B310 - https enforced above  # nosemgrep: dynamic-urllib-use-detected
        doc = json.loads(resp.read())
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(doc))
    return doc
