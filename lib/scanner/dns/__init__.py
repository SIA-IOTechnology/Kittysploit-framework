# -*- coding: utf-8 -*-
"""DNS scanner helpers (inspired by NSE dns-* scripts)."""

from lib.scanner.dns.detectors import (
    probe_dns_nsid,
    probe_dns_recursion,
    probe_dns_srv_enum,
    probe_dns_zone_transfer,
    probe_dns_cache_snoop,
    probe_dns_brute,
    probe_dns_update,
)

__all__ = [
    "probe_dns_nsid",
    "probe_dns_recursion",
    "probe_dns_srv_enum",
    "probe_dns_zone_transfer",
    "probe_dns_cache_snoop",
    "probe_dns_brute",
    "probe_dns_update",
]
