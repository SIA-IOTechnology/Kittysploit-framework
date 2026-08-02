#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""mDNS / DNS-SD helpers."""

from lib.scanner.mdns.client import (
    MDNS_ADDR,
    MDNS_PORT,
    MdnsClient,
    MdnsEnumResult,
    MdnsService,
    parse_dns_message,
)
from lib.scanner.mdns.detectors import (
    DEFAULT_IOT_QUERIES,
    IOT_MDNS_HANDOFF,
    normalize_service_type,
    probe_mdns,
    probe_mdns_enum,
    probe_mdns_iot,
    suggest_modules_from_mdns,
)
from lib.scanner.mdns.session import MdnsProbeMixin

__all__ = [
    "DEFAULT_IOT_QUERIES",
    "IOT_MDNS_HANDOFF",
    "MDNS_ADDR",
    "MDNS_PORT",
    "MdnsClient",
    "MdnsEnumResult",
    "MdnsProbeMixin",
    "MdnsService",
    "normalize_service_type",
    "parse_dns_message",
    "probe_mdns",
    "probe_mdns_enum",
    "probe_mdns_iot",
    "suggest_modules_from_mdns",
]
