#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mDNS / DNS-SD probe helpers with IoT service-type handoff."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from lib.scanner.mdns.client import MdnsClient, parse_dns_message


# Service type → KittySploit module handoff
IOT_MDNS_HANDOFF: Dict[str, str] = {
    "_mqtt._tcp": "listeners/iot/mqtt",
    "_mqtt-tls._tcp": "listeners/iot/mqtt",
    "_coap._udp": "listeners/iot/coap_client",
    "_coaps._udp": "listeners/iot/coap_client",
    "_onvif._tcp": "listeners/iot/onvif_client",
    "_rtsp._tcp": "listeners/iot/rtsp_client",
    "_axis-video._tcp": "listeners/iot/onvif_client",
    "_hap._tcp": "auxiliary/admin/http/camera/onvif_device_info",
    "_homekit._tcp": "auxiliary/admin/http/camera/onvif_device_info",
    "_http._tcp": "scanner/http/openwrt_detect",
    "_https._tcp": "scanner/http/openwrt_luci_detect",
    "_ipp._tcp": "scanner/udp/mdns_enum",
    "_printer._tcp": "scanner/udp/mdns_enum",
    "_airplay._tcp": "scanner/udp/mdns_enum",
    "_raop._tcp": "scanner/udp/mdns_enum",
    "_googlecast._tcp": "scanner/udp/mdns_enum",
    "_spotify-connect._tcp": "scanner/udp/mdns_enum",
    "_ssh._tcp": "listeners/multi/bind_tcp",
    "_sftp-ssh._tcp": "listeners/multi/bind_tcp",
    "_smb._tcp": "scanner/udp/mdns_enum",
    "_companion-link._tcp": "scanner/udp/mdns_enum",
    "_matter._tcp": "listeners/iot/matter_client",
    "_matterc._udp": "listeners/iot/matter_client",
    "_hap._udp": "scanner/udp/mdns_enum",
    "_nanoleafapi._tcp": "scanner/udp/mdns_enum",
    "_hue._tcp": "scanner/udp/mdns_enum",
    "_philipshue._tcp": "scanner/udp/mdns_enum",
    "_sonos._tcp": "listeners/iot/upnp_client",
    "_androidtvremote2._tcp": "scanner/udp/mdns_enum",
    "_nvstream_dbd._tcp": "scanner/udp/mdns_enum",
    "_workstation._tcp": "scanner/udp/mdns_enum",
    "_device-info._tcp": "scanner/udp/mdns_enum",
}

DEFAULT_IOT_QUERIES: Tuple[str, ...] = (
    "_services._dns-sd._udp.local",
    "_mqtt._tcp.local",
    "_mqtt-tls._tcp.local",
    "_coap._udp.local",
    "_coaps._udp.local",
    "_onvif._tcp.local",
    "_rtsp._tcp.local",
    "_axis-video._tcp.local",
    "_hap._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ipp._tcp.local",
    "_airplay._tcp.local",
    "_googlecast._tcp.local",
    "_ssh._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_sonos._tcp.local",
    "_hue._tcp.local",
    "_device-info._tcp.local",
)


def _parse_answer_names(data: bytes) -> List[str]:
    """Extract service-ish names from a raw mDNS response (legacy helper)."""
    names: List[str] = []
    seen = set()
    for rec in parse_dns_message(data):
        for candidate in (rec.name, rec.text):
            text = str(candidate or "").strip()
            if not text or text in seen:
                continue
            low = text.lower()
            if any(
                x in low
                for x in (
                    "local",
                    "_tcp",
                    "_udp",
                    "mqtt",
                    "onvif",
                    "coap",
                    "hap",
                    "rtsp",
                    "matter",
                    "http",
                )
            ):
                seen.add(text)
                names.append(text[:160])
        if len(names) >= 32:
            break
    return names


def normalize_service_type(name: str) -> str:
    """Collapse ``foo._mqtt._tcp.local`` → ``_mqtt._tcp``."""
    low = str(name or "").strip().lower().rstrip(".")
    for key in IOT_MDNS_HANDOFF:
        if key in low:
            return key
    parts = [p for p in low.split(".") if p]
    for i, part in enumerate(parts):
        if part.startswith("_") and i + 1 < len(parts) and parts[i + 1] in ("_tcp", "_udp"):
            return f"{part}.{parts[i + 1]}"
    return low


def suggest_modules_from_mdns(services: List[str]) -> List[str]:
    """Map discovered mDNS names to framework modules."""
    suggested: List[str] = []
    for name in services or []:
        key = normalize_service_type(name)
        module = IOT_MDNS_HANDOFF.get(key)
        if module and module not in suggested:
            suggested.append(module)
        if not module:
            for hint, mod in IOT_MDNS_HANDOFF.items():
                if hint in key and mod not in suggested:
                    suggested.append(mod)
                    break
    return suggested[:12]


def probe_mdns(
    host: str,
    port: int = 5353,
    timeout: float = 3.0,
    *,
    query_name: str = "_services._dns-sd._udp.local",
) -> Dict[str, object]:
    """Unicast mDNS query to a target (many IoT stacks answer unicast)."""
    client = MdnsClient(timeout=timeout, port=port)
    records = client.query_unicast(host, query_name, qtype=12)
    if not records and client.last_error:
        return {
            "detected": False,
            "services": [],
            "query": query_name,
            "error": client.last_error,
        }
    if not records:
        return {
            "detected": False,
            "services": [],
            "query": query_name,
            "error": "timeout" if not client.last_error else client.last_error,
        }
    # Build a synthetic packet-less name list from records
    names: List[str] = []
    seen = set()
    for rec in records:
        for candidate in (rec.name, rec.text):
            text = str(candidate or "").strip()
            if text and text not in seen:
                seen.add(text)
                names.append(text[:160])
    return {
        "detected": True,
        "services": names[:32],
        "query": query_name,
        "error": "",
    }


def probe_mdns_iot(
    host: str,
    port: int = 5353,
    timeout: float = 2.0,
    *,
    queries: Tuple[str, ...] | None = None,
    multicast: bool = False,
) -> Dict[str, Any]:
    """
    Probe common IoT DNS-SD types and aggregate service names + module handoffs.
    """
    client = MdnsClient(timeout=timeout, port=port)
    result = client.enumerate(
        host=host,
        queries=queries or DEFAULT_IOT_QUERIES,
        multicast=multicast,
        resolve_srv=False,
    )
    return {
        "detected": result.detected,
        "services": result.names,
        "queries_hit": result.queries_hit,
        "suggested_modules": result.suggested_modules,
        "error": result.error,
        "mode": result.mode,
    }


def probe_mdns_enum(
    host: str = "",
    port: int = 5353,
    timeout: float = 2.5,
    *,
    multicast: bool = False,
    queries: Tuple[str, ...] | None = None,
) -> Dict[str, Any]:
    """Deep enum with SRV/TXT/A correlation."""
    client = MdnsClient(timeout=timeout, port=port)
    result = client.enumerate(
        host=host,
        queries=queries or DEFAULT_IOT_QUERIES,
        multicast=multicast or not host,
        resolve_srv=True,
    )
    return {
        "detected": result.detected,
        "services": [
            {
                "instance": s.instance,
                "service_type": s.service_type,
                "host": s.host,
                "port": s.port,
                "addresses": list(s.addresses),
                "txt": dict(s.txt),
            }
            for s in result.services
        ],
        "names": result.names,
        "queries_hit": result.queries_hit,
        "suggested_modules": result.suggested_modules,
        "error": result.error,
        "mode": result.mode,
    }
