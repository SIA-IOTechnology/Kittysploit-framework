# -*- coding: utf-8 -*-
"""Parse nmap XML (from -oX - or a saved file) into structured host/service dicts."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """Return ``{"hosts": [...], "scanner": "nmap", ...}`` from nmap XML text."""
    text = (xml_text or "").strip()
    if not text:
        return {"hosts": [], "scanner": "nmap"}

    # Nmap may print a progress line before the XML when mixed; keep from <nmaprun
    start = text.find("<nmaprun")
    if start > 0:
        text = text[start:]
    end = text.rfind("</nmaprun>")
    if end >= 0:
        text = text[: end + len("</nmaprun>")]

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid nmap XML: {exc}") from exc

    hosts: List[Dict[str, Any]] = []
    for host_el in root.findall("host"):
        parsed = _parse_host(host_el)
        if parsed:
            hosts.append(parsed)

    return {
        "hosts": hosts,
        "scanner": "nmap",
        "args": root.attrib.get("args") or "",
        "startstr": root.attrib.get("startstr") or "",
        "version": root.attrib.get("version") or "",
    }


def _parse_host(host_el: ET.Element) -> Optional[Dict[str, Any]]:
    address = ""
    mac = None
    for addr in host_el.findall("address"):
        addrtype = (addr.attrib.get("addrtype") or "").lower()
        value = (addr.attrib.get("addr") or "").strip()
        if not value:
            continue
        if addrtype in ("ipv4", "ipv6") and not address:
            address = value
        elif addrtype == "mac":
            mac = value

    if not address:
        return None

    status_el = host_el.find("status")
    status = (status_el.attrib.get("state") if status_el is not None else None) or "unknown"

    hostname = None
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        # Prefer user/PTR then first hostname
        preferred = None
        for hn in hostnames_el.findall("hostname"):
            name = (hn.attrib.get("name") or "").strip()
            if not name:
                continue
            htype = (hn.attrib.get("type") or "").lower()
            if htype in ("user", "ptr"):
                preferred = name
                break
            if preferred is None:
                preferred = name
        hostname = preferred

    os_name = None
    os_el = host_el.find("os")
    if os_el is not None:
        best = None
        best_acc = -1
        for match in os_el.findall("osmatch"):
            name = (match.attrib.get("name") or "").strip()
            try:
                acc = int(match.attrib.get("accuracy") or 0)
            except ValueError:
                acc = 0
            if name and acc > best_acc:
                best = name
                best_acc = acc
        os_name = best

    services: List[Dict[str, Any]] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            svc = _parse_port(port_el)
            if svc:
                services.append(svc)

    return {
        "address": address,
        "hostname": hostname,
        "mac": mac,
        "os": os_name,
        "status": "up" if status == "up" else ("down" if status == "down" else "unknown"),
        "services": services,
    }


def _parse_port(port_el: ET.Element) -> Optional[Dict[str, Any]]:
    try:
        port = int(port_el.attrib.get("portid") or 0)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None

    protocol = (port_el.attrib.get("protocol") or "tcp").lower()
    if protocol not in ("tcp", "udp"):
        return None

    state_el = port_el.find("state")
    state = (state_el.attrib.get("state") if state_el is not None else None) or "unknown"
    # Normalize nmap states we store
    if state not in ("open", "closed", "filtered", "unknown"):
        # open|filtered etc. → filtered for DB constraint
        if "open" in state and "filtered" in state:
            state = "filtered"
        elif state.startswith("open"):
            state = "open"
        elif state.startswith("closed"):
            state = "closed"
        else:
            state = "filtered"

    name = None
    version = None
    banner = None
    service_el = port_el.find("service")
    if service_el is not None:
        name = (service_el.attrib.get("name") or "").strip() or None
        product = (service_el.attrib.get("product") or "").strip()
        ver = (service_el.attrib.get("version") or "").strip()
        extrainfo = (service_el.attrib.get("extrainfo") or "").strip()
        tunnel = (service_el.attrib.get("tunnel") or "").strip()
        parts = [p for p in (product, ver) if p]
        version = " ".join(parts) if parts else None
        banner_bits = []
        if product:
            banner_bits.append(product)
        if ver:
            banner_bits.append(ver)
        if extrainfo:
            banner_bits.append(f"({extrainfo})")
        if tunnel:
            banner_bits.append(f"tunnel:{tunnel}")
        banner = " ".join(banner_bits) if banner_bits else None

    return {
        "port": port,
        "protocol": protocol,
        "state": state,
        "name": name,
        "version": version,
        "banner": banner,
    }
