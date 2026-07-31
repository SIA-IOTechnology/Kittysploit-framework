#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Broadcast / multicast discovery probes (NSE broadcast-dhcp / wpad / wsdd)."""

from __future__ import annotations

import random
import socket
import struct
import uuid
from typing import Dict, List, Optional
from urllib.request import Request, urlopen


def probe_broadcast_dhcp(
    timeout: float = 5.0,
    iface: str = "",
) -> Dict[str, object]:
    """
    Send DHCP DISCOVER and collect offers (NSE broadcast-dhcp-discover).
    Requires scapy; may need admin/raw socket privileges.
    """
    result: Dict[str, object] = {
        "detected": False,
        "offers": [],
        "error": "",
    }
    try:
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, srp1  # type: ignore
    except Exception as exc:
        result["error"] = f"scapy_required:{exc}"
        return result

    try:
        if iface:
            conf.iface = iface
        mac = "de:ad:c0:de:ca:fe"
        mac_bytes = bytes(int(x, 16) for x in mac.split(":"))
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=mac_bytes + b"\x00" * 10, xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15, 51]), "end"])
        )
        ans = srp1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            result["error"] = "no_offer"
            return result
        offer: Dict[str, object] = {}
        bootp = ans.getlayer(BOOTP)
        if bootp:
            offer["yiaddr"] = str(getattr(bootp, "yiaddr", "") or "")
            offer["siaddr"] = str(getattr(bootp, "siaddr", "") or "")
        dhcp = ans.getlayer(DHCP)
        if dhcp and dhcp.options:
            for opt in dhcp.options:
                if not isinstance(opt, tuple):
                    continue
                name, val = opt[0], opt[1] if len(opt) > 1 else ""
                if name in ("server_id", "router", "subnet_mask", "name_server", "domain", "lease_time"):
                    offer[str(name)] = str(val)
        result["offers"] = [offer]
        result["detected"] = True
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_broadcast_wpad(
    domain: str = "",
    timeout: float = 5.0,
) -> Dict[str, object]:
    """
    WPAD discovery via DNS + HTTP wpad.dat (NSE broadcast-wpad-discover inspired).
    """
    result: Dict[str, object] = {
        "detected": False,
        "wpad_hosts": [],
        "pac_urls": [],
        "pac_preview": "",
        "error": "",
    }
    candidates: List[str] = ["wpad"]
    domain = (domain or "").strip().strip(".")
    if domain:
        candidates.append(f"wpad.{domain}")
    hosts: List[str] = []
    for name in candidates:
        try:
            infos = socket.getaddrinfo(name, 80, type=socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                hosts.append(f"{name}/{ip}")
        except Exception:
            continue
    result["wpad_hosts"] = hosts[:10]
    pac_urls = []
    for name in candidates:
        for scheme in ("http",):
            url = f"{scheme}://{name}/wpad.dat"
            try:
                req = Request(url, headers={"User-Agent": "KittySploit-WPAD"})
                with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    body = resp.read(2048)
                    if body and (b"FindProxy" in body or b"PROXY" in body or b"function" in body):
                        pac_urls.append(url)
                        if not result["pac_preview"]:
                            result["pac_preview"] = body.decode("utf-8", errors="replace")[:300]
            except Exception:
                continue
    result["pac_urls"] = pac_urls
    result["detected"] = bool(hosts or pac_urls)
    if not result["detected"]:
        result["error"] = "no_wpad"
    return result


_WSDD_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <soap:Header>
  <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  <wsa:MessageID>uuid:{msg_id}</wsa:MessageID>
  <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
 </soap:Header>
 <soap:Body>
  <wsd:Probe/>
 </soap:Body>
</soap:Envelope>
"""


def probe_broadcast_wsdd(timeout: float = 3.0) -> Dict[str, object]:
    """WS-Discovery Probe multicast (NSE broadcast-wsdd-discover)."""
    result: Dict[str, object] = {
        "detected": False,
        "endpoints": [],
        "error": "",
    }
    msg = _WSDD_PROBE.format(msg_id=str(uuid.uuid4())).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 3702))
        endpoints: List[str] = []
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            text = data.decode("utf-8", errors="replace")
            # Extract XAddrs / Addresses
            import re

            found = re.findall(r"https?://[^\s<>\"]+", text)
            entry = f"{addr[0]}:" + (",".join(found[:3]) if found else "probe-match")
            endpoints.append(entry[:200])
            if len(endpoints) >= 20:
                break
        result["endpoints"] = endpoints
        result["detected"] = bool(endpoints)
        if not endpoints:
            result["error"] = "no_wsdd_replies"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()
