#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Network / pivot recon for OpenWrt / BusyBox shells."""

from kittysploit import *
from lib.post.linux.session import LinuxSessionMixin
import os
import time


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "OpenWrt / BusyBox Network Recon",
        "description": (
            "Enumerate interfaces, routes, ARP/neighbors, DNS, and listening "
            "sockets on an embedded Linux shell for LAN/WAN pivot planning."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["iot", "openwrt", "busybox", "gather", "pivot"],
        "references": ["https://attack.mitre.org/techniques/T1016/"],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["network_map"],
                "suggested_followups": [
                    "post/shell/linux/pivot/scan_internal_network",
                ],
            },
        },
    }

    save_local = OptBool(True, "Save report under ./output", False)

    def run(self):
        if not self.linux_require_linux():
            return False

        commands = (
            ("ifconfig -a 2>/dev/null || ip addr 2>/dev/null", "interfaces"),
            ("route -n 2>/dev/null || ip route 2>/dev/null", "routes"),
            ("cat /proc/net/route 2>/dev/null", "proc routes"),
            ("arp -an 2>/dev/null || ip neigh 2>/dev/null || cat /proc/net/arp 2>/dev/null", "neighbors"),
            ("cat /etc/resolv.conf 2>/dev/null", "DNS"),
            ("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || cat /proc/net/tcp 2>/dev/null | head -n 40", "listeners"),
            ("brctl show 2>/dev/null", "bridges"),
            ("iwconfig 2>/dev/null || iwinfo 2>/dev/null | head -n 80", "wireless"),
            ("uci show network 2>/dev/null | head -n 80", "uci network"),
            ("uci show firewall 2>/dev/null | head -n 80", "uci firewall"),
        )

        sections = []
        print_status("Collecting embedded network / pivot information...")
        for cmd, label in commands:
            out = (self.cmd_execute(cmd) or "").strip()
            if not out or "not found" in out.lower():
                continue
            sections.append(f"=== {label} ===\n{out}")
            print_success(f"{label}: {len(out.splitlines())} line(s)")

        if not sections:
            print_warning("No network data returned")
            return True

        report = "\n\n".join(sections)
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"openwrt_network_{stamp}.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(report + "\n")
            print_success(f"Saved ./{path}")
        print_info(report[:3000] + ("\n...[truncated]..." if len(report) > 3000 else ""))
        print_success("Network recon completed")
        return True
