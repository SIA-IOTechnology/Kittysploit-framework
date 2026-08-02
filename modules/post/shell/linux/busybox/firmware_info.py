#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Gather OpenWrt / embedded firmware identity from a BusyBox-style shell."""

from kittysploit import *
from lib.post.linux.session import LinuxSessionMixin
import os
import time


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "OpenWrt / BusyBox Firmware Info",
        "description": (
            "Collect firmware/board identity from an embedded Linux shell: "
            "openwrt_release, board name, uname, and common version files."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["iot", "openwrt", "busybox", "gather"],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "produces": ["tech_hints"],
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["ot_assets"],
                "suggested_followups": [
                    "post/shell/linux/busybox/dump_nvram",
                    "post/shell/linux/busybox/network_recon",
                    "post/shell/linux/busybox/deploy_embedded_c2",
                ],
            },
        },
    }

    save_local = OptBool(True, "Save report under ./output", False)

    _FILES = (
        "/etc/openwrt_release",
        "/etc/openwrt_version",
        "/etc/device_info",
        "/etc/board.json",
        "/tmp/sysinfo/board_name",
        "/tmp/sysinfo/model",
        "/proc/version",
        "/proc/cpuinfo",
        "/etc/banner",
    )

    def run(self):
        if not self.linux_require_linux():
            return False

        sections = []
        print_status("Collecting OpenWrt / BusyBox firmware identity...")

        for cmd, label in (
            ("uname -a 2>/dev/null", "uname"),
            ("cat /etc/os-release 2>/dev/null", "os-release"),
            ("which busybox 2>/dev/null; busybox 2>&1 | head -n 2", "busybox"),
        ):
            out = (self.cmd_execute(cmd) or "").strip()
            if out:
                sections.append(f"=== {label} ===\n{out}")
                print_info(f"{label}: {out.splitlines()[0][:120]}")

        for path in self._FILES:
            out = (self.cmd_execute(f"cat {path} 2>/dev/null") or "").strip()
            if out and "No such file" not in out and "can't open" not in out.lower():
                sections.append(f"=== {path} ===\n{out}")
                print_success(f"Found {path}")

        if not sections:
            print_warning("No firmware identity files found")
            return True

        report = "\n\n".join(sections)
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"openwrt_firmware_{stamp}.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(report + "\n")
            print_success(f"Saved ./{path}")
        print_success("Firmware info collection completed")
        return True
