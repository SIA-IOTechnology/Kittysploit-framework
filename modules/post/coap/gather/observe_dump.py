#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Collect CoAP Observe notifications for a resource over a time window."""

from kittysploit import *
from lib.protocols.coap.client import COAP_PORT
from lib.protocols.coap.session import CoapSessionMixin
import json
import os
import time


class Module(Post, CoapSessionMixin):
    __info__ = {
        "name": "CoAP Observe Dump",
        "description": (
            "Register RFC 7641 Observe on a resource and collect notifications "
            "for a duration (ACK CON notifications, then deregister)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.COAP],
        "tags": ["iot", "coap", "gather", "observe"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["coap_access", "ot_assets"],
                "consumes_capabilities": ["coap_access"],
                "suggested_followups": ["post/coap/gather/config_dump"],
            },
            "requires": {"capabilities_any": ["coap_access"]},
        },
    }

    session_id = OptString("", "CoAP session ID (optional if rhost set)", False)
    rhost = OptString("", "CoAP host when not using a session", False)
    rport = OptPort(COAP_PORT, "CoAP UDP port", False)
    dtls = OptBool(False, "Use DTLS/CoAPS", False)
    path = OptString("sensor", "Resource path to observe", True)
    duration = OptInteger(10, "Seconds to collect notifications", False)
    max_notifications = OptInteger(50, "Maximum notifications to keep", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip():
            return True
        print_error("CoAP session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False
        path = str(self.path or "").strip().lstrip("/")
        if not path:
            print_error("path is required")
            return False
        try:
            client = self.open_coap()
        except Exception as exc:
            print_error(str(exc))
            return False

        duration = max(1, int(self.duration or 10))
        limit = max(1, int(self.max_notifications or 50))
        print_status(
            f"Observing coap{'s' if client.dtls else ''}://{client.host}:{client.port}/{path} "
            f"for {duration}s (max {limit})"
        )
        notes = client.observe_stream(path, duration=float(duration), max_notifications=limit)
        if not notes:
            print_warning("No notifications received (resource may not support Observe)")
        else:
            print_success(f"Collected {len(notes)} notification(s)")
            for i, resp in enumerate(notes[:20], 1):
                preview = resp.text().replace("\n", " ")[:80]
                obs = f" obs={resp.observe}" if resp.observe is not None else ""
                print_info(
                    f"  [{i}] {resp.code_class}.{resp.code_detail:02d}{obs} "
                    f"{len(resp.payload)}B {preview}"
                )

        result = {
            "host": client.host,
            "port": client.port,
            "dtls": bool(client.dtls),
            "path": path,
            "duration": duration,
            "count": len(notes),
            "notifications": [n.to_dict() for n in notes],
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            out = os.path.join("output", f"coap_observe_{stamp}.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
            print_success(f"Saved ./{out}")
        return True
