#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Write CoAP resources via PUT/POST/DELETE (lab / authorized testing)."""

from kittysploit import *
from lib.protocols.coap.client import COAP_PORT
from lib.protocols.coap.session import CoapSessionMixin
import json
import os
import time


class Module(Post, CoapSessionMixin):
    __info__ = {
        "name": "CoAP Resource Write",
        "description": (
            "Send PUT, POST, or DELETE to a CoAP resource. Intrusive — use only "
            "on authorized lab targets."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.COAP],
        "tags": ["iot", "coap", "manage"],
        "agent": {
            "risk": "intrusive",
            "effects": ["configuration_change"],
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["coap_access"],
                "produces_capabilities": ["coap_access"],
            },
            "requires": {"capabilities_any": ["coap_access"]},
        },
    }

    session_id = OptString("", "CoAP session ID (optional if rhost set)", False)
    rhost = OptString("", "CoAP host when not using a session", False)
    rport = OptPort(COAP_PORT, "CoAP UDP port", False)
    dtls = OptBool(False, "Use DTLS/CoAPS", False)
    path = OptString("", "Resource path", True)
    method = OptChoice("PUT", "CoAP method", False, choices=["PUT", "POST", "DELETE"])
    payload = OptString("", "Request payload (PUT/POST)", False)
    save_local = OptBool(True, "Save JSON result under ./output", False)

    def check(self):
        if not str(self.path or "").strip():
            print_error("path is required")
            return False
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip():
            return True
        print_error("CoAP session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False
        try:
            client = self.open_coap()
        except Exception as exc:
            print_error(str(exc))
            return False

        path = str(self.path).strip().lstrip("/")
        method = str(self.method or "PUT").strip().upper()
        body = str(self.payload or "")
        print_status(
            f"{method} {client.scheme}://{client.host}:{client.port}/{path} "
            f"({len(body)} byte payload)"
        )

        if method == "PUT":
            resp = client.put(path, body)
        elif method == "POST":
            resp = client.post(path, body)
        elif method == "DELETE":
            resp = client.delete(path)
        else:
            print_error(f"Unsupported method: {method}")
            return False

        if not resp:
            print_error(client.last_error or "No response / timeout")
            return False

        print_success(
            f"Response {resp.code_class}.{resp.code_detail:02d} ({len(resp.payload)} bytes)"
        )
        if resp.payload:
            print_info(resp.text()[:400])

        result = {
            "host": client.host,
            "port": client.port,
            "dtls": bool(client.dtls),
            "method": method,
            "path": path,
            "request_payload": body,
            "response": resp.to_dict(),
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            out = os.path.join("output", f"coap_write_{stamp}.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
            print_success(f"Saved ./{out}")
        return True
