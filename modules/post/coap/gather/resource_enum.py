#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enumerate CoAP resources via .well-known/core and optional path probes."""

from kittysploit import *
from lib.protocols.coap.client import COAP_PORT
from lib.protocols.coap.session import CoapSessionMixin
import json
import os
import re
import time


class Module(Post, CoapSessionMixin):
    __info__ = {
        "name": "CoAP Resource Enum",
        "description": (
            "Enumerate CoAP resources from .well-known/core and optionally GET "
            "discovered paths. Uses a CoAP session or rhost."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.COAP],
        "tags": ["iot", "coap", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["coap_access", "ot_assets"],
                "consumes_capabilities": ["coap_access"],
                "suggested_followups": [
                    "post/coap/gather/config_dump",
                    "post/coap/gather/observe_dump",
                ],
            },
            "requires": {"capabilities_any": ["coap_access"]},
        },
    }

    session_id = OptString("", "CoAP session ID (optional if rhost set)", False)
    rhost = OptString("", "CoAP host when not using a session", False)
    rport = OptPort(COAP_PORT, "CoAP UDP port", False)
    dtls = OptBool(False, "Use DTLS/CoAPS", False)
    fetch_resources = OptBool(True, "GET each discovered resource path", False)
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
        try:
            client = self.open_coap()
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"Enumerating CoAP on {client.host}:{client.port}...")
        wk = client.well_known() or ""
        paths = sorted(set(re.findall(r"</([^>;]+)", wk)))
        if wk:
            print_success(f".well-known/core ({len(wk)} bytes, {len(paths)} path hint(s))")
            print_info(wk[:400] + ("..." if len(wk) > 400 else ""))
        else:
            print_warning("Empty .well-known/core")

        resources = []
        if bool(self.fetch_resources) and paths:
            for path in paths[:40]:
                resp = client.get(path)
                entry = {
                    "path": path,
                    "code": f"{resp.code_class}.{resp.code_detail:02d}" if resp else None,
                    "payload": resp.text() if resp else "",
                    "bytes": len(resp.payload) if resp else 0,
                }
                resources.append(entry)
                status = entry["code"] or "timeout"
                print_info(f"  /{path} -> {status} ({entry['bytes']} B)")

        result = {
            "host": client.host,
            "port": client.port,
            "well_known": wk,
            "paths": paths,
            "resources": resources,
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"coap_resources_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
            print_success(f"Saved ./{path}")
        return True
