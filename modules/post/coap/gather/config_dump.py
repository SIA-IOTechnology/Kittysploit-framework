#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dump CoAP device/config resources (well-known + common IoT paths)."""

from kittysploit import *
from lib.protocols.coap.client import COAP_PORT, DEFAULT_CONFIG_PATHS
from lib.protocols.coap.session import CoapSessionMixin
import json
import os
import time


class Module(Post, CoapSessionMixin):
    __info__ = {
        "name": "CoAP Config Dump",
        "description": (
            "Enumerate .well-known/core and GET common IoT config/status paths "
            "(device, version, firmware, sensor, …) to dump readable state."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.COAP],
        "tags": ["iot", "coap", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["coap_access", "ot_assets"],
                "consumes_capabilities": ["coap_access"],
                "suggested_followups": [
                    "post/coap/gather/observe_dump",
                    "post/coap/manage/resource_write",
                ],
            },
            "requires": {"capabilities_any": ["coap_access"]},
        },
    }

    session_id = OptString("", "CoAP session ID (optional if rhost set)", False)
    rhost = OptString("", "CoAP host when not using a session", False)
    rport = OptPort(COAP_PORT, "CoAP UDP port", False)
    dtls = OptBool(False, "Use DTLS/CoAPS", False)
    extra_paths = OptString(
        "",
        "Comma-separated extra paths to GET (in addition to defaults)",
        False,
    )
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

        print_status(f"Config dump on {client.scheme}://{client.host}:{client.port}")
        links = client.list_resources()
        discovered = [e["path"] for e in links if e.get("path")]
        if links:
            print_success(f".well-known/core → {len(links)} link(s)")
            for entry in links[:30]:
                obs = " [obs]" if entry.get("obs") else ""
                print_info(f"  /{entry['path']}{obs}")

        extra = [
            p.strip().lstrip("/")
            for p in str(self.extra_paths or "").split(",")
            if p.strip()
        ]
        paths = []
        seen = set()
        for path in list(discovered) + list(DEFAULT_CONFIG_PATHS) + extra:
            if path and path not in seen:
                seen.add(path)
                paths.append(path)

        resources = []
        for path in paths[:60]:
            resp = client.get(path)
            entry = {
                "path": path,
                "code": f"{resp.code_class}.{resp.code_detail:02d}" if resp else None,
                "payload": resp.text() if resp else "",
                "bytes": len(resp.payload) if resp else 0,
                "ok": bool(resp and resp.ok),
            }
            resources.append(entry)
            if entry["ok"] and entry["payload"]:
                preview = entry["payload"].replace("\n", " ")[:80]
                print_success(f"  /{path} → {entry['code']} {preview}")
            elif resp:
                print_info(f"  /{path} → {entry['code']}")

        result = {
            "host": client.host,
            "port": client.port,
            "dtls": bool(client.dtls),
            "links": links,
            "resources": resources,
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            out = os.path.join("output", f"coap_config_{stamp}.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
            print_success(f"Saved ./{out}")
        return True
