#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Probe ONVIF Events service (GetEventProperties / topic list)."""

from kittysploit import *
from lib.protocols.onvif.session import OnvifSessionMixin
import json
import os
import time


class Module(Post, OnvifSessionMixin):
    __info__ = {
        "name": "ONVIF Events Probe",
        "description": (
            "Query ONVIF Events GetEventProperties and extract topic hints. "
            "Uses an ONVIF session or rhost."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.ONVIF],
        "tags": ["iot", "camera", "onvif", "events", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["onvif_access"],
                "consumes_capabilities": ["onvif_access"],
            },
            "requires": {"capabilities_any": ["onvif_access"]},
        },
    }

    session_id = OptString("", "ONVIF session ID (optional if rhost set)", False)
    rhost = OptString("", "Camera host when not using a session", False)
    rport = OptPort(80, "HTTP port", False)
    ssl = OptBool(False, "Use HTTPS", False)
    username = OptString("", "ONVIF username", False)
    password = OptString("", "ONVIF password", False)
    save_local = OptBool(True, "Save JSON under ./output", False)

    def check(self):
        if self._resolve_session():
            return True
        if str(self.rhost or "").strip():
            return True
        print_error("ONVIF session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False
        try:
            client = self.open_onvif(discover=True)
        except Exception as exc:
            print_error(str(exc))
            return False

        if client.events_xaddr:
            print_success(f"Events XAddr: {client.events_xaddr}")
        else:
            print_warning("No Events XAddr — trying default events_service path")

        props = client.get_event_properties()
        if not props.get("ok"):
            print_error(client.last_error or "GetEventProperties failed")
            return False

        topics = props.get("topics") or []
        print_success(f"Event properties OK ({props.get('bytes', 0)} bytes, {len(topics)} topic hint(s))")
        for topic in topics[:20]:
            print_info(f"  {topic}")

        result = {
            "host": client.host,
            "port": client.port,
            "events_xaddr": client.events_xaddr,
            "topics": topics,
            "raw_preview": props.get("raw_preview") or "",
        }
        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"onvif_events_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print_success(f"Saved ./{path}")
        return True
