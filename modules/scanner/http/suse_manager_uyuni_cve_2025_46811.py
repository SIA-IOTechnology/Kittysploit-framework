#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import websocket

from kittysploit import *
from lib.protocols.websocket.websocket_client import WebsocketTimeoutException, Websocket_client


class Module(Scanner, Websocket_client):

    __info__ = {
        "name": "SUSE Manager / Uyuni CVE-2025-46811 WebSocket detection",
        "description": (
            "Detects unauthenticated exposure of /rhn/websocket/minion/remote-commands by "
            "requesting a preview of Salt minions (CVE-2025-46811). Affected stacks include "
            "Uyuni 2025.05, SUSE Manager 5.0.4, SUSE Manager 4.3.15 per public advisories."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-46811",
        "references": [
            "https://www.uyuni-project.org/",
            "https://github.com/uyuni-project/uyuni",
            "https://www.suse.com/",
        ],
        "modules": [
            "exploits/multi/http/suse_manager_uyuni_cve_2025_46811_ws_rce",
        ],
        "tags": ["web", "scanner", "suse", "uyuni", "websocket", "cve-2025-46811"],
    }

    path = OptString(
        "/rhn/websocket/minion/remote-commands",
        "WebSocket path for minion remote commands",
        True,
    )

    def _preview_minions(self):
        self.ws_connect()
        if self.ws:
            self.ws.settimeout(float(self.timeout))
        self.ws_send(json.dumps({"preview": True, "target": "*"}))
        raw = self.ws_recv()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        doc = json.loads(raw)
        if (
            isinstance(doc, dict)
            and isinstance(doc.get("minions"), list)
            and doc["minions"]
            and all(isinstance(x, str) for x in doc["minions"])
        ):
            return doc["minions"]
        return []

    def run(self):
        try:
            minions = self._preview_minions()
            if not minions:
                return False
            sample = ", ".join(minions[:5])
            extra = f" (+{len(minions) - 5} more)" if len(minions) > 5 else ""
            self.set_info(
                severity="critical",
                cve="CVE-2025-46811",
                reason=(
                    f"Unauthenticated WebSocket preview returned {len(minions)} minion(s): "
                    f"{sample}{extra}"
                ),
                minions_count=len(minions),
            )
            print_info(f"CVE-2025-46811: {len(minions)} minion(s) leaked via preview")
            return True
        except websocket.WebSocketBadStatusException as e:
            if getattr(e, "status_code", None) == 400:
                print_warning(f"WebSocket handshake failed (HTTP 400): try toggling ssl option ({e})")
            return False
        except (WebsocketTimeoutException, json.JSONDecodeError, ValueError, KeyError):
            return False
        except Exception as e:
            print_error(f"Scanner error: {e}")
            return False
        finally:
            self.ws_close()
