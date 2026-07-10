#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.openclaw.gateway_client import (
    FIXED_CVE_2026_25253,
    OpenClawGatewayClient,
    version_lt,
)


class Module(Scanner, Http_client):

    __info__ = {
        "name": "OpenClaw AI agent gateway detection",
        "description": (
            "Detects exposed OpenClaw (formerly Clawdbot/Moltbot) AI agent gateways "
            "and flags versions likely affected by CVE-2026-25253 token exfiltration."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "cve": ["CVE-2026-25253"],
        "references": [
            "https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-25253",
            "https://docs.openclaw.ai/gateway/health",
        ],
        "modules": [
            "exploits/multi/http/openclaw_gateway_rce",
            "auxiliary/misc/openclaw_token_exfil",
        ],
        "tags": ["web", "scanner", "openclaw", "ai-agent", "mcp", "gateway", "cve-2026-25253"],
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(18789, "Target port (OpenClaw default)", True)
    ssl = OptBool(False, "Use HTTPS/WSS", True, advanced=True)
    ws_probe = OptBool(
        True,
        "Probe WebSocket connect.challenge (confirms live gateway control plane)",
        required=False,
    )

    def _ws_reachable(self) -> bool:
        client = OpenClawGatewayClient(
            host=self.target,
            port=self.port,
            ssl=self.ssl,
            timeout=max(int(self.timeout or 10), 5),
            verify_ssl=getattr(self, "verify_ssl", False),
        )
        try:
            client.ws_connect()
            if not client.ws:
                return False
            client.ws.settimeout(5)
            for _ in range(5):
                raw = client.ws.recv()
                if not raw:
                    continue
                if b"connect.challenge" in raw or '"connect.challenge"' in raw:
                    return True
            return False
        except Exception:
            return False
        finally:
            client.ws_close()

    def run(self):
        client = OpenClawGatewayClient(
            host=self.target,
            port=self.port,
            ssl=self.ssl,
            timeout=max(int(self.timeout or 10), 5),
            verify_ssl=getattr(self, "verify_ssl", False),
        )

        try:
            info = client.fingerprint()
        except ConnectionError:
            return False

        if not info.get("detected"):
            return False

        version = str(info.get("version") or "")
        cve_vulnerable = bool(version and version_lt(version, FIXED_CVE_2026_25253))
        ws_live = self._ws_reachable() if self.ws_probe else None

        severity = "high" if cve_vulnerable else "medium"
        reason_bits = ["OpenClaw gateway detected"]
        if version:
            reason_bits.append(f"version={version}")
        if cve_vulnerable:
            reason_bits.append("likely vulnerable to CVE-2026-25253 (< 2026.1.29)")
        if ws_live is True:
            reason_bits.append("WebSocket control plane reachable")
        bind = str(info.get("bind") or "")
        if bind and bind not in ("loopback", "127.0.0.1", "localhost"):
            severity = "critical"
            reason_bits.append(f"bind={bind}")

        self.set_info(
            severity=severity,
            cve="CVE-2026-25253" if cve_vulnerable else "",
            service="openclaw",
            version=version,
            bind=bind,
            channels=info.get("channels") or [],
            websocket_live=ws_live,
            reason="; ".join(reason_bits),
        )
        return True
