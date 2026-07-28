#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprint React SPA stacks and distinguish them from Next.js."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.react_probe import probe_react_stack, stack_label
from lib.scanner.http.detectors import evidence_nextjs, evidence_react


class Module(Scanner, Http_client):
    __info__ = {
        "name": "React SPA Stack Detection",
        "description": (
            "Identifies standalone React SPAs (CRA / Vite / classic) and explicitly "
            "differentiates them from Next.js so the correct scanner pack can run."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "technology", "react", "spa", "vite", "cra", "tech"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "tech_fingerprint", "from_detail": "react"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/react_sourcemap_detect",
                    "scanner/http/react_env_bundle_detect",
                    "scanner/http/react_dotenv_exposure_detect",
                ],
            },
        },
        "references": [
            "https://create-react-app.dev/",
            "https://vitejs.dev/guide/",
            "https://nextjs.org/docs",
        ],
    }

    def run(self):
        ok, reason, stack = probe_react_stack(self)
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if stack == "nextjs":
            label = evidence_nextjs(r) or "Next.js"
            self.set_info(
                severity="info",
                reason=f"{label} detected — use plugin nextjs (not standalone React pack)",
                stack=stack,
                framework=label,
                path="/",
            )
            # Still a positive stack ID so operators see the distinction.
            return True

        if not ok:
            return False

        label = evidence_react(r) or stack_label(stack)
        self.set_info(
            severity="info",
            reason=f"{label} SPA fingerprint matched",
            stack=stack,
            framework=label,
            path="/",
            evidence=reason or label,
        )
        return True
