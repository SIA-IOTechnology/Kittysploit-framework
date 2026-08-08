#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect tRPC batch endpoints vulnerable to request amplification."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.trpc_probe import probe_trpc_batch_amplification


class Module(Scanner, Http_client):
    __info__ = {
        "name": "tRPC Batch Amplification Detection",
        "description": (
            "Sends batched tRPC requests with many duplicated procedures to detect "
            "amplification ratios indicative of DoS / resource exhaustion risk."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "trpc", "nextjs", "dos", "amplification", "misconfig"],
        "modules": ["auxiliary/scanner/http/trpc_openapi_procedure_enum"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.1,
            "chain": {
                "produces_capabilities": [{"capability": "api_abuse_surface", "from_detail": "trpc_batch"}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    trpc_base = OptString("/api/trpc", "Primary tRPC base path", False)
    batch_size = OptInteger(25, "Number of batched procedures to probe", False, advanced=True)

    def run(self):
        bases = [str(self.trpc_base or "/api/trpc").strip() or "/api/trpc", "/trpc", "/api/trpc/health"]
        findings = []
        seen = set()
        for base in bases:
            if base in seen:
                continue
            seen.add(base)
            hit = probe_trpc_batch_amplification(
                self.http_request,
                base,
                batch_size=int(self.batch_size or 25),
            )
            if hit:
                findings.append(hit)

        if not findings:
            return False

        worst = max(findings, key=lambda f: float(f.get("amplification_ratio") or 0))
        high = [f for f in findings if f.get("severity") == "high"]

        self.set_info(
            severity="high" if high else "medium",
            reason=(
                f"tRPC batch amplification: {worst.get('amplification_ratio')}x "
                f"({worst.get('procedure_count')} procedures, {worst.get('batch_response_bytes')} bytes)"
            ),
            path=worst.get("path") or "/api/trpc",
            findings=findings,
        )
        return True
