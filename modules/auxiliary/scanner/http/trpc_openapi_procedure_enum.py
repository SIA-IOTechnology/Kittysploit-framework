#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate tRPC procedures and related OpenAPI routes on Next.js apps."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.trpc_probe import (
    extract_trpc_procedures_from_js,
    probe_trpc_procedure,
    scan_trpc_surface,
)
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "tRPC / OpenAPI Procedure Enumeration",
        "description": (
            "Probes /api/trpc for common procedures, batch amplification, and exposed "
            "openapi.json routes. Extracts dotted procedure names from JS bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["trpc", "nextjs", "api", "openapi", "enumeration", "auxiliary"],
        "modules": ["scanner/http/nextjs_detect", "auxiliary/scanner/http/graphql_abuse"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 18,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "risk_signals", "tech_hints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.1,
        },
    }

    trpc_base = OptString("/api/trpc", "Primary tRPC base path", False)

    def run(self):
        findings = scan_trpc_surface(self.http_request)
        base = str(self.trpc_base or "/api/trpc").strip() or "/api/trpc"

        bodies = collect_vibe_http_bodies(self.http_request)
        for _path, text in bodies:
            for proc in extract_trpc_procedures_from_js(text[:500_000]):
                hit = probe_trpc_procedure(self.http_request, base, proc)
                if hit:
                    findings.append(hit)

        if not findings:
            print_warning("No tRPC/OpenAPI procedures discovered")
            return False

        procs = [f.get("procedure") or f.get("kind") for f in findings if f.get("procedure") or f.get("kind")]
        print_success(f"tRPC/OpenAPI: {len(findings)} hit(s)")
        for name in procs[:8]:
            print_info(f"  → {name}")

        self.set_info(
            severity="high" if any(f.get("severity") == "high" for f in findings) else "medium",
            reason=f"tRPC/OpenAPI enum: {len(findings)} accessible route(s)/procedure(s)",
            findings=findings[:20],
            procedures=procs[:20],
        )
        return True
