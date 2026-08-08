#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate gRPC-Web services and methods over HTTP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.grpc_web_probe import scan_grpc_web_surface
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "gRPC-Web Method Enumeration",
        "description": (
            "Probes gRPC-Web and HTTP-transported gRPC paths for reflection, health checks, "
            "and service/method routes embedded in JS bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["grpc", "grpc-web", "api", "enumeration", "auxiliary", "rpc"],
        "modules": ["scanner/http/grpc_reflection_detect", "scanner/http/gloo_unauth_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.1,
        },
    }

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request)
        homepage = next((t for p, t in bodies if p == "/"), "")
        for _path, text in bodies:
            if "grpc" in text.lower() and len(homepage) < len(text):
                homepage = text[:500_000]

        findings = scan_grpc_web_surface(self.http_request, homepage)
        if not findings:
            print_warning("No gRPC-Web endpoints discovered")
            return False

        for hit in findings:
            print_success(f"gRPC-Web {hit.get('kind')} at {hit.get('path')} (HTTP {hit.get('status_code')})")

        self.set_info(
            severity="medium",
            reason=f"gRPC-Web enum: {len(findings)} endpoint(s)",
            findings=findings,
        )
        return True
