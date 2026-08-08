#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed LLM chat/completion endpoints (prompt injection surface)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.llm_surface_probe import scan_llm_surfaces


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LLM Prompt Injection Surface Detection",
        "description": (
            "Probes OpenAI-compatible /v1/chat/completions, Ollama, and generic /api/chat "
            "endpoints for unauthenticated inference — prompt injection and tool abuse entry points."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "llm", "ai", "openai", "ollama", "prompt", "inference"],
        "modules": [
            "scanner/http/ollama_detect",
            "scanner/http/openwebui_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 11,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.2,
            "noise": 0.45,
            "value": 1.3,
        },
    }

    def run(self):
        findings = scan_llm_surfaces(self.http_request)
        open_hits = [f for f in findings if f.get("status_code") in (200, 201)]
        if not findings:
            return False
        self.set_info(
            severity="critical" if open_hits else "medium",
            reason=f"LLM completion surface ({len(open_hits)} unauthenticated)" if open_hits else "LLM endpoints reachable (auth required)",
            path=findings[0].get("path") or "/v1/chat/completions",
            findings=findings[:10],
        )
        return True
