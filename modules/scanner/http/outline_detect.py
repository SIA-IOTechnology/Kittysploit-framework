#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Outline (getoutline.com) team wiki panel detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Outline Panel - Detect",
        "description": (
            "Detects self-hosted Outline wiki instances (getoutline.com). Uses "
            "product-specific markers; ignores generic SPA pages containing the "
            "word outline in CSS/JS bundles."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "panel", "outline", "wiki", "knowledge-base"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
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
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["auxiliary/scanner/http/login_page_detector"],
            },
        },
        "references": ["https://github.com/outline/outline", "https://www.getoutline.com/"],
    }

    _STRONG_MARKERS = (
        "data-outline-team",
        "getoutline.com",
        "github.com/outline/outline",
        "/api/auth.config",
        "outline-icons",
        "outline-wiki",
    )
    _TITLE_MARKERS = ("outline",)

    def _score_outline(self, body: str) -> int:
        text = body or ""
        lower = text.lower()
        score = sum(1 for marker in self._STRONG_MARKERS if marker.lower() in lower)
        if "<title>outline</title>" in lower:
            score += 2
        if 'content="outline"' in lower and "generator" in lower:
            score += 2
        if "shared documents" in lower and "sign in" in lower and score >= 1:
            score += 1
        return score

    def _probe_auth_config(self) -> bool:
        response = self.http_request(
            method="GET",
            path="/api/auth.config",
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return False
        body = (response.text or "").lower()
        return "providers" in body or "slack" in body or "google" in body

    def run(self):
        response = self.http_request(method="GET", path="/", allow_redirects=True)
        if not response or int(response.status_code or 0) != 200:
            return False

        body = response.text or ""
        score = self._score_outline(body)
        if score >= 2:
            self.set_info(
                severity="info",
                reason="Outline wiki panel detected",
                path="/",
            )
            return True

        if self._probe_auth_config():
            self.set_info(
                severity="info",
                reason="Outline wiki detected via /api/auth.config",
                path="/api/auth.config",
            )
            return True

        return False
