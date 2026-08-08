#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep Firebase RTDB rules audit with path enumeration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.firebase_rtdb_probe import audit_rtdb_surface_session, discover_rtdb_url
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firebase RTDB Rules Audit",
        "description": (
            "Discovers databaseURL from Firebase web config, probes exposed rules JSON, "
            "and enumerates common RTDB paths (users, admin, messages…) for anonymous read access."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["web", "scanner", "firebase", "rtdb", "rules", "misconfig"],
        "modules": [
            "scanner/http/firebase_api_key_detect",
            "scanner/http/firebase_rtdb_public_access_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 22,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.3,
            "chain": {
                "suggested_followups": ["scanner/http/firebase_rtdb_public_access_detect"],
            },
        },
    }

    database_url = OptString("", "RTDB root URL (auto-discovered from Firebase config if empty)", False)

    def run(self):
        base = str(self.database_url or "").strip()
        if not base:
            bodies = collect_vibe_http_bodies(self.http_request)
            for _path, text in bodies:
                base = discover_rtdb_url(text)
                if base:
                    break

        if not base:
            return False

        self._configure_session()
        findings, root = audit_rtdb_surface_session(
            self.session,
            base,
            verify_ssl=self._to_bool(self.verify_ssl),
        )
        if not findings:
            return False

        critical = [f for f in findings if f.get("severity") == "critical"]
        paths = [f.get("path") for f in findings if f.get("path")]

        self.set_info(
            severity="critical" if critical else "high",
            reason=f"RTDB rules audit: {len(findings)} exposed path/rule(s) at {root}",
            path=paths[0] if paths else root,
            database_url=root,
            findings=findings[:20],
        )
        return True
