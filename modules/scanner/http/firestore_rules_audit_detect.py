#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep Firestore rules audit with collection enumeration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.firestore_probe import audit_firestore_rules, discover_firestore_project
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firestore Rules Audit",
        "description": (
            "Discovers Firestore projectId from Firebase config and probes common collections "
            "(users, admin, orders…) for unauthenticated REST read access."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["web", "scanner", "firebase", "firestore", "rules", "misconfig", "cloud"],
        "modules": [
            "scanner/http/firestore_public_access_detect",
            "scanner/http/firebase_api_key_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 18,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.3,
        },
    }

    project_id = OptString("", "Firestore project ID (auto-discovered if empty)", False)
    api_key = OptString("", "Optional browser API key (?key=)", False)

    def run(self):
        project = str(self.project_id or "").strip()
        api_key = str(self.api_key or "").strip()

        if not project or not api_key:
            bodies = collect_vibe_http_bodies(self.http_request)
            for _path, text in bodies:
                scraped_project, scraped_key = discover_firestore_project(text)
                if not project and scraped_project:
                    project = scraped_project
                if not api_key and scraped_key:
                    api_key = scraped_key
                if project and api_key:
                    break

        if not project:
            host = str(self.target or "").strip().lower().split(":")[0]
            import re

            match = re.match(r"^([a-z0-9\-]+)\.(?:web\.app|firebaseapp\.com)$", host, re.I)
            if match:
                project = match.group(1)

        if not project:
            return False

        self._configure_session()
        findings = audit_firestore_rules(
            self.session,
            project,
            api_key,
            verify_ssl=self._to_bool(self.verify_ssl),
        )
        if not findings:
            return False

        critical = [f for f in findings if f.get("severity") == "critical"]
        collections = [f.get("collection") for f in findings if f.get("collection")]

        self.set_info(
            severity="critical" if critical else "high",
            reason=f"Firestore rules audit: {len(findings)} readable collection(s) in {project}",
            project_id=project,
            collections=collections[:15],
            findings=findings[:20],
        )
        return True
