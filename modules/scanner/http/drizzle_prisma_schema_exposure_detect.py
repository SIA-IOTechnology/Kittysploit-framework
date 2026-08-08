#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Drizzle ORM and Prisma schema/migration artifacts."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.drizzle_prisma_probe import scan_drizzle_prisma_exposure


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Drizzle / Prisma Schema Exposure Detection",
        "description": (
            "Probes for exposed prisma/schema.prisma, migration SQL, drizzle.config.ts, "
            "drizzle/meta/_journal.json, and db/schema.ts files leaking full DB schemas."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "prisma", "drizzle", "orm", "database", "exposure", "misconfig"],
        "modules": ["scanner/http/prisma_schema_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 14,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 0.9,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    def run(self):
        findings = scan_drizzle_prisma_exposure(self.http_request)
        if not findings:
            return False
        high = [f for f in findings if f.get("severity") in ("critical", "high")]
        models = []
        for f in findings:
            models.extend(f.get("models") or f.get("tables") or [])
        self.set_info(
            severity="high" if high else "medium",
            reason=f"ORM schema/migration exposed ({len(findings)} artifact(s), {len(models)} model(s)/table(s))",
            path=findings[0].get("path") or "/prisma/schema.prisma",
            findings=findings[:15],
            models=models[:30],
        )
        return True
