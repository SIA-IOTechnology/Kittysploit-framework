#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Moodle and report the version from lib/upgrade.txt."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.moodle import Moodle


class Module(Scanner, Http_client, Moodle):

    __info__ = {
        "name": "Moodle detection",
        "description": (
            "Detects a Moodle installation and reports the version from "
            "lib/upgrade.txt when available."
        ),
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [
            "exploits/multi/http/moodle_cve_2021_21809_spellcheck_rce",
        ],
        "tags": ["web", "scanner", "moodle", "cms", "version"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.2,
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
                "produces_capabilities": [],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/moodle_cve_2021_21809_spellcheck_rce",
                ],
            },
        },
    }

    path = OptString("/", "Moodle base path to test", required=False)

    def _candidate_paths(self):
        configured = self.moodle_normalize_base_path(str(self.path or "/"))
        candidates = [configured]
        for candidate in ("/moodle", "/lms", "/elearning"):
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def run(self):
        best = {"score": 0, "base_path": "/", "version": None, "evidence": []}

        for base_path in self._candidate_paths():
            info = self.moodle_detect(base_path=base_path)
            score = len(info.get("evidence") or [])
            if info.get("version"):
                score += 2
            if score > best["score"]:
                best = {
                    "score": score,
                    "base_path": info.get("base_path") or base_path,
                    "version": info.get("version"),
                    "evidence": info.get("evidence") or [],
                }

        if best["score"] >= 1 and best["evidence"]:
            version = best["version"] or "unknown"
            self.set_info(
                severity="info",
                reason=f"Moodle detected at {best['base_path']} (version={version})",
                base_path=best["base_path"],
                path=best["base_path"],
                version=version,
                evidence=", ".join(best["evidence"]),
            )
            print_success(f"Moodle detected at {best['base_path']}")
            if best["version"]:
                print_status(f"Version: {best['version']}")
            else:
                print_warning("Version could not be determined from lib/upgrade.txt")
            return True

        self.set_info(reason="Moodle not detected")
        return False
