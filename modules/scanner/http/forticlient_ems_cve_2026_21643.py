#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection non intrusive d'exposition potentielle à CVE-2026-21643 (FortiClient EMS)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


HOME_PATHS = ["/", "/login", "/signin"]
API_PATH = "/api/v1/init_consts"


class Module(Scanner, Http_client):

    __info__ = {
        "name": "FortiClient EMS CVE-2026-21643 exposure detection",
        "description": (
            "Conservatively detects likely exposure to CVE-2026-21643 by checking that "
            "FortiClient EMS is exposed, that /api/v1/init_consts is reachable without "
            "authentication, that SITES_ENABLED appears true, and that the visible version "
            "is exactly 7.4.4. No SQL injection payloads are sent."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "references": [
            "https://www.fortiguard.com/psirt/FG-IR-25-1142",
            "https://bishopfox.com/blog/cve-2026-21643-pre-authentication-sql-injection-in-forticlient-ems-7-4-4",
        ],
        "tags": [
            "web",
            "scanner",
            "fortinet",
            "forticlient",
            "ems",
            "exposure",
            "cve-2026-21643",
        ],
    }

    @staticmethod
    def _looks_like_forticlient_ems(response) -> bool:
        if not response:
            return False

        text = (getattr(response, "text", "") or "").lower()
        headers = {k.lower(): v.lower() for k, v in getattr(response, "headers", {}).items()}

        markers = [
            "forticlient ems",
            "forticlient endpoint management server",
            "fortinet",
            "ems",
        ]
        if any(marker in text for marker in markers):
            return True

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        return "fortinet" in server or "fortinet" in powered

    @staticmethod
    def _extract_version_from_text(text: str) -> str:
        if not text:
            return ""

        patterns = [
            r"forticlient(?:\s+endpoint\s+management\s+server|\s+ems)?[^\d]{0,20}(7\.\d+\.\d+)",
            r'"version"\s*:\s*"?(7\.\d+\.\d+)"?',
            r'"ems_version"\s*:\s*"?(7\.\d+\.\d+)"?',
            r'"productversion"\s*:\s*"?(7\.\d+\.\d+)"?',
            r'"appversion"\s*:\s*"?(7\.\d+\.\d+)"?',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _sites_enabled(response):
        if not response:
            return None
        text = response.text or ""
        match = re.search(r'"SITES_ENABLED"\s*:\s*(true|false)', text, re.I)
        if not match:
            match = re.search(r'"sites_enabled"\s*:\s*(true|false)', text, re.I)
        if not match:
            return None
        return match.group(1).lower() == "true"

    @staticmethod
    def _is_affected_version(version: str) -> bool:
        return version == "7.4.4"

    @staticmethod
    def _looks_like_consts_response(response) -> bool:
        if not response or response.status_code != 200:
            return False

        text = (response.text or "").lower()
        content_type = (response.headers.get("Content-Type", "") or "").lower()

        if "application/json" in content_type and any(
            marker in text for marker in ("forticlient", "ems", "tenant", "const", "version")
        ):
            return True

        if text.startswith("{") and any(marker in text for marker in ("tenant", "version", "ems")):
            return True

        return False

    def run(self):
        product_detected = False
        detected_version = ""

        for path in HOME_PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            if self._looks_like_forticlient_ems(r):
                product_detected = True
            if not detected_version:
                detected_version = self._extract_version_from_text(r.text or "")
            if product_detected and detected_version:
                break

        init_consts = self.http_request(method="GET", path=API_PATH, allow_redirects=False)
        if not init_consts:
            return False

        if not self._looks_like_consts_response(init_consts):
            return False

        if not detected_version:
            detected_version = self._extract_version_from_text(init_consts.text or "")

        sites_enabled = self._sites_enabled(init_consts)
        if sites_enabled is not True:
            return False

        if not detected_version:
            # Conservative: if we cannot establish the version, do not report a positive match.
            return False

        if not self._is_affected_version(detected_version):
            return False

        reason = "FortiClient EMS 7.4.4 detected, SITES_ENABLED=true, and /api/v1/init_consts is reachable without authentication"
        if not product_detected:
            reason = "Version 7.4.4 with SITES_ENABLED=true detected via /api/v1/init_consts"

        self.set_info(
            severity="high",
            reason=reason,
            cve="CVE-2026-21643",
            endpoint=API_PATH,
            status_code=str(init_consts.status_code),
            version=detected_version,
            sites_enabled="true",
        )
        return True

        return False
