#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.phpsysinfo import Phpsysinfo

_AFFECTED_VERSION = "3.4.5"


class Module(Scanner, Http_client, Phpsysinfo):

    __info__ = {
        "name": "phpSysInfo CVE-2026-55584 (PSI_ALLOWED IP allowlist bypass) detection",
        "description": (
            "Detects phpSysInfo <= 3.4.5 instances where PSI_ALLOWED can be bypassed by "
            "spoofing X-Forwarded-For or Client-IP before REMOTE_ADDR is checked. "
            "Probes xml.php with a baseline request, then common allowlisted IP candidates."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-55584",
        "references": [
            "https://github.com/phpsysinfo/phpsysinfo/security/advisories/GHSA-786w-p5pm-cvgh",
            "https://www.cve.org/CVERecord?id=CVE-2026-55584",
        ],
        "modules": [
            "auxiliary/admin/http/phpsysinfo_cve_2026_55584_info_disclosure",
        ],
        "tags": [
            "web",
            "scanner",
            "phpsysinfo",
            "disclosure",
            "allowlist",
            "bypass",
            "cve-2026-55584",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    base_path = OptString("/", "phpSysInfo base URL path (e.g. /phpsysinfo)", required=False)
    spoof_ip = OptString(
        "",
        "Known allowlisted IP to try first (optional; common private/resolver IPs are also tested)",
        required=False,
    )
    header_mode = OptString(
        "all",
        "Bypass header to use: all, x-forwarded-for, client-ip",
        required=False,
        advanced=True,
    )

    def run(self):
        try:
            result = self.phpsysinfo_probe_allowlist_bypass(
                base_path=self.base_path,
                spoof_ip=self.spoof_ip,
                header_mode=self.header_mode,
                timeout=max(int(self.timeout or 10), 10),
            )
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False

        status = result.get("status")
        version = str(result.get("version") or "")
        reason = str(result.get("reason") or "")

        if status == "bypass":
            detail = reason
            if version:
                detail += f"; version hint {version}"
            self.set_info(
                severity="high",
                cve="CVE-2026-55584",
                reason=detail,
                confidence="high",
                xml_path=result.get("xml_path"),
                spoof_ip=result.get("spoof_ip"),
                header=result.get("header_name"),
            )
            print_success(
                f"Bypass confirmed via {result.get('header_name')}: {result.get('spoof_ip')} "
                f"on {result.get('xml_path')}"
            )
            return True

        if status == "open":
            if version and self.phpsysinfo_version_lte(version, _AFFECTED_VERSION):
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-55584",
                    reason=(
                        f"phpSysInfo {version} exposes xml.php without allowlist denial; "
                        f"version <= {_AFFECTED_VERSION} may be affected if PSI_ALLOWED is enabled"
                    ),
                    confidence="medium",
                    xml_path=result.get("xml_path"),
                )
                print_warning(
                    f"xml.php is reachable (version hint {version}); allowlist bypass not required to read XML"
                )
                return True

            self.set_info(
                severity="info",
                reason=reason,
                xml_path=result.get("xml_path"),
            )
            print_info("xml.php is reachable without allowlist denial")
            return True

        if status == "denied":
            self.set_info(
                severity="info",
                cve="CVE-2026-55584",
                reason=reason,
                confidence="low",
                xml_path=result.get("xml_path"),
            )
            print_warning("Allowlist denial seen; bypass not confirmed with default spoof IPs")
            return False

        if status == "not_found":
            if version and self.phpsysinfo_version_lte(version, _AFFECTED_VERSION):
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-55584",
                    reason=f"{reason}; version hint {version} (<= {_AFFECTED_VERSION})",
                    confidence="low",
                )
                print_warning(reason)
                return True

            print_status(reason)
            return False

        if status == "error":
            print_error(reason)
            return False

        return False
