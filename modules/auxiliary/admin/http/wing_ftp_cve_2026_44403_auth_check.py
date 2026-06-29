#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wing_ftp import WingFtp

_AFFECTED_VERSION = "8.1.2"


class Module(Auxiliary, Http_client, WingFtp):

    __info__ = {
        "name": "Wing FTP Server CVE-2026-44403 - authenticated admin check",
        "description": (
            "CVE-2026-44403: Wing FTP Server <= 8.1.2 allows a full administrator to poison "
            "domain-admin session serialization via the mydirectory field, leading to Lua RCE. "
            "This auxiliary verifies admin panel presence, authenticates with supplied "
            "credentials, and reports whether the version hint is in the affected range."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-44403"],
        "references": [
            "https://www.wftpserver.com/",
            "https://www.cve.org/CVERecord?id=CVE-2026-44403",
        ],
        "tags": [
            "wing-ftp",
            "ftp",
            "authenticated",
            "rce",
            "cve-2026-44403",
            "auxiliary",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(WingFtp.DEFAULT_PORT, "Target port (Wing FTP admin default 5466)", required=True)
    ssl = OptBool(False, "Use HTTPS for the admin panel", required=True)
    base_path = OptString("/", "URL path prefix if the admin UI is not at site root", required=False)
    username = OptString("", "Full admin username (not readonly, not domain admin)", required=True)
    password = OptString("", "Full admin password", required=True)

    def check(self):
        timeout = max(int(self.timeout or 10), 10)
        base_path = self.base_path

        try:
            probe = self.wing_ftp_probe_panel(base_path=base_path, timeout=timeout)
        except Exception as exc:
            return {"vulnerable": False, "reason": f"Probe failed: {exc}", "confidence": "low"}

        if probe.get("status") != "panel":
            return {
                "vulnerable": False,
                "reason": probe.get("reason") or "Wing FTP admin panel not detected",
                "confidence": "low",
            }

        login = self.wing_ftp_login(
            self.username,
            self.password,
            base_path=base_path,
            timeout=timeout,
        )
        if login.get("two_factor"):
            return {
                "vulnerable": False,
                "reason": "Two-factor authentication is enabled; this workflow does not handle TOTP",
                "confidence": "medium",
            }
        if not login.get("ok"):
            return {
                "vulnerable": False,
                "reason": login.get("reason") or "Authentication failed",
                "confidence": "medium",
            }

        version = str(probe.get("version") or "")
        auth_version = self.wing_ftp_fetch_version_after_login(base_path=base_path, timeout=timeout)
        if auth_version:
            version = auth_version

        if version and self.wing_ftp_version_lte(version, _AFFECTED_VERSION):
            return {
                "vulnerable": True,
                "reason": (
                    f"Authenticated to Wing FTP {version} (<= {_AFFECTED_VERSION}); "
                    "session poisoning RCE prerequisites met"
                ),
                "confidence": "high",
                "details": f"panel={probe.get('path')}; version={version}",
            }

        return {
            "vulnerable": True,
            "reason": (
                "Authenticated full admin access confirmed; version not parsed but product "
                f"family matches CVE-2026-44403 (<= {_AFFECTED_VERSION})"
            ),
            "confidence": "medium",
            "details": f"panel={probe.get('path')}; version={version or 'unknown'}",
        }

    def run(self):
        timeout = max(int(self.timeout or 10), 10)
        base_path = self.base_path

        probe = self.wing_ftp_probe_panel(base_path=base_path, timeout=timeout)
        if probe.get("status") != "panel":
            print_error(probe.get("reason") or "Wing FTP admin panel not detected")
            return False

        print_success(f"Wing FTP admin panel detected ({probe.get('path')})")

        login = self.wing_ftp_login(
            self.username,
            self.password,
            base_path=base_path,
            timeout=timeout,
        )
        if login.get("two_factor"):
            print_error("Two-factor authentication is enabled; this module does not handle TOTP")
            return False
        if not login.get("ok"):
            print_error(login.get("reason") or "Authentication failed")
            return False

        print_success(f"Authenticated as {self.username}")

        version = str(probe.get("version") or "")
        auth_version = self.wing_ftp_fetch_version_after_login(base_path=base_path, timeout=timeout)
        if auth_version:
            version = auth_version

        if version:
            print_info(f"Version hint: {version}")
            if self.wing_ftp_version_lte(version, _AFFECTED_VERSION):
                print_warning(
                    f"Version {version} is at or below {_AFFECTED_VERSION} (patched in 8.1.3)"
                )
            else:
                print_info(f"Version {version} appears newer than the affected range")
        else:
            print_warning("Could not extract a version string from the admin UI")

        print_info(
            "CVE-2026-44403: a full admin can create or modify a domain admin with a poisoned "
            "mydirectory value; logging in as that account serializes Lua that executes on the "
            "next session load via loadfile()."
        )
        print_info(
            "Use exploits/multi/http/wing_ftp_cve_2026_44403_rce for controlled exploitation."
        )
        return True
