#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wing_ftp import WingFtp

_AFFECTED_VERSION = "8.1.2"


class Module(Scanner, Http_client, WingFtp):

    __info__ = {
        "name": "Wing FTP Server CVE-2026-44403 (session poisoning RCE) detection",
        "description": (
            "Detects Wing FTP Server <= 8.1.2 admin panels vulnerable to authenticated "
            "session serialization abuse (CVE-2026-44403). Fingerprints the web admin UI "
            "on the default port 5466 and extracts a version hint when available."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-44403",
        "references": [
            "https://www.wftpserver.com/",
            "https://www.cve.org/CVERecord?id=CVE-2026-44403",
        ],
        "modules": [
            "exploits/multi/http/wing_ftp_cve_2026_44403_rce",
            "auxiliary/admin/http/wing_ftp_cve_2026_44403_auth_check",
        ],
        "tags": [
            "web",
            "scanner",
            "wing-ftp",
            "ftp",
            "rce",
            "authenticated",
            "cve-2026-44403",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(WingFtp.DEFAULT_PORT, "Target port (Wing FTP admin default 5466)", required=True)
    ssl = OptBool(False, "Use HTTPS for the admin panel", required=True)
    base_path = OptString("/", "URL path prefix if the admin UI is not at site root", required=False)
    username = OptString("", "Optional full admin username to confirm login", required=False)
    password = OptString("", "Optional full admin password", required=False)

    def run(self):
        timeout = max(int(self.timeout or 10), 10)
        base_path = self.base_path

        try:
            probe = self.wing_ftp_probe_panel(base_path=base_path, timeout=timeout)
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False

        status = probe.get("status")
        version = str(probe.get("version") or "")
        reason = str(probe.get("reason") or "")

        if status == "error":
            print_error(reason)
            return False

        if status != "panel":
            print_status(reason)
            return False

        print_success(f"Wing FTP admin panel detected ({probe.get('path')})")
        if version:
            print_info(f"Version hint: {version}")

        login_ok = False
        username = str(self.username or "").strip()
        password = str(self.password or "")
        if username and password:
            login = self.wing_ftp_login(username, password, base_path=base_path, timeout=timeout)
            if login.get("ok"):
                login_ok = True
                print_success(f"Admin login confirmed for {username}")
                auth_version = self.wing_ftp_fetch_version_after_login(
                    base_path=base_path,
                    timeout=timeout,
                )
                if auth_version:
                    version = auth_version
                    print_info(f"Authenticated version hint: {version}")
            elif login.get("two_factor"):
                print_warning("Admin credentials supplied but 2FA is enabled")
            else:
                print_warning(login.get("reason") or "Supplied admin credentials did not authenticate")

        if version and self.wing_ftp_version_lte(version, _AFFECTED_VERSION):
            self.set_info(
                severity="critical",
                cve="CVE-2026-44403",
                reason=(
                    f"Wing FTP Server {version} <= {_AFFECTED_VERSION}; "
                    "authenticated session poisoning RCE is likely"
                ),
                confidence="high" if login_ok else "medium",
                version=version,
                panel_path=probe.get("path"),
            )
            print_warning(
                f"Version {version} is at or below {_AFFECTED_VERSION} (fixed in 8.1.3)"
            )
            return True

        if login_ok:
            self.set_info(
                severity="high",
                cve="CVE-2026-44403",
                reason=(
                    "Wing FTP admin login succeeded; version unknown but panel matches "
                    "affected product family"
                ),
                confidence="medium",
                panel_path=probe.get("path"),
            )
            print_warning("Authenticated admin access confirmed; verify version manually")
            return True

        self.set_info(
            severity="medium",
            cve="CVE-2026-44403",
            reason=(
                f"{reason}; version not confirmed — Wing FTP <= {_AFFECTED_VERSION} "
                "may be affected if admin credentials are available"
            ),
            confidence="low",
            version=version,
            panel_path=probe.get("path"),
        )
        print_info("Panel detected; supply USERNAME/PASSWORD for stronger confirmation")
        return True
