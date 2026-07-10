#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.meig import Meig

_AFFECTED_FIRMWARE = "MDM9607.LE.1.0-00110-STD.PROD-1"


class Module(Scanner, Http_client, Meig):

    __info__ = {
        "name": "MeiG FORGE_SLT711 CVE-2026-36356 (GoAhead blind OS command injection) detection",
        "description": (
            "Detects unauthenticated blind OS command injection in MeiG Smart FORGE_SLT711 "
            "(Ortel 4G LTE CPE) and related MDM9607 GoAhead firmware. Fingerprints the "
            "web UI, then sends a timed sleep payload to POST /action/SetRemoteAccessCfg."
        ),
        "author": ["Daniil Gordeev", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-36356",
        "references": [
            "http://www.meigsmart.com",
            "https://www.cve.org/CVERecord?id=CVE-2026-36356",
        ],
        "modules": [
            "exploits/linux/http/meig_forge_slt711_cve_2026_36356_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "meig",
            "forge_slt711",
            "goahead",
            "router",
            "cpe",
            "command-injection",
            "blind",
            "rce",
            "unauthenticated",
            "cve-2026-36356",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe', 'active_exploitation'],
        'expected_requests': 3,
        'reversible': False,
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(80, "Target HTTP port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True)
    target_path = OptString(
        Meig.DEFAULT_ENDPOINT,
        "GoAhead action endpoint to probe",
        required=False,
    )
    check_sleep = OptInteger(
        2,
        "Sleep seconds injected during the timing probe",
        required=False,
        advanced=True,
    )
    skip_fingerprint = OptBool(
        False,
        "Skip GET / fingerprint and probe the action endpoint directly",
        required=False,
        advanced=True,
    )

    def run(self):
        timeout = max(int(self.timeout or 10), 10)
        endpoint = self.meig_normalize_path(self.target_path)
        fingerprint = None

        if not self.skip_fingerprint:
            try:
                fingerprint = self.meig_fingerprint(timeout=timeout)
            except Exception as exc:
                print_warning(f"Fingerprint step failed: {exc}")

            status = (fingerprint or {}).get("status")
            if status == "match":
                print_success(str(fingerprint.get("reason") or "MeiG/GoAhead device detected"))
                server = str(fingerprint.get("server") or "").strip()
                if server:
                    print_info(f"Server: {server}")
            elif status == "maybe":
                print_warning(str(fingerprint.get("reason") or "Possible GoAhead device"))
            elif status == "unknown":
                print_status(str(fingerprint.get("reason") or "Fingerprint inconclusive"))

        print_info(f"Probing {endpoint} with timed command injection ...")
        try:
            result = self.meig_probe_rce(
                sleep_seconds=int(self.check_sleep or 2),
                path=endpoint,
                timeout=timeout,
            )
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False

        status = result.get("status")
        reason = str(result.get("reason") or "")
        confidence = str(result.get("confidence") or "low")

        if status == "vulnerable":
            detail = (
                f"{reason}; unauthenticated root command injection on MeiG FORGE_SLT711 class "
                f"firmware (tested {_AFFECTED_FIRMWARE})"
            )
            self.set_info(
                severity="critical",
                cve="CVE-2026-36356",
                reason=detail,
                confidence=confidence,
                endpoint=endpoint,
                elapsed=result.get("elapsed"),
            )
            print_success(reason)
            print_warning("Use exploits/linux/http/meig_forge_slt711_cve_2026_36356_rce to obtain a shell")
            return True

        if status == "likely":
            detail = (
                f"{reason}; endpoint reachable with retcode=0 — blind RCE may be present "
                f"(timing probe did not delay; firmware <= {_AFFECTED_FIRMWARE} class)"
            )
            self.set_info(
                severity="high",
                cve="CVE-2026-36356",
                reason=detail,
                confidence=confidence,
                endpoint=endpoint,
                elapsed=result.get("elapsed"),
            )
            print_warning(reason)
            return True

        if status == "error":
            print_error(reason)
            return False

        if fingerprint and fingerprint.get("status") in ("match", "maybe"):
            self.set_info(
                severity="medium",
                cve="CVE-2026-36356",
                reason=(
                    f"{fingerprint.get('reason')}; {endpoint} did not confirm injection — "
                    "may be patched or endpoint restricted"
                ),
                confidence="low",
                endpoint=endpoint,
            )
            print_status(reason)
            return False

        print_status(reason)
        return False
