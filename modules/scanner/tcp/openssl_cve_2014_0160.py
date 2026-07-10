#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect OpenSSL Heartbleed (CVE-2014-0160) via malformed TLS heartbeat."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.protocols.tcp.tls_heartbeat import probe_heartbleed


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "OpenSSL Heartbleed CVE-2014-0160 detection",
        "description": (
            "Sends a malformed TLS heartbeat (CVE-2014-0160) and reports whether the "
            "server returns more data than declared. Supports direct TLS (e.g. HTTPS) and "
            "cleartext services that upgrade with STARTTLS/STLS/AUTH TLS."
        ),
        "author": ["Jared Stafford", "Travis Lee", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2014-0160",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://heartbleed.com/",
        ],
        "modules": ["auxiliary/scanner/tcp/openssl_cve_2014_0160_memory_dump",],
        "tags": [
            "scanner",
            "tcp",
            "tls",
            "ssl",
            "openssl",
            "heartbleed",
            "memory-disclosure",
            "cve-2014-0160",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(443, "Target TCP port (443 HTTPS, 587 SMTP, 110 POP3, etc.)", True)
    timeout = OptPort(10, "Probe timeout in seconds", False, advanced=True)
    starttls = OptBool(False,"Force STARTTLS/STLS/AUTH TLS before the TLS handshake",required=False)
    auto_starttls = OptBool(True, "Automatically negotiate STARTTLS on common mail/FTP ports (21, 25, 110, 143, 587)", required=False, advanced=True)
    verbose = OptBool(False, "Verbose TLS exchange logging", required=False, advanced=True)

    def _log(self, message: str) -> None:
        if self.verbose:
            print_debug(message)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target hostname or IP is required")
            return False

        port = self._port()
        print_status(f"Testing Heartbleed on {host}:{port}...")

        result = probe_heartbleed(
            host,
            port,
            timeout=self._timeout(),
            use_starttls=bool(self.starttls),
            auto_starttls=bool(self.auto_starttls),
            log=self._log,
        )

        if not result.vulnerable:
            self.set_info(
                severity="info",
                reason=result.reason or "Target does not appear vulnerable to Heartbleed",
            )
            print_info(result.reason or "Not vulnerable")
            return False

        self.set_info(
            severity="critical",
            cve="CVE-2014-0160",
            reason=(
                f"Malformed heartbeat on {host}:{port} leaked {result.leaked_bytes} bytes "
                f"({result.tls_version})"
            ),
            confidence="high",
            tls_version=result.tls_version,
            leaked_bytes=result.leaked_bytes,
        )
        print_warning(
            f"VULNERABLE — heartbeat leaked {result.leaked_bytes} bytes over {result.tls_version}"
        )
        return True
