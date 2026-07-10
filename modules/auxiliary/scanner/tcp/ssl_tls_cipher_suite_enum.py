#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate accepted TLS cipher suites on a live service."""

from __future__ import annotations

import json
import re

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client, _get_opt
from lib.protocols.tcp.tls_audit import enumerate_cipher_suites


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "SSL/TLS Cipher Suite Enumeration",
        "description": (
            "Enumerate cipher suites accepted by a TLS endpoint and flag weak or "
            "deprecated protocol versions."
        ),
        "author": ["KittySploit Team"],
        "tags": ["auxiliary", "scanner", "tcp", "tls", "ssl", "cipher", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(443, "Target TCP port", True)
    timeout = OptPort(10, "Probe timeout in seconds", False, advanced=True)
    server_name = OptString("", "Override SNI hostname (defaults to target hostname)", required=False, advanced=True)
    max_ciphers = OptInteger(80, "Maximum cipher candidates to test", required=False, advanced=True)
    starttls = OptBool(False, "Force STARTTLS/STLS/AUTH TLS before the TLS handshake", required=False)
    auto_starttls = OptBool(
        True,
        "Automatically negotiate STARTTLS on common mail/FTP ports (21, 25, 110, 143, 587)",
        required=False,
        advanced=True,
    )
    output_file = OptString("", "Optional JSON output file", required=False)
    verbose = OptBool(False, "Verbose TLS exchange logging", required=False, advanced=True)

    def _log(self, message: str) -> None:
        if self.verbose:
            print_debug(message)

    def _sni_hostname(self) -> str:
        override = str(_get_opt(self, "server_name") or "").strip()
        if override:
            return override
        raw = str(_get_opt(self, "target") or "").strip()
        raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
        return raw.split("/", 1)[0].split(":", 1)[0].strip()

    def check(self):
        return self.is_tcp_open()

    def run(self):
        host = self._host()
        if not host:
            print_error("Target hostname or IP is required")
            return {"error": "missing_target"}

        port = self._port()
        sni = self._sni_hostname()
        print_info(f"Enumerating cipher suites on {host}:{port} (SNI={sni or host})")

        result = enumerate_cipher_suites(
            host,
            port,
            server_name=sni or host,
            timeout=self._timeout(),
            max_ciphers=int(self.max_ciphers or 80),
            use_starttls=bool(self.starttls),
            auto_starttls=bool(self.auto_starttls),
            log=self._log,
        )
        data = result.to_dict()

        if not result.success:
            print_error(result.error or "Cipher enumeration failed")
            if self.output_file:
                self._save_output(data)
            return data

        print_success(
            f"Accepted ciphers: {len(result.accepted_ciphers)} "
            f"versions={', '.join(result.supported_versions)}"
        )
        for entry in result.accepted_ciphers[:12]:
            flag = " [WEAK]" if entry.weak else ""
            print_info(f"  {entry.tls_version} {entry.name} ({entry.bits} bits){flag}")
        if len(result.accepted_ciphers) > 12:
            print_info(f"  ... +{len(result.accepted_ciphers) - 12} more")

        if result.weak_ciphers:
            print_warning(f"Weak ciphers accepted: {', '.join(result.weak_ciphers[:10])}")
        else:
            print_success(f"No weak cipher suites observed (risk={result.risk_level})")

        if self.output_file:
            self._save_output(data)
        return data

    def _save_output(self, data):
        try:
            with open(str(self.output_file), "w") as fp:
                json.dump(data, fp, indent=2)
            print_success(f"Results saved to {self.output_file}")
        except Exception as exc:
            print_error(f"Failed to save output: {exc}")
