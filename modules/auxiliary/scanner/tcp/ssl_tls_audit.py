#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live SSL/TLS configuration audit for TCP services."""

from __future__ import annotations

import json
import re

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client, _get_opt
from lib.protocols.tcp.tls_audit import audit_tls_service


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "SSL/TLS Configuration Audit",
        "description": (
            "Audit a live TLS service: negotiated protocol and cipher, certificate chain "
            "metadata (SAN, expiry, issuer), hostname coverage, weak/legacy TLS signals, "
            "and optional trust-store validation."
        ),
        "author": ["KittySploit Team"],
        "tags": ["auxiliary", "scanner", "tcp", "tls", "ssl", "certificate", "misconfig"],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(443, "Target TCP port (443 HTTPS, 587 SMTP, 110 POP3, etc.)", True)
    timeout = OptPort(10, "Probe timeout in seconds", False, advanced=True)
    server_name = OptString("", "Override SNI hostname (defaults to target hostname)", required=False, advanced=True)
    verify_ssl = OptBool(False, "Validate certificate against the system trust store", required=False)
    probe_versions = OptBool(True, "Probe accepted TLS protocol versions (1.0–1.3)", required=False)
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

    def _connect_host(self) -> str:
        return self._host()

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
        host = self._connect_host()
        if not host:
            print_error("Target hostname or IP is required")
            return {"error": "missing_target"}

        port = self._port()
        sni = self._sni_hostname()
        print_info(f"Auditing TLS on {host}:{port} (SNI={sni or host})")

        result = audit_tls_service(
            host,
            port,
            server_name=sni or host,
            timeout=self._timeout(),
            verify_ssl=bool(self.verify_ssl),
            probe_versions=bool(self.probe_versions),
            use_starttls=bool(self.starttls),
            auto_starttls=bool(self.auto_starttls),
            log=self._log,
        )
        data = result.to_dict()

        if not result.success:
            print_error(result.error or "TLS audit failed")
            if self.output_file:
                self._save_output(data)
            return data

        cert = result.certificate
        print_success(
            f"TLS {result.tls_version} / {result.cipher} "
            f"({result.cipher_bits} bits)"
        )
        print_info(
            f"Certificate: CN={cert.get('subject_cn', '')} "
            f"issuer={cert.get('issuer_cn', '')} "
            f"expires={cert.get('not_after', '')}"
        )
        sans = cert.get("san_dns", [])
        if sans:
            preview = ", ".join(sans[:8])
            if len(sans) > 8:
                preview += f" (+{len(sans) - 8} more)"
            print_info(f"SAN DNS ({len(sans)}): {preview}")

        if result.supported_versions:
            print_info(f"Accepted TLS versions: {', '.join(result.supported_versions)}")

        if result.verify_ssl:
            if result.verify_ok:
                print_success("Trust-store validation: OK")
            else:
                print_warning(f"Trust-store validation failed: {result.verify_error}")

        if result.findings:
            print_warning(f"Findings ({len(result.findings)}) — risk={result.risk_level} score={result.risk_score}")
            for finding in result.findings:
                print_warning(f"[{finding.get('severity', 'info').upper()}] {finding.get('description', '')}")
        else:
            print_success(f"No TLS misconfiguration signals detected (risk={result.risk_level})")

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

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error") or not data.get("success"):
            return [], []

        host = data.get("server_name") or data.get("host") or self.target
        nodes = []
        edges = []

        cert = data.get("certificate", {})
        cert_id = f"cert_{host}"
        nodes.append({
            "id": cert_id,
            "label": f"{cert.get('subject_cn', 'certificate')} ({data.get('tls_version', '')})",
            "group": "certificate",
            "icon": "🔐",
        })
        edges.append({"from": host, "to": cert_id, "label": "tls"})

        for idx, san in enumerate(cert.get("san_dns", [])[:15]):
            nid = f"san_{idx}_{san}"
            nodes.append({"id": nid, "label": san, "group": "subdomain", "icon": "🌐"})
            edges.append({"from": cert_id, "to": nid, "label": "san"})

        for idx, finding in enumerate(data.get("findings", [])[:10]):
            nid = f"finding_{idx}"
            nodes.append({
                "id": nid,
                "label": finding.get("description", finding.get("type", "finding")),
                "group": "risk",
                "icon": "⚠️",
            })
            edges.append({"from": cert_id, "to": nid, "label": finding.get("severity", "info")})

        return nodes, edges
