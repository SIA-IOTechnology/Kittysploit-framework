#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP NTLM challenge info (NSE http-ntlm-info)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.ntlm.detectors import probe_http_ntlm_info
from lib.scanner.target_utils import normalize_scanner_target


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP NTLM Info",
        "description": (
            "Sends an NTLM Type-1 negotiate and parses the Type-2 challenge for NetBIOS / "
            "DNS domain and computer names (NSE http-ntlm-info)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/http-ntlm-info.html"],
        "tags": ["http", "ntlm", "windows", "ad", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        target = str(getattr(self.target, "value", self.target) or "").strip()
        host, url_port, url_ssl = normalize_scanner_target(target)
        if not host:
            return False
        port = int(getattr(self.port, "value", self.port) or (443 if url_ssl else 80))
        if url_port:
            port = int(url_port)
        use_ssl = bool(getattr(self.ssl, "value", self.ssl))
        if url_ssl is not None:
            use_ssl = bool(url_ssl)
        scheme = "https" if use_ssl else "http"
        path = str(getattr(self.path, "value", self.path) or "/")
        url = f"{scheme}://{host}:{port}"
        timeout = float(getattr(self.timeout, "value", self.timeout) or 8)
        verify = bool(getattr(self.verify_ssl, "value", self.verify_ssl))
        info = probe_http_ntlm_info(url=url, timeout=timeout, verify_ssl=verify, path=path)
        if not info.get("detected"):
            return False
        ntlm = info.get("info") or {}
        self.set_info(
            severity="info",
            reason="HTTP NTLM challenge disclosed host/domain identity",
            nb_domain=str(ntlm.get("nb_domain") or ""),
            nb_computer=str(ntlm.get("nb_computer") or ""),
            dns_domain=str(ntlm.get("dns_domain") or ""),
            dns_computer=str(ntlm.get("dns_computer") or ""),
            os_version=str(ntlm.get("os_version") or ""),
            target_name=str(ntlm.get("target_name") or ""),
        )
        return True
