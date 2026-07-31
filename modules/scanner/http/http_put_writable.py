#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP PUT writable path check (NSE http-put)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.bigip_put import probe_http_put
from lib.scanner.target_utils import normalize_scanner_target


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP PUT Writable",
        "description": (
            "Attempts an HTTP PUT of a probe file and reports if the server accepts writes "
            "(NSE http-put). Tries DELETE cleanup afterward."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://nmap.org/nsedoc/scripts/http-put.html"],
        "tags": ["http", "put", "writable", "scanner", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "file_write"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    put_path = OptString(
        "/kittysploit_put_probe.txt",
        "Path to PUT the probe file",
        False,
    )

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
        url = f"{scheme}://{host}:{port}"
        timeout = float(getattr(self.timeout, "value", self.timeout) or 8)
        verify = bool(getattr(self.verify_ssl, "value", self.verify_ssl))
        path = str(self.put_path or "/kittysploit_put_probe.txt")
        info = probe_http_put(url=url, path=path, timeout=timeout, verify_ssl=verify)
        if not info.get("writable"):
            return False
        self.set_info(
            severity="high",
            reason=f"HTTP PUT accepted on {path}",
            path=path,
            status_code=int(info.get("status_code") or 0),
        )
        return True
