#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect anonymous FTP login."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ftp.detectors import probe_ftp_anonymous


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "FTP Anonymous Login",
        "description": (
            "Checks whether the FTP service allows anonymous or guest login "
            "and optionally lists the landing directory."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc1635",
        ],
        "tags": ["ftp", "network", "scanner", "anonymous", "misconfig", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.3,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": ""},
                    "ftp_surface",
                    "anonymous_access",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["auxiliary/scanner/ftp/ftp_enum"],
            },
        },
    }

    port = OptPort(21, "Target FTP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        for user, password in (
            ("anonymous", "anonymous@"),
            ("ftp", "ftp@"),
            ("anonymous", "mozilla@example.com"),
        ):
            info = probe_ftp_anonymous(
                host=host,
                port=port,
                timeout=self._timeout(),
                username=user,
                password=password,
            )
            if not info.get("anonymous"):
                continue

            preview = str(info.get("list_preview") or "").strip()
            files = [line.strip() for line in preview.splitlines() if line.strip()][:12]
            self.report_finding(
                "Anonymous FTP login allowed",
                severity="medium",
                evidence={
                    "host": host,
                    "port": port,
                    "username": user,
                    "banner": str(info.get("banner") or "")[:200],
                    "cwd": str(info.get("cwd") or ""),
                    "files_found": files,
                },
                impact={
                    "summary": "Unauthenticated users may read (and sometimes write) FTP content.",
                    "business_risk": "Data exposure / staging for further compromise",
                },
                remediation={
                    "summary": "Disable anonymous FTP or tightly restrict accessible paths.",
                    "actions": [
                        "Disable anonymous/guest FTP accounts",
                        "Enforce authenticated FTP/SFTP only",
                        "Restrict filesystem roots and write permissions",
                    ],
                },
            )
            return True
        return False
