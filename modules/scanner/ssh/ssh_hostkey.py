#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH host key fingerprints (NSE ssh-hostkey)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_ssh_hostkey


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SSH Host Key",
        "description": (
            "Retrieves the SSH host key type and MD5/SHA256 fingerprints "
            "(NSE ssh-hostkey). Requires Paramiko."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/ssh-hostkey.html"],
        "tags": ["ssh", "hostkey", "fingerprint", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    "service_identified",
                    "remote_access",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/ssh/ssh_auth_methods",
                    "scanner/ssh/ssh_empty_password_detect",
                    "auxiliary/scanner/ssh/ssh_login_bruteforce",
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_ssh_hostkey(host=host, port=port, timeout=max(self._timeout(), 8.0))
        if not info.get("detected") or not info.get("key_type"):
            if info.get("error") == "paramiko_required":
                print_info("Paramiko required for SSH host key retrieval")
            return False
        key_type = str(info.get("key_type") or "")
        bits = int(info.get("bits") or 0)
        fp_sha256 = str(info.get("fingerprint_sha256") or "")
        fp_md5 = str(info.get("fingerprint_md5") or "")
        weak = bool(info.get("weak"))
        severity = "low" if weak else "info"
        parts = [key_type]
        if bits:
            parts.append(f"{bits}-bit")
        if fp_sha256:
            parts.append(fp_sha256)
        elif fp_md5:
            parts.append(f"MD5:{fp_md5}")
        if weak:
            parts.append("weak key")
        reason = " ".join(parts) if parts else "SSH host key retrieved"
        banner = str(info.get("banner") or "").strip()
        if banner:
            reason = f"{reason} | banner={banner}"
        self.set_info(
            severity=severity,
            reason=reason,
            key_type=key_type,
            bits=bits,
            fingerprint_md5=fp_md5,
            fingerprint_sha256=fp_sha256,
            weak=weak,
            banner=banner,
        )
        return True
