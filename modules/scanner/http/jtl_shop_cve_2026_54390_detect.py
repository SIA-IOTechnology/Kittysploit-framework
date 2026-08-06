#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect JTL Shop CVE-2026-54390 Smarty SSTI (5.2.0–5.7.1)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.jtl_shop_probe import (
    JTL_PATCHED_VERSIONS,
    JTL_RCE_MIN,
    JTL_VULN_MAX,
    JTL_VULN_MIN,
    JtlShop,
)


class Module(Scanner, Http_client, JtlShop):
    __info__ = {
        "name": "JTL Shop CVE-2026-54390 Smarty SSTI Detect",
        "description": (
            "Detects JTL Shop 5.2.0 through 5.7.1 vulnerable to CVE-2026-54390: "
            "contact form fields reach SmartyRenderer email subjects via "
            "fetch('string:' . $subject). Versions 5.4.0+ allow full RCE via "
            "registered Smarty modifiers; 5.2.x–5.3.x allow credential theft."
        ),
        "author": ["Sansec", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-54390"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-54390",
            "https://www.cve.org/CVERecord?id=CVE-2026-54390",
            "https://sansec.io/research/jtl-shop-ssti-rce",
        ],
        "modules": ["exploits/multi/http/jtl_shop_cve_2026_54390_smarty_rce"],
        "tags": [
            "web",
            "scanner",
            "jtl",
            "jtl-shop",
            "smarty",
            "ssti",
            "contact-form",
            "rce",
            "cve-2026-54390",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["rce"],
                "suggested_followups": [
                    "exploits/multi/http/jtl_shop_cve_2026_54390_smarty_rce",
                ],
            },
        },
    }

    contact_path = OptString(
        "",
        "Optional contact form path override (auto-detect if empty)",
        False,
        advanced=True,
    )

    def _base_path(self) -> str:
        path = str(getattr(self, "path", "/") or "/").strip()
        return path if path.startswith("/") else f"/{path}"

    def run(self):
        probe = self.jtl_probe(self._base_path())
        if not probe.get("found"):
            return False

        version = str(probe.get("version") or "")
        vulnerable = self.jtl_is_vulnerable(version)
        rce_capable = self.jtl_supports_rce(version)
        extra_paths = [str(self.contact_path)] if str(self.contact_path or "").strip() else None
        form = self.jtl_find_contact_form(self._base_path(), extra_paths=extra_paths)

        if vulnerable is True and rce_capable is True:
            severity = "critical"
            reason = (
                f"JTL Shop {version} ({JTL_VULN_MIN}–{JTL_VULN_MAX}, RCE >= {JTL_RCE_MIN}) "
                f"with contact form at {form.get('path') if form else 'unknown'}; "
                f"CVE-2026-54390 Smarty SSTI"
            )
        elif vulnerable is True:
            severity = "high"
            reason = (
                f"JTL Shop {version} vulnerable to CVE-2026-54390 Smarty SSTI "
                f"(credential/config theft; full RCE requires >= {JTL_RCE_MIN})"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"JTL Shop {version} patched for CVE-2026-54390 "
                f"(fixed in {', '.join(JTL_PATCHED_VERSIONS)})"
            )
        else:
            severity = "high"
            reason = (
                f"JTL Shop detected (version unknown); CVE-2026-54390 if "
                f"{JTL_VULN_MIN}–{JTL_VULN_MAX}"
            )

        print_status(
            f"jtl-shop version={version or 'unknown'} vuln={vulnerable} "
            f"rce={rce_capable} contact={bool(form)}"
        )
        self.set_info(
            severity=severity,
            reason=reason,
            version=version or "unknown",
            vulnerable=vulnerable,
            rce_capable=rce_capable,
            contact_form=bool(form),
            contact_path=(form or {}).get("path"),
            cve="CVE-2026-54390",
            evidence=probe.get("evidence"),
        )
        return True
