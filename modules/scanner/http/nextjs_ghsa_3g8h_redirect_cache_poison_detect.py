#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js x-nextjs-data redirect cache poisoning (GHSA-3g8h) — detect",
        "description": (
            "GET the configured path without redirects, then repeat with `x-nextjs-data: 1`. "
            "Vulnerable: 2xx + `x-nextjs-redirect` without `Location`. Patched: 3xx + `Location`."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://github.com/advisories/GHSA-3g8h-86w9-wvmq"],
        "tags": ["scanner", "http", "nextjs", "redirect", "cache"],
    }

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

    def _get(self, extra_headers=None):
        url = self._url()
        kw = dict(allow_redirects=False, timeout=float(self._o(self.timeout)))
        if extra_headers:
            kw["headers"] = extra_headers
        try:
            r = self.get(url, **kw)
            h = r.headers
            loc = (h.get("Location") or "").strip()
            nxt = (h.get("x-nextjs-redirect") or "").strip()
            return r.status_code, loc, nxt, None
        except Exception as e:
            return 0, "", "", str(e)
        finally:
            if extra_headers:
                for k in extra_headers:
                    self.session.headers.pop(k, None)

    @staticmethod
    def _verdict(code, loc, nxt):
        if 200 <= code < 300 and nxt and not loc:
            return "vulnerable"
        if 300 <= code < 400 and loc:
            return "patched"
        return "inconclusive"

    def run(self):
        _, _, _, be = self._get()
        if be:
            self.set_info(reason=f"GET failed: {be}")
            return False
        xc, loc, nxt, xe = self._get({"x-nextjs-data": "1"})
        if xe:
            self.set_info(reason=f"Probe GET failed: {xe}")
            return False
        v = self._verdict(xc, loc, nxt)
        if v == "vulnerable":
            self.set_info(reason=f"2xx with x-nextjs-redirect, no Location (HTTP {xc})", confidence="high")
            return True
        if v == "patched":
            self.set_info(reason=f"3xx + Location with header (HTTP {xc})", confidence="high")
        else:
            self.set_info(reason=f"Inconclusive HTTP {xc}", confidence="low")
        return False
