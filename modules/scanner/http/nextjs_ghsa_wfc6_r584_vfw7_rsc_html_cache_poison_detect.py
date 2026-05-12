#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js RSC / HTML cache poisoning (GHSA-wfc6) — detect",
        "description": (
            "Baseline GET, GET with RSC + Next-Router-Prefetch, clean GET again; flags text/html bodies "
            "that still look like RSC Flight framing."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://github.com/advisories/GHSA-wfc6-r584-vfw7"],
        "tags": ["scanner", "http", "nextjs", "rsc", "cache"],
    }

    rsc_header_value = OptString("text/x-component", "RSC header value for poison request", required=False, advanced=True)

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
        kw = dict(timeout=float(self._o(self.timeout)))
        if extra_headers:
            kw["headers"] = extra_headers
        try:
            r = self.get(url, **kw)
            ct = (r.headers.get("Content-Type") or "").lower()
            return r.status_code, ct, r.content[:2048], None
        except Exception as e:
            return -1, "", b"", str(e)
        finally:
            if extra_headers:
                for k in extra_headers:
                    self.session.headers.pop(k, None)

    @staticmethod
    def _rsc_framing(body: bytes) -> bool:
        if not body:
            return False
        return body.startswith(b"0:") or b"$react" in body or b'"$",' in body

    def run(self):
        _, _, _, e1 = self._get()
        if e1:
            self.set_info(reason=f"baseline: {e1}")
            return False
        rv = str(self._o(self.rsc_header_value) or "text/x-component").strip() or "text/x-component"
        _, ct2, b2, e2 = self._get({"RSC": rv, "Next-Router-Prefetch": "1"})
        if e2:
            self.set_info(reason=f"poison: {e2}")
            return False
        _, ct3, b3, e3 = self._get()
        if e3:
            self.set_info(reason=f"reread: {e3}")
            return False
        if "text/html" in (ct3 or "") and self._rsc_framing(b3):
            self.set_info(reason="re-read text/html + Flight framing", confidence="medium")
            return True
        if "text/html" in (ct2 or "") and self._rsc_framing(b2):
            self.set_info(reason="poison text/html + Flight framing", confidence="medium")
            return True
        return False
