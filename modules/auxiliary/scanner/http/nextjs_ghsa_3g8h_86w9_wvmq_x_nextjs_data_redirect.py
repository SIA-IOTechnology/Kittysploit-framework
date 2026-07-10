#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js x-nextjs-data redirect cache poisoning (GHSA-3g8h-86w9-wvmq)",
        "description": (
            "Compares GET responses on a redirecting route with and without `x-nextjs-data: 1`. "
            "Pre-16.2.5 Next.js may return 2xx + `x-nextjs-redirect` without `Location`, breaking "
            "browsers and poisoning shared caches. Patched stacks keep a normal 3xx + Location."
        ),
        "author": ["KittySploit Team"],
        "references": ["https://github.com/advisories/GHSA-3g8h-86w9-wvmq"],
        "tags": ["http", "nextjs", "redirect", "cache", "scanner", "ghsa"],
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

    expected_dest = OptString(
        "",
        "Optional expected redirect path (e.g. /somewhere); printed for context only",
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
            ct = (h.get("Content-Type") or "").strip()
            return r.status_code, loc, nxt, ct, r.content[:4096], None
        except Exception as e:
            return 0, "", "", "", b"", str(e)
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

    def check(self):
        bc, bloc, bnxt, _, _, be = self._get()
        base = {"code": bc, "location": bloc, "x_nextjs_redirect": bnxt}
        if be:
            return {"vulnerable": False, "reason": f"GET failed: {be}", "confidence": "high", "baseline": base}
        xc, loc, nxt, _, _, xe = self._get({"x-nextjs-data": "1"})
        if xe:
            return {"vulnerable": False, "reason": f"Probe GET failed: {xe}", "confidence": "high", "baseline": base}
        v = self._verdict(xc, loc, nxt)
        probe = {"code": xc, "location": loc, "x_nextjs_redirect": nxt}
        if v == "vulnerable":
            return {
                "vulnerable": True,
                "reason": f"2xx with x-nextjs-redirect and no Location (HTTP {xc})",
                "confidence": "high",
                "baseline": base,
                "probe": probe,
            }
        if v == "patched":
            return {
                "vulnerable": False,
                "reason": f"3xx + Location preserved with header (HTTP {xc})",
                "confidence": "high",
                "baseline": base,
                "probe": probe,
            }
        return {
            "vulnerable": False,
            "reason": f"Inconclusive HTTP {xc}",
            "confidence": "low",
            "baseline": base,
            "probe": probe,
        }

    def run(self) -> bool:
        exp = str(self._o(self.expected_dest) or "").strip()
        print_info(f"URL: {self._url()}" + (f"  (expected dest {exp})" if exp else ""))

        print_status("[1/3] Baseline GET (no x-nextjs-data)")
        bc, bloc, bnxt, _, _, be = self._get()
        if be:
            print_error(f"Baseline failed: {be}")
            return False
        print_status(f"  HTTP {bc}")
        print_status(f"  Location: {bloc or '(none)'}")
        print_status(f"  x-nextjs-redirect: {bnxt or '(none)'}")

        print_status("[2/3] GET with x-nextjs-data: 1")
        xc, loc, nxt, ct, body, xe = self._get({"x-nextjs-data": "1"})
        if xe:
            print_error(f"Probe failed: {xe}")
            return False
        print_status(f"  HTTP {xc}")
        print_status(f"  Content-Type: {ct or '(none)'}")
        print_status(f"  Location: {loc or '(none)'}")
        print_status(f"  x-nextjs-redirect: {nxt or '(none)'}")

        print_status("[3/3] Verdict")
        v = self._verdict(xc, loc, nxt)
        if v == "vulnerable":
            print_error(
                "Vulnerable: 2xx with x-nextjs-redirect and no Location — cache poisoning / broken redirect in browsers."
            )
            return True
        if v == "patched":
            print_success("Appears patched (3xx + Location with attacker header).")
            return False
        print_warning(f"Inconclusive (HTTP {xc}). Body sample: {body[:200]!r}")
        return False
