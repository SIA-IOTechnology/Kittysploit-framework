#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection listing public AWS S3 (check-only)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "AWS S3 public listing detect",
        "description": "Checks if S3 ListBucket is anonymously accessible (no exploitation).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/aws/s3_bucket_access_check",
            "auxiliary/aws/s3_bucket_file_list",
            "auxiliary/aws/s3_sensitive_pattern_scan",
            "auxiliary/aws/aws_s3_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "aws", "s3", "misconfig", "public"],
    }

    timeout = OptString("5", "HTTP timeout in seconds", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def run(self):
        timeout_seconds = self._to_int(self.timeout, 5)
        r = self.http_request(
            method="GET",
            path="/?list-type=2&max-keys=1",
            allow_redirects=False,
            timeout=timeout_seconds,
        )
        if not r:
            return False
        body = (r.text or "").lower()
        if r.status_code == 200 and "listbucketresult" in body and ("<contents>" in body or "<keycount>" in body):
            self.set_info(severity="high", reason="Anonymous S3 ListBucket appears enabled")
            return True
        return False
