#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify MinIO/S3 anonymous bucket listing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_xml_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MinIO Public Bucket Listing Verification",
        "description": "Confirms anonymous ListBuckets or open bucket listing on MinIO/S3 API.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["minio", "s3", "storage", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["cloud_exposure", "unauth_read"]},
        },
    }

    def run(self):
        for path in ("/minio/v2/metrics/bucket", "/", "/?list-type=2"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 403):
                continue
            body = r.text or ""
            if is_xml_response(body) and ("listbucketresult" in body.lower() or "<name>" in body.lower()):
                self.set_info(
                    severity="high",
                    reason="MinIO/S3 anonymous bucket listing confirmed",
                    path=path,
                    confidence="high",
                )
                return True
            if "x-amz-bucket" in str(r.headers).lower() or "minio" in body.lower() and r.status_code == 200:
                self.set_info(severity="medium", reason="MinIO API exposed; listing not fully confirmed", path=path)
                return True
        return False
