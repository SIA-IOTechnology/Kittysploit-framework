#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection bucket S3 / API S3 exposée."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "AWS S3 bucket detection",
        "description": "Detects S3 bucket or S3-style API (ListBucketResult, NoSuchKey, AccessDenied XML).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/aws/s3_bucket_access_check",
            "auxiliary/aws/s3_bucket_file_list",
            "auxiliary/aws/s3_sensitive_pattern_scan",
            "auxiliary/aws/s3_file_download",
            "auxiliary/aws/aws_s3_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "aws", "s3", "bucket", "storage"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        t = r.text
        # S3 REST API returns XML
        if "ListBucketResult" in t or "<Name>" in t and "Contents" in t:
            self.set_info(severity="medium", reason="S3 bucket listing (ListBucketResult)")
            return True
        if "NoSuchKey" in t or "AccessDenied" in t or "InvalidBucketName" in t or "NoSuchBucket" in t:
            self.set_info(severity="medium", reason="S3 API (AWS XML error response)")
            return True
        h = {k.lower(): v for k, v in r.headers.items()}
        if h.get("x-amz-request-id") or h.get("x-amz-id-2"):
            self.set_info(severity="medium", reason="S3 API (x-amz-* headers)")
            return True
        return False
