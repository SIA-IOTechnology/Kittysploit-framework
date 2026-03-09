#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection AWS CloudFront / CDN Amazon."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "AWS CloudFront detection",
        "description": "Detects AWS CloudFront CDN (X-Amz-Cf-* headers or CloudFront error pages).",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["cloud", "scanner", "aws", "cloudfront", "cdn"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        h = {k.lower(): v for k, v in r.headers.items()}
        if h.get("x-amz-cf-id") or h.get("x-amz-cf-pop") or "cloudfront" in str(h.get("via", "")).lower():
            self.set_info(severity="info", reason="CloudFront (X-Amz-Cf-* or Via)")
            return True
        if r.status_code in (403, 404) and "cloudfront" in r.text.lower() and "request" in r.text.lower():
            self.set_info(severity="info", reason="CloudFront error page")
            return True
        return False
