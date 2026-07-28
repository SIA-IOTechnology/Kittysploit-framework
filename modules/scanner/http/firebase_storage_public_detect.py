#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect publicly listable Firebase Storage / GCS buckets."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


_BUCKET_RE = re.compile(
    r"""(?:storageBucket|storage_bucket)\s*[:=]\s*["']([a-z0-9.\-]+)["']""",
    re.I,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firebase Storage Public Listing",
        "description": (
            "Probe Firebase Storage REST "
            "`/v0/b/{bucket}/o` for anonymous object listing (common misconfig when rules are open)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": [
            "web", "scanner", "firebase", "storage", "misconfiguration", "cloud", "gcs",
        ],
        "references": [
            "https://firebase.google.com/docs/storage/security",
            "https://firebase.google.com/docs/storage/web/download-files",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
        },
    }

    bucket = OptString(
        "",
        "Storage bucket (e.g. project.appspot.com); scraped from page if empty",
        False,
    )

    def _scrape_bucket(self) -> str:
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or r.status_code != 200 or not r.text:
            return ""
        m = _BUCKET_RE.search(r.text)
        return m.group(1) if m else ""

    def run(self):
        bucket = str(
            self.bucket.value if hasattr(self.bucket, "value") else self.bucket or ""
        ).strip()
        if not bucket:
            bucket = self._scrape_bucket()
        if not bucket:
            host = str(self.target.value if hasattr(self.target, "value") else self.target or "")
            host = host.split(":")[0].strip().lower()
            if host.endswith(".appspot.com") or "firebasestorage" in host:
                bucket = host
        if not bucket:
            self.set_info(reason="No storageBucket found (set bucket option)")
            return False

        url = f"https://firebasestorage.googleapis.com/v0/b/{quote(bucket)}/o?maxResults=5"
        try:
            self._configure_session()
            r = self.session.get(url, timeout=8, verify=self._to_bool(self.verify_ssl))
        except Exception as exc:
            self.set_info(reason=f"probe failed: {exc}")
            return False

        text = (r.text or "")[:1000]
        if r.status_code == 200 and ('"items"' in text or '"prefixes"' in text or text.strip() == "{}"):
            self.set_info(
                severity="high",
                reason=f"Anonymous listing allowed on bucket {bucket}",
                bucket=bucket,
                http=r.status_code,
                evidence=text[:300],
            )
            return True
        if r.status_code in (401, 403) or "Permission denied" in text or "PERMISSION_DENIED" in text:
            self.set_info(
                severity="info",
                reason=f"Bucket {bucket} denies anonymous list",
                bucket=bucket,
                http=r.status_code,
            )
            return False
        self.set_info(
            reason=f"bucket={bucket} http={r.status_code}",
            bucket=bucket,
            http=r.status_code,
            evidence=text[:200],
        )
        return False
