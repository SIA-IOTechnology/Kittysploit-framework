#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection chemins métadonnées cloud (risque SSRF / proxy vers metadata)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Paths often proxied to cloud metadata (169.254.169.254); finding them = potential SSRF/metadata exposure
METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data",
    "/metadata",
    "/metadata/",
    "/computeMetadata/v1/",
    "/computeMetadata/v1",
    "/openstack/latest/meta_data.json",
    "/openstack/2012-08-10/meta_data.json",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Cloud metadata path detection",
        "description": "Detects HTTP paths that may expose cloud metadata (AWS/Azure/GCP/OpenStack).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["cloud", "scanner", "metadata", "aws", "azure", "gcp", "ssrf", "imds"],
    }

    def run(self):
        for path in METADATA_PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 403, 401):
                continue
            # 200 with body = likely metadata; 403 with Metadata: true (GCP) = metadata endpoint
            h = {k.lower(): v for k, v in r.headers.items()}
            if h.get("metadata") == "true" or (r.status_code == 200 and len(r.text) > 0 and ("instance" in r.text.lower() or "ami-id" in r.text or "account" in r.text.lower())):
                self.set_info(severity="high", reason=f"Metadata endpoint at {path}")
                return True
            if r.status_code == 200 and r.text and ("availability_zone" in r.text or "instance-id" in r.text or "local-hostname" in r.text):
                self.set_info(severity="high", reason=f"Metadata endpoint at {path}")
                return True
        return False
