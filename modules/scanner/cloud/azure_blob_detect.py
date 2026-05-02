#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Azure Blob Storage exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Azure Blob Storage detection",
        "description": "Detects Azure Blob Storage REST API (x-ms-* headers or Azure error body).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/azure/blob_acl_misconfig_hint",
            "auxiliary/azure/blob_exposure_audit",
            "auxiliary/azure/blob_container_file_list",
            "auxiliary/azure/blob_sensitive_pattern_scan",
            "auxiliary/azure/blob_file_download",
            "auxiliary/azure/azure_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "azure", "blob", "storage"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        h = {k.lower(): v for k, v in r.headers.items()}
        for key in ("x-ms-request-id", "x-ms-version", "x-ms-lease-state", "x-ms-blob-type"):
            if key in h:
                self.set_info(severity="medium", reason=f"Azure Blob ({key})")
                return True
        t = r.text.lower()
        if "azure" in t and ("blob" in t or "storage" in t or "x-ms-" in t):
            self.set_info(severity="medium", reason="Azure Blob (response body)")
            return True
        return False
