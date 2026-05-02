#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection listing public Azure Blob container (check-only)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Azure Blob public listing detect",
        "description": "Checks if Azure Blob container listing is anonymously accessible (no exploitation).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/azure/blob_acl_misconfig_hint",
            "auxiliary/azure/blob_exposure_audit",
            "auxiliary/azure/blob_container_file_list",
            "auxiliary/azure/blob_sensitive_pattern_scan",
            "auxiliary/azure/azure_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "azure", "blob", "misconfig", "public"],
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
            path="/?restype=container&comp=list&maxresults=1",
            allow_redirects=False,
            timeout=timeout_seconds,
        )
        if not r:
            return False
        body = (r.text or "").lower()
        if r.status_code == 200 and "enumerationresults" in body and ("<blobs>" in body or "<blob>" in body):
            self.set_info(severity="high", reason="Anonymous Azure Blob container listing appears enabled")
            return True
        return False
