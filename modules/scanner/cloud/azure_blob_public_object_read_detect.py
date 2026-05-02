#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection lecture anonyme blob Azure (check-only)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Azure Blob public object read detect",
        "description": "Checks anonymous read access to a user-provided blob path (no exploitation).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/azure/blob_file_download",
            "auxiliary/azure/blob_sensitive_pattern_scan",
            "auxiliary/azure/azure_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "azure", "blob", "misconfig", "public"],
    }

    blob_path = OptString("/index.html", "Blob path to test (e.g. /dump.sql)", required=False)
    timeout = OptString("5", "HTTP timeout in seconds", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def run(self):
        path = str(self.blob_path or "/index.html").strip()
        if not path.startswith("/"):
            path = "/" + path
        timeout_seconds = self._to_int(self.timeout, 5)
        r = self.http_request(method="HEAD", path=path, allow_redirects=False, timeout=timeout_seconds)
        if not r or r.status_code in (400, 405, 501):
            # Fallback minimal GET for servers not handling HEAD.
            r = self.http_request(
                method="GET",
                path=path,
                allow_redirects=False,
                timeout=timeout_seconds,
                headers={"Range": "bytes=0-0"},
            )
        if not r:
            return False
        if r.status_code == 200:
            size = str((r.headers or {}).get("Content-Length", "unknown"))
            self.set_info(severity="high", reason=f"Anonymous Azure blob read possible on {path} (content-length={size})")
            return True
        if r.status_code == 206:
            self.set_info(severity="high", reason=f"Anonymous Azure blob ranged-read possible on {path}")
            return True
        return False
