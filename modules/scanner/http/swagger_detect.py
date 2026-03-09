#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Swagger / OpenAPI exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/swagger",
    "/swagger/",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/api-docs/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Swagger/OpenAPI detection",
        "description": "Detects exposed Swagger or OpenAPI documentation (API disclosure).",
        "author": "KittySploit Team",
        "severity": "low",
        "modules": [],
        "tags": ["web", "scanner", "swagger", "openapi", "api", "disclosure"],
    }

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            t = r.text.lower()
            if "swagger" in t or "openapi" in t or '"paths":' in t or "api-docs" in path and ("{" in t or "yaml" in r.headers.get("content-type", "")):
                self.set_info(severity="low", reason=f"API docs exposed at {path}")
                return True
        return False
