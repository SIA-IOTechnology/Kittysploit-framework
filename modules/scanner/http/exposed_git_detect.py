#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection dépôt Git exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/.git/HEAD",
    "/.git/config",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Exposed Git repository detection",
        "description": "Detects publicly accessible Git metadata such as /.git/HEAD or /.git/config.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["web", "scanner", "git", "disclosure", "source-code"],
    }

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue

            body = (r.text or "").strip()
            if path.endswith("/HEAD") and "ref: refs/" in body:
                self.set_info(severity="medium", reason=f"Exposed Git metadata at {path}")
                return True
            if path.endswith("/config") and "[core]" in body:
                self.set_info(severity="medium", reason=f"Exposed Git config at {path}")
                return True

        return False
