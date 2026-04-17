#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection fichiers .env exposés."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/app/.env",
    "/config/.env",
]

KEYWORDS = [
    "app_key=",
    "app_env=",
    "db_password=",
    "db_username=",
    "aws_access_key_id=",
    "mail_host=",
    "secret_key=",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Exposed .env file detection",
        "description": "Detects publicly accessible .env files containing application secrets or environment configuration.",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["web", "scanner", "env", "secrets", "disclosure", "config"],
    }

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue

            body = (r.text or "").lower()
            if any(keyword in body for keyword in KEYWORDS):
                self.set_info(severity="high", reason=f"Exposed environment file at {path}")
                return True

        return False
