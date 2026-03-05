#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Security headers that should ideally be present
SECURITY_HEADERS = [
    ("X-Frame-Options", "low", "Clickjacking protection"),
    ("X-Content-Type-Options", "low", "MIME sniffing protection"),
    ("X-XSS-Protection", "info", "Legacy XSS filter"),
    ("Strict-Transport-Security", "info", "HSTS"),
    ("Content-Security-Policy", "info", "CSP"),
    ("Referrer-Policy", "info", "Referrer leakage"),
    ("Permissions-Policy", "info", "Feature policy"),
]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Security headers detection',
        'description': 'Detects missing HTTP security headers (X-Frame-Options, CSP, HSTS, etc.).',
        'author': 'KittySploit Team',
        'severity': 'low',
        'modules': [],
        'tags': ['web', 'scanner', 'security', 'headers', 'hardening'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers_lower = {k.lower(): k for k in r.headers}
        missing = []
        for header_name, _sev, desc in SECURITY_HEADERS:
            if header_name.lower() not in headers_lower:
                missing.append(header_name)
        if missing:
            self.set_info(severity="low", reason=f"Missing headers: {', '.join(missing)}")
            return True
        return False
