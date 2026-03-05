#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Methods that are often considered risky when allowed on web root
RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'HTTP methods detection',
        'description': 'Detects allowed HTTP methods (via Allow header or OPTIONS). Risky methods may indicate misconfiguration.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'http', 'methods', 'options', 'allow'],
    }

    def run(self):
        r = self.http_request(method="OPTIONS", path="/", allow_redirects=False)
        if not r:
            return False
        allow = r.headers.get("Allow")
        if not allow:
            return False
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if not methods:
            return False
        risky = [m for m in methods if m in RISKY_METHODS]
        if risky:
            self.set_info(severity="low", reason=f"Allowed: {', '.join(methods)} (risky: {', '.join(risky)})")
        else:
            self.set_info(severity="info", reason=f"Allowed methods: {', '.join(methods)}")
        return True
