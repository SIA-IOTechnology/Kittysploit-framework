#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


ADMIN_PATHS = ["/admin", "/administrator", "/login", "/user/login", "/wp-admin", "/wp-login.php", "/manager", "/admin.php", "/backend", "/panel", "/login.php"]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Admin panel detection',
        'description': 'Detects exposed admin or login panels.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': ['auxiliary/scanner/http/login/admin_login_bruteforce'],
        'tags': ['web', 'scanner', 'admin', 'login', 'panel'],
    }

    def run(self):
        found = []
        for path in ADMIN_PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            t = r.text.lower()
            if "password" in t and ("type=\"password\"" in t or "type='password'" in t or "name=\"password\"" in t):
                found.append(path)
        if found:
            self.set_info(severity="info", reason=f"Login panel(s): {', '.join(found)}")
            return True
        return False
