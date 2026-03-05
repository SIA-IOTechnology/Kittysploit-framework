#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'WordPress detection',
        'description': 'Detects if WordPress is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'wordpress', 'cms'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        t = r.text.lower()
        if "wp-includes" in t or "wp-content" in t or "wordpress" in t or "/wp-login" in t:
            return True
        r2 = self.http_request(method="GET", path="/wp-login.php", allow_redirects=True)
        if r2 and ("wordpress" in r2.text.lower() or "wp-login" in r2.text.lower()):
            return True
        return False
