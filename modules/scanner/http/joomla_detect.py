#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Joomla detection',
        'description': 'Detects if Joomla is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'joomla', 'cms'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if r and ("joomla" in r.text.lower() or "com_content" in r.text.lower() or "/administrator/" in r.text.lower()):
            return True
        r2 = self.http_request(method="GET", path="/administrator/", allow_redirects=True)
        if r2 and "joomla" in r2.text.lower():
            return True
        return False
