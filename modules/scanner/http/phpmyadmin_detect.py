#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'phpMyAdmin detection',
        'description': 'Detects if phpMyAdmin is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'phpmyadmin', 'mysql'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/phpmyadmin", allow_redirects=True)
        if r and ("phpmyadmin" in r.text.lower() or "pma" in r.text.lower()):
            return True
        return False