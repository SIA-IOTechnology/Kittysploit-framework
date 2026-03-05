#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Drupal detection',
        'description': 'Detects if Drupal is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'drupal', 'cms'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if r and ("drupal" in r.text.lower() or "drupal.settings" in r.text.lower() or "sites/default" in r.text.lower()):
            return True
        r2 = self.http_request(method="GET", path="/user/login", allow_redirects=True)
        if r2 and "drupal" in r2.text.lower():
            return True
        return False
